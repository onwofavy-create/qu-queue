const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const db = require('./db/database');
const q = require('./services/queue');
const noShow = require('./services/noShowWorker');
const otp = require('./services/otp');
const notifications = require('./services/notifications');
const {
  PORT,
  HOST,
  JWT_SECRET,
  TOKEN_DAYS,
  NODE_ENV,
  PLATFORM_OWNER_EMAIL,
  PLATFORM_OWNER_PASSWORD,
  TLS_CERT_PATH,
  TLS_KEY_PATH,
  BEHIND_HTTPS_PROXY,
} = require('./config');
const {
  hashPassword,
  hashToken,
  randomToken,
  verifyPassword,
  cleanText,
  normalizePhone,
  sign,
  verify,
} = require('./utils/security');

const ROOT = path.resolve(__dirname, '../..');
const QUICK_SERVICE_TEMPLATES = [
  { name: 'Blood Test', customer_name: 'Blood Test', category: 'Blood & Lab', search_keywords: 'blood,cbc,test', estimated_duration: 20 },
  { name: 'Malaria Test', customer_name: 'Malaria Test', category: 'Blood & Lab', search_keywords: 'malaria,blood test,lab', estimated_duration: 15 },
  { name: 'X-Ray', customer_name: 'X-Ray', category: 'Scans', search_keywords: 'xray,x-ray,scan', estimated_duration: 25 },
  { name: 'Ultrasound', customer_name: 'Ultrasound', category: 'Scans', search_keywords: 'ultrasound,scan,imaging', estimated_duration: 20 },
  { name: 'Consultation', customer_name: 'Consultation', category: 'Consultation', search_keywords: 'consultation,doctor,visit', estimated_duration: 20 },
  { name: 'Registration', customer_name: 'Registration', category: 'Registration', search_keywords: 'register,check in,admin', estimated_duration: 10 },
  { name: 'General Queue', customer_name: 'General Queue', category: 'General', search_keywords: 'general,queue,any', estimated_duration: 15 },
];
const FRONT_CANDIDATES = [
  path.join(ROOT, 'frontend'),
  path.resolve(__dirname, '../../frontend'),
  path.resolve(__dirname, '../../../frontend'),
];
const FRONT =
  FRONT_CANDIDATES.find((p) => fs.existsSync(path.join(p, 'index.html'))) ||
  FRONT_CANDIDATES[0];
const FRONT_RESOLVED = path.resolve(FRONT);

const clients = new Map();
const buckets = new Map();

if (NODE_ENV === 'production' && JWT_SECRET === 'dev-only-change-this-secret') {
  console.error('Refusing to start: set QU_JWT_SECRET before running in production.');
  process.exit(1);
}
if (NODE_ENV === 'production' && (!PLATFORM_OWNER_EMAIL || !PLATFORM_OWNER_PASSWORD)) {
  console.error('Refusing to start: set QU_PLATFORM_OWNER_EMAIL and QU_PLATFORM_OWNER_PASSWORD in production.');
  process.exit(1);
}
if (NODE_ENV === 'production' && ((!TLS_CERT_PATH || !TLS_KEY_PATH) && !BEHIND_HTTPS_PROXY)) {
  console.error('Refusing to start: configure QU_TLS_CERT_PATH/QU_TLS_KEY_PATH or set QU_BEHIND_HTTPS_PROXY=true in production.');
  process.exit(1);
}

const json = (res, status, data, extraHeaders = {}) => {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  res.end(body);
};

function cookieValue(req, name) {
  const cookies = String(req.headers.cookie || '').split(';');
  const match = cookies.map((item) => item.trim().split('=')).find(([key]) => key === name);
  return match ? decodeURIComponent(match.slice(1).join('=')) : '';
}

function sessionCookie(token, rememberMe) {
  const maxAge = rememberMe ? 30 * 86400 : undefined;
  return `qu_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax;${NODE_ENV === 'production' ? ' Secure;' : ''}${maxAge ? ` Max-Age=${maxAge};` : ''}`;
}

const clearSessionCookie = 'qu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0;';

const parseBody = (req) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 100000) {
        req.destroy(Error('Payload too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const s = Buffer.concat(chunks).toString('utf8');
        resolve(s ? JSON.parse(s) : {});
      } catch {
        reject(Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });

function rate(req, res) {
  const minute = new Date().toISOString().slice(0, 16);
  const key = (req.socket.remoteAddress || 'unknown') + ':' + minute;
  const n = (buckets.get(key) || 0) + 1;
  buckets.set(key, n);
  if (n > 240) {
    json(res, 429, { error: 'Too many requests' });
    return false;
  }
  if (buckets.size > 5000) {
    const prefix = minute.slice(0, 15);
    for (const k of buckets.keys()) {
      if (!k.endsWith(prefix) && !k.endsWith(minute)) buckets.delete(k);
    }
  }
  return true;
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

function auth(req) {
  const h = req.headers.authorization || '';
  const bearer = h.startsWith('Bearer ') ? h.slice(7) : '';
  const sessionToken = bearer || cookieValue(req, 'qu_session');
  if (!sessionToken) throw Error('Authentication required');
  const payload = verify(sessionToken, JWT_SECRET);
  if (payload.sessionId) {
    const row = db
      .prepare(
        'SELECT * FROM user_sessions WHERE session_id=? AND is_active=1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP'
      )
      .get(payload.sessionId);
    if (!row || row.user_id !== Number(payload.id)) {
      throw Error('Session expired or revoked');
    }
    db.prepare('UPDATE user_sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?').run(row.id);
  }
  return payload;
}

function platformUser(req, res) {
  try {
    const p = auth(req);
    if (p.role !== 'platform_owner') throw Error('Forbidden');
    const u = db
      .prepare('SELECT * FROM platform_users WHERE id=? AND is_active=1')
      .get(Number(p.id));
    if (!u) throw Error('Account unavailable');
    return u;
  } catch (e) {
    json(res, e.message === 'Forbidden' ? 403 : 401, { error: e.message });
    return null;
  }
}

function user(req, res, roles = []) {
  try {
    const p = auth(req);
    if (roles.length && !roles.includes(p.role)) throw Error('Forbidden');
    if (p.role === 'platform_owner') {
      const u = db.prepare('SELECT * FROM platform_users WHERE id=? AND is_active=1').get(Number(p.id));
      if (!u) throw Error('Account unavailable');
      return { id: u.id, name: u.name, email: u.email, role: 'platform_owner', org_id: null, branch_id: null, station_id: null, is_active: 1, station_name: null };
    }
    const s = db
      .prepare(
        `SELECT st.id,st.name,st.email,st.role,st.org_id,st.branch_id,st.station_id,st.is_active,
               ss.name station_name
         FROM staff st
         LEFT JOIN service_stations ss ON ss.id=st.station_id
         WHERE st.id=?`
      )
      .get(p.id);
    if (!s || !s.is_active) throw Error('Account unavailable');
    return s;
  } catch (e) {
    json(res, e.message === 'Forbidden' ? 403 : 401, { error: e.message });
    return null;
  }
}

function recordAuditEvent({ orgId = null, userId = null, action, ticketNumber = null, customerName = null, serviceName = null, staffName = null, stationName = null, reason = null, metadata = null, userEmail = null }) {
  if (!action) return;
  db.prepare(
    'INSERT INTO audit_events(org_id,user_id,action,ticket_number,customer_name,service_name,staff_name,station_name,reason,metadata) VALUES(?,?,?,?,?,?,?,?,?,?)'
  ).run(
    orgId,
    userId,
    action,
    ticketNumber,
    customerName,
    serviceName,
    staffName || userEmail || null,
    stationName,
    reason,
    metadata ? JSON.stringify(metadata) : null
  );
}

function createUserSession({ userId, orgId, branchId, role, email, rememberMe = false, deviceId = null, metadata = null }) {
  const sessionId = randomToken();
  const token = sign({ id: userId, orgId, branchId, role, email, sessionId }, JWT_SECRET, rememberMe ? 30 : TOKEN_DAYS);
  const hash = hashToken(token);
  const expiresAt = new Date(Date.now() + (rememberMe ? 30 : TOKEN_DAYS) * 86400000).toISOString();
  db.prepare(
    'INSERT INTO user_sessions(user_id,org_id,branch_id,role,email,session_id,token_hash,device_id,remember_me,is_active,expires_at,last_seen_at,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'
  ).run(
    userId,
    orgId,
    branchId,
    role,
    email,
    sessionId,
    hash,
    deviceId,
    rememberMe ? 1 : 0,
    1,
    expiresAt,
    new Date().toISOString(),
    metadata ? JSON.stringify(metadata) : null
  );
  return { token, sessionId, expiresAt };
}

function revokeSession(tokenOrSessionId, userId = null) {
  const token = String(tokenOrSessionId || '').trim();
  if (token) {
    const payload = verify(token, JWT_SECRET).catch ? null : null;
  }
  if (token) {
    try {
      const payload = verify(token, JWT_SECRET);
      if (payload.sessionId) {
        db.prepare('UPDATE user_sessions SET revoked_at=CURRENT_TIMESTAMP, is_active=0 WHERE session_id=? AND (user_id=? OR ? IS NULL)').run(payload.sessionId, userId ?? payload.id, userId ?? null);
        return true;
      }
    } catch {}
  }
  if (userId) {
    db.prepare('UPDATE user_sessions SET revoked_at=CURRENT_TIMESTAMP, is_active=0 WHERE user_id=?').run(userId);
  }
  return false;
}

function branchFor(s, id) {
  return db
    .prepare('SELECT * FROM branches WHERE id=? AND org_id=? AND is_active=1')
    .get(Number(id), s.org_id);
}

function generateAccessToken(code) {
  const value = String(code || '').replace(/[^A-Z0-9]/gi, '').toUpperCase();
  const seed = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${value.slice(0, 3) || 'QU'}-${seed}`.slice(0, 12);
}

function generateCompanyPublicCode() {
  const slice = crypto.randomBytes(6).toString('base64url').replace(/[-_]/g, '').slice(0, 8).toUpperCase();
  return `Q-${slice || 'QUEUEOS'}`;
}

function generateCompanyToken() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const pick = (n) => Array.from({ length: n }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('');
  return `${pick(4)}-${pick(4)}`;
}

function generateCompanyQrId() {
  return `q_${crypto.randomBytes(8).toString('base64url').replace(/[-_]/g, '').slice(0, 12)}`;
}

function qrCodeUrlForBranch(code, token = '') {
  const target = token
    ? `https://queueos.app/join?branch=${encodeURIComponent(code)}&token=${encodeURIComponent(token)}`
    : `https://queueos.app/join?branch=${encodeURIComponent(code)}`;
  return `https://api.qrserver.com/v1/create-qr-code/?size=260x260&data=${encodeURIComponent(target)}`;
}

function qrCodeUrlForCompany(companyCode, token = '') {
  const target = token
    ? `https://queueos.app/join?company=${encodeURIComponent(companyCode)}&token=${encodeURIComponent(token)}`
    : `https://queueos.app/join?company=${encodeURIComponent(companyCode)}`;
  return `https://api.qrserver.com/v1/create-qr-code/?size=260x260&data=${encodeURIComponent(target)}`;
}

function branchAccessData(branch) {
  const mode = String(branch.access_mode || 'code');
  return {
    mode,
    access_mode: mode,
    has_token: !!branch.access_token,
    has_qr: !!branch.qr_code_url,
    access_token: branch.access_token || null,
    qr_code_url: branch.qr_code_url || null,
    join_url: `https://queueos.app/join?branch=${encodeURIComponent(branch.code)}`,
    token_url: branch.access_token ? `https://queueos.app/join?token=${encodeURIComponent(branch.access_token)}` : null,
  };
}

function organizationAccessData(org) {
  const mode = String(org.company_access_mode || 'token');
  return {
    mode,
    access_mode: mode,
    has_token: !!org.company_access_token,
    has_qr: !!org.company_qr_code_url,
    access_token: org.company_access_token || null,
    qr_code_url: org.company_qr_code_url || null,
    public_code: org.company_public_code || null,
    qr_id: org.company_qr_id || null,
    join_url: org.company_public_code ? `https://queueos.app/join?company=${encodeURIComponent(org.company_public_code)}` : null,
    token_url: org.company_access_token ? `https://queueos.app/join?token=${encodeURIComponent(org.company_access_token)}` : null,
  };
}

function getDefaultBranchForOrg(orgId) {
  const org = db.prepare('SELECT id,name FROM organizations WHERE id=?').get(orgId);
  if (!org) return null;
  const existing = db.prepare('SELECT * FROM branches WHERE org_id=? AND is_active=1 ORDER BY id LIMIT 1').get(orgId);
  if (existing) return existing;
  const createdId = ensureDefaultBranch(orgId, org.name);
  return db.prepare('SELECT * FROM branches WHERE id=?').get(createdId);
}

function getDefaultOrgBranch(orgId) {
  const branch = db.prepare('SELECT * FROM branches WHERE org_id=? AND is_active=1 ORDER BY id LIMIT 1').get(orgId);
  return branch || null;
}

function resolveCompanyByAccess(input) {
  const value = String(input || '').trim();
  if (!value) return null;
  const lookup = value.toUpperCase();
  return (
    db.prepare('SELECT * FROM organizations WHERE company_public_code=? OR company_qr_id=? OR upper(company_access_token)=?').get(lookup, lookup, lookup) ||
    db.prepare('SELECT o.* FROM branches b JOIN organizations o ON o.id=b.org_id WHERE b.code=? AND b.is_active=1').get(lookup.toUpperCase()) ||
    db.prepare('SELECT o.* FROM branches b JOIN organizations o ON o.id=b.org_id WHERE upper(b.access_token)=? AND b.is_active=1').get(lookup)
  );
}

function normalizeSearchText(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

function levenshteinDistance(a, b) {
  const s = a.toLowerCase();
  const t = b.toLowerCase();
  if (s === t) return 0;
  const m = s.length;
  const n = t.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

function serviceSearchMatches(orgId, rawSearch) {
  const branch = getDefaultBranchForOrg(orgId);
  if (!branch) return [];
  const q = normalizeSearchText(rawSearch);
  const rows = db.prepare('SELECT * FROM services WHERE branch_id=? AND is_active=1 ORDER BY name').all(branch.id);
  if (!q) return rows;
  return rows
    .map((service) => {
      const combined = [service.name, service.customer_name || '', service.category || '', service.search_keywords || ''].join(' ');
      const values = normalizeSearchText(combined).split(' ');
      const queryWords = q.split(' ');
      const exact = combined.toLowerCase().includes(q) ? 1 : 0;
      const keywordHits = queryWords.filter((word) => word && values.some((v) => v.includes(word))).length;
      const distance = Math.min(
        levenshteinDistance(q, normalizeSearchText(service.name)),
        levenshteinDistance(q, normalizeSearchText(service.customer_name || service.name)),
        levenshteinDistance(q, normalizeSearchText(service.category || ''))
      );
      const score = exact * 100 + keywordHits * 20 - distance;
      return { service, score };
    })
    .filter(({ score }) => score > -20)
    .sort((a, b) => b.score - a.score)
    .map(({ service }) => service);
}

function ensureDefaultBranch(orgId, orgName = 'Main Queue') {
  const existing = db
    .prepare('SELECT id FROM branches WHERE org_id=? AND is_active=1 ORDER BY id LIMIT 1')
    .get(orgId);
  if (existing) return existing.id;
  const base = String(orgName || 'Main Queue').trim() || 'Main Queue';
  let code;
  for (let i = 0; i < 50; i++) {
    code = `Q-${crypto.randomInt(1000, 9999)}`;
    if (!db.prepare('SELECT id FROM branches WHERE code=?').get(code)) break;
  }
  const branchId = db
    .prepare(
      'INSERT INTO branches(org_id,name,code,address,phone,opening_hours,access_mode) VALUES(?,?,?,?,?,?,?)'
    )
    .run(orgId, base, code, 'Main location', null, 'Mon-Sun 08:00-18:00', 'token')
    .lastInsertRowid;
  db.prepare('INSERT INTO queue_settings(branch_id, require_otp) VALUES(?,0)').run(branchId);
  const serviceId = db
    .prepare('INSERT INTO services(branch_id,name,customer_name,category,search_keywords,estimated_duration) VALUES(?,?,?,?,?,?)')
    .run(branchId, 'General Queue', 'General Queue', 'General', 'general,queue,any', 15)
    .lastInsertRowid;
  const stationId = db
    .prepare('INSERT INTO service_stations(branch_id,name,service_id) VALUES(?,?,?)')
    .run(branchId, 'Reception Desk', serviceId)
    .lastInsertRowid;
  db.prepare('UPDATE staff SET branch_id=?, station_id=? WHERE org_id=? AND role=? AND branch_id IS NULL')
    .run(branchId, stationId, orgId, 'owner');
  return branchId;
}

function writeSse(branchId, payload) {
  const line = `data: ${JSON.stringify(payload)}\n\n`;
  for (const [res, b] of clients) {
    if (b !== Number(branchId)) continue;
    try {
      res.write(line);
    } catch {
      clients.delete(res);
    }
  }
}

q.events.on('changed', (b) => {
  writeSse(b, { type: 'QUEUE_UPDATED', at: Date.now() });
  try {
    notifications.evaluateBranch(b);
  } catch {}
});

function login(body, res) {
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const rememberMe = !!body.remember_me;
  if (!isValidEmail(email) || !password) {
    return json(res, 401, { error: 'Invalid email or password' });
  }

  const platform = db
    .prepare('SELECT * FROM platform_users WHERE lower(email)=? AND is_active=1')
    .get(email);
  if (platform && verifyPassword(password, platform.password_hash)) {
    const session = createUserSession({ userId: platform.id, orgId: null, branchId: null, role: 'platform_owner', email: platform.email, rememberMe, deviceId: String(body.device_id || 'device') });
    db.prepare('UPDATE platform_users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?').run(platform.id);
    recordAuditEvent({ userId: platform.id, action: 'LOGIN', staffName: platform.name, userEmail: platform.email });
    return json(res, 200, { token: session.token, sessionId: session.sessionId, rememberMe, user: { id: platform.id, name: platform.name, email: platform.email, role: 'platform_owner', orgId: null, branchId: null, stationId: null, stationName: null } }, { 'set-cookie': sessionCookie(session.token, rememberMe) });
  }

  const s = db.prepare('SELECT * FROM staff WHERE lower(email)=? AND is_active=1').get(email);
  if (!s || !verifyPassword(password, s.password_hash)) {
    return json(res, 401, { error: 'Invalid email or password' });
  }
  const session = createUserSession({ userId: s.id, orgId: s.org_id, branchId: s.branch_id, role: s.role, email: s.email, rememberMe, deviceId: String(body.device_id || 'device') });
  const station = s.station_id ? db.prepare('SELECT id,name FROM service_stations WHERE id=?').get(s.station_id) : null;
  recordAuditEvent({ orgId: s.org_id, userId: s.id, action: 'LOGIN', staffName: s.name, userEmail: s.email, metadata: { role: s.role } });
  json(res, 200, {
    token: session.token,
    sessionId: session.sessionId,
    rememberMe,
    user: {
      id: s.id,
      name: s.name,
      email: s.email,
      role: s.role,
      orgId: s.org_id,
      branchId: s.branch_id,
      stationId: s.station_id || null,
      stationName: station?.name || null,
    },
  }, { 'set-cookie': sessionCookie(session.token, rememberMe) });
}

function seed() {
  if (NODE_ENV === 'production') {
    db.prepare("DELETE FROM platform_users WHERE lower(email)='platform@queueos.app'").run();
  }
  if (
    db.prepare('SELECT COUNT(*) n FROM platform_users').get().n === 0 &&
    PLATFORM_OWNER_EMAIL &&
    PLATFORM_OWNER_PASSWORD
  ) {
    db.prepare('INSERT INTO platform_users(name,email,password_hash,is_active) VALUES(?,?,?,1)').run(
      'QueueOS Platform Owner',
      PLATFORM_OWNER_EMAIL.trim().toLowerCase(),
      hashPassword(PLATFORM_OWNER_PASSWORD)
    );
  }
  if (NODE_ENV === 'production') return;
  if (db.prepare('SELECT COUNT(*) n FROM organizations').get().n) return;
  const org = db
    .prepare(
      'INSERT INTO organizations(name,email,password_hash,category,company_public_code,company_qr_id,company_access_mode,company_access_token,company_qr_code_url) VALUES(?,?,?,?,?,?,?,?,?)'
    )
    .run(
      'QueueOS Demo',
      'owner@qu.local',
      hashPassword('password'),
      'Healthcare',
      'Q-QUEUEOS',
      'q_queueos_demo',
      'both',
      'ELB7-K92P',
      qrCodeUrlForCompany('Q-QUEUEOS', 'ELB7-K92P')
    ).lastInsertRowid;
  const branch = db
    .prepare(
      'INSERT INTO branches(org_id,name,code,address,phone,opening_hours,access_mode,access_token,qr_code_url) VALUES(?,?,?,?,?,?,?,?,?)'
    )
    .run(
      org,
      'Main Queue',
      'QU-4827',
      'Lagos, Nigeria',
      '08000000000',
      'Mon–Fri 08:00–18:00',
      'both',
      'ELB7-K92P',
      qrCodeUrlForBranch('QU-4827', 'ELB7-K92P')
    ).lastInsertRowid;
  db.prepare('INSERT INTO queue_settings(branch_id, require_otp) VALUES(?,0)').run(branch);
  const a = db
    .prepare(
      'INSERT INTO services(branch_id,name,customer_name,category,search_keywords,estimated_duration) VALUES(?,?,?,?,?,?)'
    )
    .run(branch, 'General Service', 'General Service', 'General', 'general,queue,service', 15).lastInsertRowid;
  db.prepare(
    'INSERT INTO services(branch_id,name,customer_name,category,search_keywords,estimated_duration) VALUES(?,?,?,?,?,?)'
  ).run(branch, 'Priority Service', 'Priority Service', 'General', 'priority,fast,urgent', 10);
  const stationIds = [];
  for (let i = 1; i <= 3; i++) {
    stationIds.push(
      db
        .prepare(
          'INSERT INTO service_stations(branch_id,name,service_id) VALUES(?,?,?)'
        )
        .run(branch, `Station ${i}`, i === 1 ? a : null).lastInsertRowid
    );
  }
  db.prepare(
    'INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)'
  ).run(
    org,
    branch,
    stationIds[0],
    'Owner',
    'owner@qu.local',
    hashPassword('password'),
    'owner'
  );
  db.prepare(
    'INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)'
  ).run(
    org,
    branch,
    stationIds[0],
    'Receptionist',
    'reception@qu.local',
    hashPassword('password'),
    'receptionist'
  );
  db.prepare(
    'INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)'
  ).run(
    org,
    branch,
    stationIds[1],
    'Counter Two',
    'station2@qu.local',
    hashPassword('password'),
    'receptionist'
  );
}

async function api(req, res, pathname) {
  if (pathname === '/api/health') {
    return json(res, 200, {
      status: 'ok',
      service: 'QueueOS',
      version: '3.1.0',
      time: new Date().toISOString(),
      node: process.version,
    });
  }

  if (pathname === '/api/auth/login' && req.method === 'POST') {
    return login(await parseBody(req), res);
  }

  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    const header = req.headers.authorization || '';
    const sessionToken = header.startsWith('Bearer ') ? header.slice(7) : cookieValue(req, 'qu_session');
    if (!sessionToken) return json(res, 401, { error: 'Authentication required' });
    try {
      const payload = verify(sessionToken, JWT_SECRET);
      revokeSession(sessionToken, Number(payload.id));
      recordAuditEvent({
        orgId: payload.orgId || null,
        userId: Number(payload.id),
        action: 'LOGOUT',
        userEmail: payload.email,
      });
      return json(res, 200, { status: 'signed_out' }, { 'set-cookie': clearSessionCookie });
    } catch {
      return json(res, 401, { error: 'Session expired or revoked' });
    }
  }

  if (pathname === '/api/auth/signup' && req.method === 'POST') {
    const body = await parseBody(req);
    const companyName = cleanText(body.company_name || body.name, 120);
    const ownerName = cleanText(body.owner_name || body.name || 'Owner', 80);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const category = cleanText(body.category, 80) || 'General';
    if (!companyName || !email || !password) {
      return json(res, 400, { error: 'Company name, email and password are required' });
    }
    if (!isValidEmail(email)) {
      return json(res, 400, { error: 'Enter a valid email address' });
    }
    if (password.length < 8) {
      return json(res, 400, { error: 'Password must be at least 8 characters' });
    }
    const exists = db.prepare('SELECT id FROM organizations WHERE lower(email)=?').get(email);
    if (exists) return json(res, 409, { error: 'Unable to create account' });
    const companyPublicCode = generateCompanyPublicCode();
    const companyQrId = generateCompanyQrId();
    const defaultAccessToken = generateCompanyToken();
    const orgId = db.prepare(
      'INSERT INTO organizations(name,email,password_hash,category,company_public_code,company_qr_id,company_access_mode,company_access_token,company_qr_code_url) VALUES(?,?,?,?,?,?,?,?,?)'
    ).run(
      companyName,
      email,
      hashPassword(password),
      category,
      companyPublicCode,
      companyQrId,
      'both',
      defaultAccessToken,
      qrCodeUrlForCompany(companyPublicCode, defaultAccessToken)
    ).lastInsertRowid;
    const defaultBranchId = ensureDefaultBranch(orgId, companyName);
    const staffId = db.prepare(
      'INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)'
    ).run(orgId, defaultBranchId, null, ownerName, email, hashPassword(password), 'owner').lastInsertRowid;
    const staff = db.prepare(
      `SELECT st.id,st.name,st.email,st.role,st.org_id,st.branch_id,st.station_id,st.is_active,
              ss.name station_name
        FROM staff st
        LEFT JOIN service_stations ss ON ss.id=st.station_id
        WHERE st.id=?`
    ).get(staffId);
    const session = createUserSession({ userId: staff.id, orgId: staff.org_id, branchId: staff.branch_id, role: staff.role, email: staff.email, rememberMe: !!body.remember_me, deviceId: String(body.device_id || 'device') });
    recordAuditEvent({ orgId, userId: staff.id, action: 'COMPANY_CREATED', staffName: staff.name, userEmail: staff.email, metadata: { company: companyName } });
    return json(res, 201, {
      token: session.token,
      sessionId: session.sessionId,
      rememberMe: !!body.remember_me,
      user: {
        id: staff.id,
        name: staff.name,
        email: staff.email,
        role: staff.role,
        orgId: staff.org_id,
        branchId: staff.branch_id,
        stationId: staff.station_id || null,
        stationName: staff.station_name || null,
      },
      company: {
        id: orgId,
        name: companyName,
        category,
        publicCode: companyPublicCode,
        accessToken: defaultAccessToken,
      },
    });
  }

  if (pathname === '/api/auth/staff-signup' && req.method === 'POST') {
    return json(res, 403, { error: 'Staff self-signup is disabled. Ask the company owner to create your invitation.' });
  }

  if (pathname === '/api/auth/invite/accept' && req.method === 'POST') {
    const body = await parseBody(req);
    const token = String(body.token || '').trim();
    const name = cleanText(body.name, 80);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!token || !name || !email || !password) {
      return json(res, 400, { error: 'Invitation token, name, email and password are required' });
    }
    if (password.length < 8) {
      return json(res, 400, { error: 'Password must be at least 8 characters' });
    }
    const invite = db.prepare('SELECT * FROM staff_invitations WHERE status=? ORDER BY id').all('pending').find((row) => {
      const hash = row.token_hash;
      const actual = hashToken(token);
      try {
        const a = Buffer.from(actual, 'utf8');
        const b = Buffer.from(hash, 'utf8');
        return a.length === b.length && crypto.timingSafeEqual(a, b);
      } catch {
        return false;
      }
    });
    if (!invite) return json(res, 404, { error: 'Invitation not found or expired' });
    if (new Date(invite.expires_at).getTime() < Date.now()) {
      db.prepare('UPDATE staff_invitations SET status=? WHERE id=?').run('expired', invite.id);
      return json(res, 410, { error: 'Invitation has expired' });
    }
    if (invite.email.toLowerCase() !== email.toLowerCase()) {
      return json(res, 400, { error: 'Email does not match the invitation' });
    }
    const existing = db.prepare('SELECT id FROM staff WHERE lower(email)=?').get(email);
    if (existing) return json(res, 409, { error: 'An account with this email already exists' });
    const branch = getDefaultBranchForOrg(invite.org_id);
    const org = db.prepare('SELECT * FROM organizations WHERE id=?').get(invite.org_id);
    const staffId = db.prepare(
      'INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)'
    ).run(invite.org_id, branch ? branch.id : null, null, name, email, hashPassword(password), invite.role).lastInsertRowid;
    db.prepare('UPDATE staff_invitations SET status=?, used_at=CURRENT_TIMESTAMP WHERE id=?').run('accepted', invite.id);
    recordAuditEvent({
      orgId: invite.org_id,
      userId: Number(staffId),
      action: 'STAFF_INVITATION_ACCEPTED',
      staffName: name,
      userEmail: email,
    });
    const member = db.prepare(
      `SELECT st.id,st.name,st.email,st.role,st.org_id,st.branch_id,st.station_id,st.is_active,
              ss.name station_name
        FROM staff st LEFT JOIN service_stations ss ON ss.id=st.station_id WHERE st.id=?`
    ).get(staffId);
    const acceptedSession = createUserSession({
      userId: member.id,
      orgId: member.org_id,
      branchId: member.branch_id,
      role: member.role,
      email: member.email,
      rememberMe: !!body.remember_me,
      deviceId: String(body.device_id || 'device'),
    });
    return json(res, 201, {
      token: acceptedSession.token,
      sessionId: acceptedSession.sessionId,
      rememberMe: !!body.remember_me,
      user: {
        id: member.id,
        name: member.name,
        email: member.email,
        role: member.role,
        orgId: member.org_id,
        branchId: member.branch_id,
        stationId: member.station_id || null,
        stationName: member.station_name || null,
      },
      company: org ? { id: org.id, name: org.name } : null,
    });
  }

  if (pathname === '/api/auth/me' && req.method === 'GET') {
    const s = user(req, res);
    if (s) json(res, 200, s);
    return;
  }

  if (pathname === '/api/company/access' && req.method === 'GET') {
    const s = user(req, res, ['owner', 'admin']);
    if (!s) return;
    const org = db.prepare('SELECT * FROM organizations WHERE id=?').get(s.org_id);
    if (!org) return json(res, 404, { error: 'Company not found' });
    return json(res, 200, organizationAccessData(org));
  }

  if (pathname === '/api/company/access' && req.method === 'POST') {
    const s = user(req, res, ['owner', 'admin']);
    if (!s) return;
    const body = await parseBody(req);
    const action = body.action === 'destroy' ? 'destroy' : 'create';
    const org = db.prepare('SELECT * FROM organizations WHERE id=?').get(s.org_id);
    if (!org) return json(res, 404, { error: 'Company not found' });
    if (action === 'destroy') {
      db.prepare('UPDATE organizations SET company_access_mode=?, company_access_token=?, company_qr_code_url=?, company_qr_id=?, company_public_code=? WHERE id=?').run('code', null, null, null, null, s.org_id);
      return json(res, 200, organizationAccessData(db.prepare('SELECT * FROM organizations WHERE id=?').get(s.org_id)));
    }
    const mode = ['code', 'token', 'qr', 'both'].includes(String(body.mode || 'token')) ? String(body.mode || 'token') : 'token';
    if (org.company_access_token || org.company_qr_code_url) {
      return json(res, 409, { error: 'You already have an active QR code or access token for this company. Revoke the existing one before creating a new one.' });
    }
    const nextMode = mode === 'code' ? 'code' : mode;
    const accessToken = ['token', 'both'].includes(nextMode) ? generateCompanyToken() : null;
    const companyPublicCode = org.company_public_code || generateCompanyPublicCode();
    const qrId = org.company_qr_id || generateCompanyQrId();
    const qrCode = ['qr', 'both'].includes(nextMode) ? qrCodeUrlForCompany(companyPublicCode, accessToken) : null;
    db.prepare(
      'UPDATE organizations SET company_access_mode=?, company_access_token=?, company_qr_code_url=?, company_public_code=?, company_qr_id=? WHERE id=?'
    ).run(nextMode, accessToken, qrCode, companyPublicCode, qrId, s.org_id);
    return json(res, 200, organizationAccessData(db.prepare('SELECT * FROM organizations WHERE id=?').get(s.org_id)));
  }

  if (pathname === '/api/owner/staff/invite' && req.method === 'POST') {
    const s = user(req, res, ['owner', 'admin']);
    if (!s) return;
    const body = await parseBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const name = cleanText(body.name, 80);
    const role = ['owner', 'admin', 'receptionist'].includes(body.role) ? body.role : 'receptionist';
    if (!name || !email) return json(res, 400, { error: 'Name and email are required' });
    const token = randomToken();
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 2).toISOString();
    const tokenHash = hashToken(token);
    db.prepare('INSERT INTO staff_invitations(org_id,invited_by,email,role,token_hash,expires_at,status,metadata) VALUES(?,?,?,?,?,?,?,?)').run(s.org_id, s.id, email, role, tokenHash, expires, 'pending', JSON.stringify({ name }));
    recordAuditEvent({ orgId: s.org_id, userId: s.id, action: 'STAFF_INVITATION_CREATED', staffName: name, userEmail: email, metadata: { role } });
    return json(res, 201, { invitation: { email, role, expires_at: expires, token }, status: 'pending' });
  }

  if (pathname === '/api/owner/staff/invitations' && req.method === 'GET') {
    const s = user(req, res, ['owner', 'admin']);
    if (!s) return;
    const rows = db.prepare('SELECT id,email,role,status,expires_at,used_at,created_at FROM staff_invitations WHERE org_id=? ORDER BY created_at DESC').all(s.org_id);
    return json(res, 200, { invitations: rows });
  }

  const invitationCancelMatch = pathname.match(/^\/api\/owner\/staff\/invitation\/(\d+)\/cancel$/);
  if (invitationCancelMatch && req.method === 'POST') {
    const s = user(req, res, ['owner', 'admin']);
    if (!s) return;
    const id = Number(invitationCancelMatch[1]);
    const invite = db.prepare('SELECT * FROM staff_invitations WHERE id=? AND org_id=?').get(id, s.org_id);
    if (!invite) return json(res, 404, { error: 'Invitation not found' });
    if (invite.status === 'accepted') return json(res, 409, { error: 'Accepted invitations cannot be cancelled' });
    db.prepare('UPDATE staff_invitations SET status=? WHERE id=?').run('cancelled', id);
    recordAuditEvent({ orgId: s.org_id, userId: s.id, action: 'STAFF_INVITATION_CANCELLED', userEmail: invite.email, metadata: { role: invite.role } });
    return json(res, 200, { status: 'cancelled', invitation: { id: invite.id, email: invite.email, role: invite.role } });
  }

  const invitationResendMatch = pathname.match(/^\/api\/owner\/staff\/invitation\/(\d+)\/resend$/);
  if (invitationResendMatch && req.method === 'POST') {
    const s = user(req, res, ['owner', 'admin']);
    if (!s) return;
    const id = Number(invitationResendMatch[1]);
    const invite = db.prepare('SELECT * FROM staff_invitations WHERE id=? AND org_id=?').get(id, s.org_id);
    if (!invite) return json(res, 404, { error: 'Invitation not found' });
    if (invite.status === 'accepted') return json(res, 409, { error: 'Accepted invitations cannot be resent' });
    const token = randomToken();
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 48).toISOString();
    db.prepare('UPDATE staff_invitations SET token_hash=?, expires_at=?, status=?, used_at=NULL WHERE id=?').run(hashToken(token), expires, 'pending', id);
    return json(res, 200, { invitation: { id: invite.id, email: invite.email, role: invite.role, expires_at: expires, token }, status: 'pending' });
  }

  if (pathname === '/api/events' && req.method === 'GET') {
    const params = new URL(req.url, 'http://x').searchParams;
    const code = params.get('company') || params.get('branch') || '';
    let branchId = null;
    if (code) {
      const company = resolveCompanyByAccess(code) || db.prepare('SELECT * FROM organizations WHERE id=?').get(Number(code));
      if (company) {
        const branch = getDefaultBranchForOrg(company.id);
        if (branch) branchId = branch.id;
      }
      if (!branchId) {
        const b = db.prepare('SELECT id FROM branches WHERE code=? AND is_active=1').get(String(code || '').toUpperCase());
        if (b) branchId = b.id;
      }
    }
    if (!branchId) return json(res, 404, { error: 'Company queue not found' });
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.write(': connected\n\n');
    clients.set(res, branchId);
    req.on('close', () => clients.delete(res));
    return;
  }

  if (pathname.startsWith('/api/customer/')) {
    const resolveCompanyDetails = (inputCode, inputToken = null) => {
      const access = inputToken || inputCode;
      const company = resolveCompanyByAccess(access || inputCode);
      if (!company) return null;
      const branch = getDefaultBranchForOrg(company.id);
      if (!branch) return null;
      const set = q.settings(branch.id);
      const allServices = db.prepare('SELECT id,name,customer_name,category,search_keywords,estimated_duration FROM services WHERE branch_id=? AND is_active=1 ORDER BY name').all(branch.id);
      return {
        company,
        branch,
        access: organizationAccessData(company),
        settings: {
          require_otp: !!set.require_otp,
          return_soon_threshold: set.return_soon_threshold,
          return_now_threshold: set.return_now_threshold,
        },
        services: allServices,
      };
    };

    if (pathname.startsWith('/api/customer/company/') && req.method === 'GET') {
      const code = decodeURIComponent(pathname.split('/').pop()).trim();
      const company = resolveCompanyByAccess(code);
      if (!company) return json(res, 404, { error: 'Company not found' });
      const branch = getDefaultBranchForOrg(company.id);
      const set = branch ? q.settings(branch.id) : null;
      const services = branch ? db.prepare('SELECT id,name,customer_name,category,search_keywords,estimated_duration FROM services WHERE branch_id=? AND is_active=1 ORDER BY name').all(branch.id) : [];
      return json(res, 200, {
        company: {
          id: company.id,
          name: company.name,
          category: company.category,
          public_code: company.company_public_code,
          access_token: company.company_access_token,
        },
        access: organizationAccessData(company),
        settings: set ? {
          require_otp: !!set.require_otp,
          return_soon_threshold: set.return_soon_threshold,
          return_now_threshold: set.return_now_threshold,
        } : {},
        services,
      });
    }

    if (pathname.startsWith('/api/customer/access/') && req.method === 'GET') {
      const token = decodeURIComponent(pathname.split('/').pop()).trim();
      const company = resolveCompanyByAccess(token);
      if (!company) return json(res, 404, { error: 'Company access token not found' });
      const branch = getDefaultBranchForOrg(company.id);
      const set = q.settings(branch.id);
      return json(res, 200, {
        company: {
          id: company.id,
          name: company.name,
          category: company.category,
          public_code: company.company_public_code,
          access_token: company.company_access_token,
        },
        access: organizationAccessData(company),
        settings: {
          require_otp: !!set.require_otp,
          return_soon_threshold: set.return_soon_threshold,
          return_now_threshold: set.return_now_threshold,
        },
        services: db.prepare('SELECT id,name,customer_name,category,search_keywords,estimated_duration FROM services WHERE branch_id=? AND is_active=1 ORDER BY name').all(branch.id),
      });
    }

    if (pathname === '/api/customer/search' && req.method === 'POST') {
      const body = await parseBody(req);
      const company = resolveCompanyByAccess(body.company_code || body.company_token || body.company || body.token || '');
      if (!company) return json(res, 404, { error: 'Company not found' });
      const matches = serviceSearchMatches(company.id, body.search || '');
      return json(res, 200, { matches, suggestion: matches[0] ? { name: matches[0].customer_name || matches[0].name } : null });
    }

    if (pathname === '/api/customer/otp' && req.method === 'POST') {
      const body = await parseBody(req);
      const identifier = String(body.company_code || body.branch_code || '').trim();
      const company = resolveCompanyByAccess(identifier);
      const branch = company ? getDefaultBranchForOrg(company.id) : null;
      if (!branch) return json(res, 404, { error: 'Company not found' });
      const phone = normalizePhone(body.phone);
      if (phone.length < 7) return json(res, 400, { error: 'Valid phone number required' });
      try {
        return json(res, 200, otp.requestOtp(phone, branch.id));
      } catch (e) {
        return json(res, 429, { error: e.message });
      }
    }

    if (pathname === '/api/customer/join' && req.method === 'POST') {
      const body = await parseBody(req);
      const company = resolveCompanyByAccess(body.company_code || body.branch_code || body.company_token || body.token || body.access_token || '');
      if (!company) return json(res, 404, { error: 'Company not found' });
      const branch = getDefaultBranchForOrg(company.id);
      if (!branch) return json(res, 404, { error: 'Company queue not configured' });
      const phone = normalizePhone(body.phone);
      if (phone && phone.length < 7) {
        return json(res, 400, { error: 'Valid phone number required' });
      }
      if (!body.service_id) {
        return json(res, 400, { error: 'Service is required' });
      }
      const set = q.settings(branch.id);
      if (set.require_otp) {
        try {
          otp.verifyOtp(phone, branch.id, body.otp);
        } catch (e) {
          return json(res, 400, { error: e.message });
        }
      }
      try {
        return json(res, 201, q.create({ branchId: branch.id, serviceId: Number(body.service_id), phone, name: cleanText(body.name), by: null }));
      } catch (e) {
        return json(res, 400, { error: e.message });
      }
    }

    const m = pathname.match(/^\/api\/customer\/ticket\/(\d+)(?:\/(cancel))?$/);
    if (m) {
      const id = Number(m[1]);
      const token = String(req.headers['x-ticket-token'] || '');
      const e = q.authorize(id, token);
      if (!e) return json(res, 404, { error: 'Ticket not found' });
      if (req.method === 'GET') return json(res, 200, q.customerView(id));
      if (req.method === 'POST' && m[2] === 'cancel') {
        const set = db.prepare('SELECT allow_customer_cancel FROM queue_settings WHERE branch_id=?').get(e.branch_id);
        if (!set?.allow_customer_cancel) {
          return json(res, 403, { error: 'Customer cancellation is disabled' });
        }
        try {
          return json(res, 200, q.transition(id, 'CANCELLED', { reason: 'Customer cancelled' }));
        } catch (err) {
          return json(res, 409, { error: err.message });
        }
      }
    }
  }

  if (pathname === '/api/internal/usage' && req.method === 'GET') {
    const platform = platformUser(req, res);
    if (!platform) return;
    const params = new URL(req.url, 'http://x').searchParams;
    const search = `%${String(params.get('search') || '').trim().toLowerCase()}%`;
    const companies = db.prepare(
      `SELECT o.id,o.name,o.email owner_email,o.created_at,o.is_active,o.last_activity_at,
              (SELECT COUNT(*) FROM staff s WHERE s.org_id=o.id AND s.is_active=1) staff_count,
              (SELECT COUNT(*) FROM queue_entries q JOIN branches b ON b.id=q.branch_id WHERE b.org_id=o.id) ticket_count,
              (SELECT COUNT(*) FROM queue_events qe JOIN queue_entries q ON q.id=qe.entry_id JOIN branches b ON b.id=q.branch_id WHERE b.org_id=o.id) queue_activity
       FROM organizations o
       WHERE lower(o.name) LIKE ? OR lower(o.email) LIKE ?
       ORDER BY o.created_at DESC`
    ).all(search, search);
    const users = db.prepare(
      `SELECT s.name,s.email,s.role,o.name company_name,s.created_at,s.is_active,
              (SELECT MAX(us.last_seen_at) FROM user_sessions us WHERE us.user_id=s.id AND us.org_id=s.org_id) last_activity
       FROM staff s JOIN organizations o ON o.id=s.org_id
       WHERE lower(s.name) LIKE ? OR lower(s.email) LIKE ? OR lower(o.name) LIKE ?
       ORDER BY s.created_at DESC`
    ).all(search, search, search);
    const totals = db.prepare(
      `SELECT
         (SELECT COUNT(*) FROM organizations) total_companies,
         (SELECT COUNT(*) FROM organizations WHERE is_active=1) active_companies,
         (SELECT COUNT(*) FROM staff WHERE role='owner' AND is_active=1) total_owners,
         (SELECT COUNT(*) FROM staff WHERE role<>'owner' AND is_active=1) total_staff,
         (SELECT COUNT(*) FROM queue_entries) total_tickets,
         (SELECT COUNT(DISTINCT o.id) FROM organizations o JOIN audit_events a ON a.org_id=o.id WHERE date(a.created_at)=date('now')) companies_active_today,
         (SELECT COUNT(DISTINCT o.id) FROM organizations o JOIN audit_events a ON a.org_id=o.id WHERE a.created_at>=datetime('now','-7 days')) companies_active_week`
    ).get();
    return json(res, 200, { totals, companies, users });
  }

  if (pathname.startsWith('/api/owner/')) {
    const s = user(req, res, ['owner', 'admin']);
    if (!s) return;

    if (pathname === '/api/owner/business' && req.method === 'GET') {
      const org = db
        .prepare('SELECT id,name,email,category,logo_url,created_at FROM organizations WHERE id=?')
        .get(s.org_id);
      return json(res, 200, org);
    }

    if (pathname === '/api/owner/audit' && req.method === 'GET') {
      const rows = db.prepare(
        `SELECT qe.created_at,qe.event_type action,q.ticket_number,c.name customer_name,
                sv.customer_name service_name,s.name staff_name,st.name station_name,qe.reason
         FROM queue_events qe
         JOIN queue_entries q ON q.id=qe.entry_id
         JOIN branches b ON b.id=q.branch_id
         JOIN customers c ON c.id=q.customer_id
         JOIN services sv ON sv.id=q.service_id
         LEFT JOIN staff s ON s.id=qe.performed_by
         LEFT JOIN service_stations st ON st.id=q.station_id
         WHERE b.org_id=?
         UNION ALL
         SELECT a.created_at,a.action,a.ticket_number,a.customer_name,a.service_name,
                a.staff_name,a.station_name,a.reason
         FROM audit_events a
         WHERE a.org_id=?
         ORDER BY created_at DESC
         LIMIT 500`
      ).all(s.org_id, s.org_id);
      return json(res, 200, { events: rows });
    }

    if (pathname === '/api/owner/business' && req.method === 'POST') {
      const x = await parseBody(req);
      const name = cleanText(x.name, 120);
      if (!name) return json(res, 400, { error: 'Business name required' });
      db.prepare(
        'UPDATE organizations SET name=?, category=?, logo_url=? WHERE id=?'
      ).run(
        name,
        cleanText(x.category, 80) || null,
        cleanText(x.logo_url, 500) || null,
        s.org_id
      );
      return json(
        res,
        200,
        db
          .prepare('SELECT id,name,email,category,logo_url,created_at FROM organizations WHERE id=?')
          .get(s.org_id)
      );
    }

    if (pathname === '/api/owner/company' && req.method === 'GET') {
      const org = db.prepare('SELECT * FROM organizations WHERE id=?').get(s.org_id);
      const branch = getDefaultBranchForOrg(s.org_id);
      return json(res, 200, {
        company: org,
        access: organizationAccessData(org),
        branch: branch ? { id: branch.id, code: branch.code, name: branch.name } : null,
      });
    }

    if (pathname === '/api/owner/services' && req.method === 'GET') {
      const branch = getDefaultBranchForOrg(s.org_id);
      if (!branch) return json(res, 404, { error: 'Queue not found' });
      return json(res, 200, db.prepare('SELECT * FROM services WHERE branch_id=? ORDER BY name').all(branch.id));
    }

    if (pathname === '/api/owner/services/quick' && req.method === 'POST') {
      const branch = getDefaultBranchForOrg(s.org_id);
      if (!branch) return json(res, 404, { error: 'Queue not found' });
      const x = await parseBody(req);
      const templates = Array.isArray(x.templates) && x.templates.length ? x.templates : QUICK_SERVICE_TEMPLATES.map((t) => t.name);
      const created = [];
      for (const entry of templates) {
        const template = QUICK_SERVICE_TEMPLATES.find((t) => String(t.name).toLowerCase() === String(entry).toLowerCase() || String(t.customer_name || t.name).toLowerCase() === String(entry).toLowerCase());
        if (!template) continue;
        const name = cleanText(template.name, 120);
        const customerName = cleanText(template.customer_name || template.name, 120) || name;
        const category = cleanText(template.category, 60) || 'General';
        const keywords = cleanText(template.search_keywords, 250) || name;
        const dur = Math.min(480, Math.max(1, Number(template.estimated_duration) || 15));
        try {
          const r = db.prepare('INSERT INTO services(branch_id,name,customer_name,category,search_keywords,estimated_duration) VALUES(?,?,?,?,?,?)').run(branch.id, name, customerName, category, keywords, dur);
          created.push(db.prepare('SELECT * FROM services WHERE id=?').get(r.lastInsertRowid));
        } catch {}
      }
      return json(res, 201, { created });
    }

    if (pathname === '/api/owner/services' && req.method === 'POST') {
      const branch = getDefaultBranchForOrg(s.org_id);
      if (!branch) return json(res, 404, { error: 'Queue not found' });
      const x = await parseBody(req);
      const name = cleanText(x.name);
      const customerName = cleanText(x.customer_name || x.name, 120) || name;
      const category = cleanText(x.category, 60) || 'General';
      const keywords = cleanText(x.search_keywords, 250) || name;
      const dur = Math.min(480, Math.max(1, Number(x.estimated_duration) || 15));
      if (!name) return json(res, 400, { error: 'Service name required' });
      try {
        const r = db.prepare('INSERT INTO services(branch_id,name,customer_name,category,search_keywords,estimated_duration) VALUES(?,?,?,?,?,?)').run(branch.id, name, customerName, category, keywords, dur);
        return json(res, 201, db.prepare('SELECT * FROM services WHERE id=?').get(r.lastInsertRowid));
      } catch {
        return json(res, 409, { error: 'Service already exists' });
      }
    }

    if (pathname === '/api/owner/settings' && req.method === 'GET') {
      const branch = getDefaultBranchForOrg(s.org_id);
      if (!branch) return json(res, 404, { error: 'Queue not found' });
      return json(res, 200, q.settings(branch.id));
    }

    if (pathname === '/api/owner/settings' && req.method === 'POST') {
      const branch = getDefaultBranchForOrg(s.org_id);
      if (!branch) return json(res, 404, { error: 'Queue not found' });
      const x = await parseBody(req);
      const bool = (v, d = 1) => v === false || v === 0 || v === '0' ? 0 : v === true || v === 1 || v === '1' ? 1 : d;
      const grace = Math.min(60, Math.max(1, Number(x.grace_period_minutes) || 5));
      const action = ['skip', 'end_of_queue', 'staff_decides'].includes(x.no_show_action) ? x.no_show_action : 'skip';
      const prefix = cleanText(x.ticket_prefix, 8) || 'Q';
      const soon = Math.min(50, Math.max(1, Number(x.return_soon_threshold) || 5));
      const nowT = Math.min(soon, Math.max(0, Number(x.return_now_threshold) || 2));
      db.prepare(`UPDATE queue_settings SET grace_period_minutes=?, no_show_action=?, allow_customer_cancel=?, allow_walkins=?, staff_can_skip=?, staff_can_cancel=?, staff_can_restore=?, show_customer_phone=?, lock_staff_to_station=?, return_soon_threshold=?, return_now_threshold=?, ticket_prefix=?, require_otp=?, notify_in_app=?, notify_sms=?, notify_push=?, notify_thresholds=?, updated_at=CURRENT_TIMESTAMP WHERE branch_id=?`).run(grace, action, bool(x.allow_customer_cancel, 1), bool(x.allow_walkins, 1), bool(x.staff_can_skip, 1), bool(x.staff_can_cancel, 1), bool(x.staff_can_restore, 1), bool(x.show_customer_phone, 1), bool(x.lock_staff_to_station, 1), soon, nowT, prefix, bool(x.require_otp, 0), bool(x.notify_in_app, 1), bool(x.notify_sms, 0), bool(x.notify_push, 1), JSON.stringify([soon, nowT, 0]), branch.id);
      recordAuditEvent({ orgId: s.org_id, userId: s.id, action: 'SETTINGS_CHANGED', metadata: { ticket_prefix: prefix, no_show_action: action } });
      return json(res, 200, q.settings(branch.id));
    }

    if (pathname.match(/^\/api\/owner\/branches\/(\d+)\/access$/) && req.method === 'POST') {
      const b = branchFor(s, pathname.match(/^\/api\/owner\/branches\/(\d+)\/access$/)[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      const x = await parseBody(req);
      const action = x.action === 'destroy' ? 'destroy' : 'create';
      const mode = ['code', 'token', 'qr', 'both'].includes(String(x.mode || 'token'))
        ? String(x.mode || 'token')
        : 'token';
      if (action === 'destroy') {
        db.prepare(
          'UPDATE branches SET access_mode=?, access_token=?, qr_code_url=? WHERE id=?'
        ).run('code', null, null, b.id);
        return json(res, 200, branchAccessData(db.prepare('SELECT * FROM branches WHERE id=?').get(b.id)));
      }
      const hasExisting = !!(b.access_token || b.qr_code_url);
      if (hasExisting) {
        return json(res, 409, { error: 'There is an active QR code or access token for this branch. Destroy it before creating another one.' });
      }
      const nextMode = mode === 'code' ? 'code' : mode;
      const accessToken = ['token', 'both'].includes(nextMode)
        ? generateAccessToken(b.code)
        : null;
      const qrCode = ['qr', 'both'].includes(nextMode)
        ? qrCodeUrlForBranch(b.code, accessToken)
        : null;
      db.prepare(
        'UPDATE branches SET access_mode=?, access_token=?, qr_code_url=? WHERE id=?'
      ).run(nextMode, accessToken, qrCode, b.id);
      return json(res, 200, branchAccessData(db.prepare('SELECT * FROM branches WHERE id=?').get(b.id)));
    }

    if (pathname.match(/^\/api\/owner\/branches\/(\d+)\/access$/) && req.method === 'GET') {
      const b = branchFor(s, pathname.match(/^\/api\/owner\/branches\/(\d+)\/access$/)[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      return json(res, 200, branchAccessData(b));
    }

    if (pathname === '/api/owner/branches' && req.method === 'GET') {
      const branches = db
        .prepare(
          'SELECT * FROM branches WHERE org_id=? AND is_active=1 ORDER BY name'
        )
        .all(s.org_id);
      if (!branches.length) {
        const created = ensureDefaultBranch(s.org_id, db.prepare('SELECT name FROM organizations WHERE id=?').get(s.org_id)?.name || 'Main Queue');
        return json(
          res,
          200,
          db.prepare('SELECT * FROM branches WHERE org_id=? AND is_active=1 ORDER BY name').all(s.org_id)
        );
      }
      return json(res, 200, branches);
    }

    if (pathname === '/api/owner/branches' && req.method === 'POST') {
      const b = await parseBody(req);
      const name = cleanText(b.name);
      if (!name) return json(res, 400, { error: 'Branch name required' });
      const code =
        cleanText(b.code, 30).toUpperCase() || `QU-${crypto.randomInt(1000, 10000)}`;
      try {
        const r = db
          .prepare(
            'INSERT INTO branches(org_id,name,code,address,phone,opening_hours) VALUES(?,?,?,?,?,?)'
          )
          .run(
            s.org_id,
            name,
            code,
            cleanText(b.address, 250),
            cleanText(b.phone, 30),
            cleanText(b.opening_hours, 200)
          );
        db.prepare('INSERT INTO queue_settings(branch_id, require_otp) VALUES(?,0)').run(
          r.lastInsertRowid
        );
        return json(
          res,
          201,
          db.prepare('SELECT * FROM branches WHERE id=?').get(r.lastInsertRowid)
        );
      } catch {
        return json(res, 409, { error: 'Branch code already exists' });
      }
    }

    const bm = pathname.match(/^\/api\/owner\/branches\/(\d+)$/);
    if (bm && req.method === 'GET') {
      const b = branchFor(s, bm[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      return json(res, 200, {
        branch: b,
        access: branchAccessData(b),
        services: db
          .prepare('SELECT * FROM services WHERE branch_id=? ORDER BY name')
          .all(b.id),
        stations: db
          .prepare(
            'SELECT * FROM service_stations WHERE branch_id=? ORDER BY name'
          )
          .all(b.id),
        staff: db
          .prepare(
            `SELECT st.id,st.name,st.email,st.role,st.is_active,st.station_id,ss.name station_name
             FROM staff st LEFT JOIN service_stations ss ON ss.id=st.station_id
             WHERE st.org_id=? AND st.branch_id=? ORDER BY st.name`
          )
          .all(s.org_id, b.id),
        settings: q.settings(b.id),
        stats: q.analytics(b.id),
        history: q.history(b.id),
        join_path: `/join.html?branch=${encodeURIComponent(b.code)}`,
      });
    }

    const settingsM = pathname.match(/^\/api\/owner\/branches\/(\d+)\/settings$/);
    if (settingsM && req.method === 'POST') {
      const b = branchFor(s, settingsM[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      const x = await parseBody(req);
      const bool = (v, d = 1) =>
        v === false || v === 0 || v === '0' ? 0 : v === true || v === 1 || v === '1' ? 1 : d;
      const grace = Math.min(60, Math.max(1, Number(x.grace_period_minutes) || 5));
      const action = ['skip', 'end_of_queue', 'staff_decides'].includes(x.no_show_action)
        ? x.no_show_action
        : 'skip';
      const prefix = cleanText(x.ticket_prefix, 8) || 'Q';
      const soon = Math.min(50, Math.max(1, Number(x.return_soon_threshold) || 5));
      const nowT = Math.min(soon, Math.max(0, Number(x.return_now_threshold) || 2));
      const thresholds = JSON.stringify([soon, nowT, 0]);
      db.prepare(
        `UPDATE queue_settings SET
           grace_period_minutes=?, no_show_action=?, allow_customer_cancel=?,
           allow_walkins=?, staff_can_skip=?, staff_can_cancel=?, staff_can_restore=?,
           show_customer_phone=?, lock_staff_to_station=?,
           return_soon_threshold=?, return_now_threshold=?, ticket_prefix=?,
           require_otp=?, notify_in_app=?, notify_sms=?, notify_push=?,
           notify_thresholds=?,
           updated_at=CURRENT_TIMESTAMP
         WHERE branch_id=?`
      ).run(
        grace,
        action,
        bool(x.allow_customer_cancel, 1),
        bool(x.allow_walkins, 1),
        bool(x.staff_can_skip, 1),
        bool(x.staff_can_cancel, 1),
        bool(x.staff_can_restore, 1),
        bool(x.show_customer_phone, 1),
        bool(x.lock_staff_to_station, 1),
        soon,
        nowT,
        prefix,
        bool(x.require_otp, 0),
        bool(x.notify_in_app, 1),
        bool(x.notify_sms, 0),
        bool(x.notify_push, 1),
        thresholds,
        b.id
      );
      return json(res, 200, q.settings(b.id));
    }

    const quickSm = pathname.match(/^\/api\/owner\/branches\/(\d+)\/services\/quick$/);
    if (quickSm && req.method === 'POST') {
      const b = branchFor(s, quickSm[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      const x = await parseBody(req);
      const source = Array.isArray(x.templates) && x.templates.length ? x.templates : [x.template || 'general'];
      const selected = source.flatMap((entry) => {
        const match = QUICK_SERVICE_TEMPLATES.find((t) => String(t.name).toLowerCase() === String(entry).toLowerCase() || String(t.customer_name || t.name).toLowerCase() === String(entry).toLowerCase());
        return match ? [match] : [];
      });
      const templates = selected.length ? selected : QUICK_SERVICE_TEMPLATES.slice(0, 4);
      const created = [];
      for (const t of templates) {
        try {
          const customerName = cleanText(t.customer_name || t.name, 120) || cleanText(t.name, 120);
          const name = cleanText(t.name, 120);
          const category = cleanText(t.category, 60) || 'General';
          const keywords = cleanText(t.search_keywords, 250) || name;
          const dur = Math.min(480, Math.max(1, Number(t.estimated_duration) || 15));
          const r = db
            .prepare(
              'INSERT INTO services(branch_id,name,customer_name,category,search_keywords,estimated_duration) VALUES(?,?,?,?,?,?)'
            )
            .run(b.id, name, customerName, category, keywords, dur);
          created.push(db.prepare('SELECT * FROM services WHERE id=?').get(r.lastInsertRowid));
        } catch {}
      }
      return json(res, 201, { created });
    }

    const sm = pathname.match(/^\/api\/owner\/branches\/(\d+)\/services$/);
    if (sm && req.method === 'POST') {
      const b = branchFor(s, sm[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      const x = await parseBody(req);
      const name = cleanText(x.name);
      const customerName = cleanText(x.customer_name || x.name, 120) || name;
      const category = cleanText(x.category, 60) || 'General';
      const keywords = cleanText(x.search_keywords, 250) || name;
      const dur = Math.min(480, Math.max(1, Number(x.estimated_duration) || 15));
      if (!name) return json(res, 400, { error: 'Service name required' });
      try {
        const r = db
          .prepare(
            'INSERT INTO services(branch_id,name,customer_name,category,search_keywords,estimated_duration) VALUES(?,?,?,?,?,?)'
          )
          .run(b.id, name, customerName, category, keywords, dur);
        return json(
          res,
          201,
          db.prepare('SELECT * FROM services WHERE id=?').get(r.lastInsertRowid)
        );
      } catch {
        return json(res, 409, { error: 'Service already exists' });
      }
    }

    const stm = pathname.match(/^\/api\/owner\/branches\/(\d+)\/stations$/);
    if (stm && req.method === 'POST') {
      const b = branchFor(s, stm[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      const x = await parseBody(req);
      const name = cleanText(x.name);
      const sid = x.service_id ? Number(x.service_id) : null;
      if (!name) return json(res, 400, { error: 'Station name required' });
      if (
        sid &&
        !db
          .prepare('SELECT id FROM services WHERE id=? AND branch_id=?')
          .get(sid, b.id)
      ) {
        return json(res, 400, { error: 'Invalid service' });
      }
      const r = db
        .prepare(
          'INSERT INTO service_stations(branch_id,name,service_id) VALUES(?,?,?)'
        )
        .run(b.id, name, sid);
      return json(
        res,
        201,
        db
          .prepare('SELECT * FROM service_stations WHERE id=?')
          .get(r.lastInsertRowid)
      );
    }

    const stm2 = pathname.match(/^\/api\/owner\/branches\/(\d+)\/staff$/);
    if (stm2 && req.method === 'POST') {
      const b = branchFor(s, stm2[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      const x = await parseBody(req);
      const role = ['receptionist', 'admin'].includes(x.role)
        ? x.role
        : 'receptionist';
      if (!x.name || !x.email || String(x.password || '').length < 8) {
        return json(res, 400, {
          error: 'Name, email and an 8+ character password are required',
        });
      }
      let stationId = x.station_id ? Number(x.station_id) : null;
      if (stationId) {
        const st = db
          .prepare('SELECT id FROM service_stations WHERE id=? AND branch_id=?')
          .get(stationId, b.id);
        if (!st) return json(res, 400, { error: 'Invalid station for this branch' });
      }
      try {
        const r = db
          .prepare(
            'INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)'
          )
          .run(
            s.org_id,
            b.id,
            stationId,
            cleanText(x.name),
            String(x.email).trim().toLowerCase(),
            hashPassword(x.password),
            role
          );
        return json(
          res,
          201,
          db
            .prepare(
              `SELECT st.id,st.name,st.email,st.role,st.branch_id,st.station_id,st.is_active,ss.name station_name
               FROM staff st LEFT JOIN service_stations ss ON ss.id=st.station_id
               WHERE st.id=?`
            )
            .get(r.lastInsertRowid)
        );
      } catch {
        return json(res, 409, { error: 'Email already exists — each staff needs a unique login' });
      }
    }

    const staffPatch = pathname.match(/^\/api\/owner\/branches\/(\d+)\/staff\/(\d+)$/);
    if (staffPatch && req.method === 'POST') {
      const b = branchFor(s, staffPatch[1]);
      if (!b) return json(res, 404, { error: 'Branch not found' });
      const member = db
        .prepare('SELECT * FROM staff WHERE id=? AND branch_id=? AND org_id=?')
        .get(Number(staffPatch[2]), b.id, s.org_id);
      if (!member) return json(res, 404, { error: 'Staff not found' });
      const x = await parseBody(req);
      let stationId =
        x.station_id === '' || x.station_id === null || x.station_id === undefined
          ? null
          : Number(x.station_id);
      if (stationId) {
        const st = db
          .prepare('SELECT id FROM service_stations WHERE id=? AND branch_id=?')
          .get(stationId, b.id);
        if (!st) return json(res, 400, { error: 'Invalid station' });
      }
      const isActive =
        x.is_active === undefined
          ? member.is_active
          : x.is_active === false || x.is_active === 0
            ? 0
            : 1;
      db.prepare('UPDATE staff SET station_id=?, is_active=? WHERE id=?').run(
        stationId,
        isActive,
        member.id
      );
      return json(
        res,
        200,
        db
          .prepare(
            `SELECT st.id,st.name,st.email,st.role,st.branch_id,st.station_id,st.is_active,ss.name station_name
             FROM staff st LEFT JOIN service_stations ss ON ss.id=st.station_id
             WHERE st.id=?`
          )
          .get(member.id)
      );
    }
  }

  if (pathname.startsWith('/api/staff/')) {
    const s = user(req, res, ['receptionist', 'owner', 'admin']);
    if (!s) return;
    const bid =
      s.branch_id ||
      Number(new URL(req.url, 'http://x').searchParams.get('branch_id'));
    const b = branchFor(s, bid);
    if (!b) return json(res, 404, { error: 'Branch not found' });
    const set = q.settings(b.id);
    const showPhone = !!set.show_customer_phone;

    if ((pathname === '/api/staff/company' || pathname === '/api/staff/branch') && req.method === 'GET') {
      const company = db
        .prepare('SELECT id,name,email,category,logo_url,company_public_code,company_access_token FROM organizations WHERE id=?')
        .get(s.org_id);
      return json(res, 200, {
        me: {
          id: s.id,
          name: s.name,
          email: s.email,
          role: s.role,
          station_id: s.station_id,
          station_name: s.station_name,
        },
        company: {
          id: company?.id || s.org_id,
          name: company?.name || 'Company',
          category: company?.category || 'General',
          email: company?.email || null,
          logo_url: company?.logo_url || null,
          public_code: company?.company_public_code || null,
          access_token: company?.company_access_token || null,
        },
        branch: b,
        org: company,
        services: db
          .prepare(
            'SELECT * FROM services WHERE branch_id=? AND is_active=1 ORDER BY name'
          )
          .all(b.id),
        stations: db
          .prepare(
            'SELECT * FROM service_stations WHERE branch_id=? AND is_active=1 ORDER BY name'
          )
          .all(b.id),
        queue: q.active(b.id, { showPhone }),
        now_serving: q.nowServing(b.id),
        next: q.nextWaiting(b.id),
        history: q.history(b.id, { showPhone }),
        stats: q.analytics(b.id),
        settings: set,
      });
    }

    if (pathname === '/api/staff/search' && req.method === 'GET') {
      const query = new URL(req.url, 'http://x').searchParams.get('q') || '';
      return json(res, 200, q.search(b.id, query, { showPhone }));
    }

    if (pathname === '/api/staff/queue/next' && req.method === 'POST') {
      const next = q.nextWaiting(b.id);
      if (!next) return json(res, 404, { error: 'No waiting customers' });
      try {
        return json(
          res,
          200,
          q.transition(next.id, 'CALLED', { by: s.id, reason: 'Next customer' })
        );
      } catch (err) {
        return json(res, 409, { error: err.message });
      }
    }

    if (pathname === '/api/staff/queue/create' && req.method === 'POST') {
      if (!set.allow_walkins) {
        return json(res, 403, { error: 'Walk-in tickets are disabled in settings' });
      }
      const x = await parseBody(req);
      const phone = normalizePhone(x.phone);
      if (phone && phone.length < 7) {
        return json(res, 400, { error: 'Valid phone number required' });
      }
      if (!x.service_id) {
        return json(res, 400, { error: 'Service is required' });
      }
      try {
        return json(
          res,
          201,
          q.create({
            branchId: b.id,
            serviceId: Number(x.service_id),
            phone,
            name: cleanText(x.name),
            by: s.id,
          })
        );
      } catch (e) {
        return json(res, 400, { error: e.message });
      }
    }

    const m = pathname.match(
      /^\/api\/staff\/queue\/(\d+)\/(call|arrive|start|finish|skip|noshow|cancel|restore|service)$/
    );
    if (m) {
      const e = q.get(Number(m[1]));
      if (!e || e.branch_id !== b.id) {
        return json(res, 404, { error: 'Queue entry not found' });
      }
      const x = req.method === 'POST' ? await parseBody(req) : {};
      const action = m[2];
      if (action === 'skip' && !set.staff_can_skip) {
        return json(res, 403, { error: 'Skipping is disabled in settings' });
      }
      if (action === 'cancel' && !set.staff_can_cancel) {
        return json(res, 403, { error: 'Staff cancellation is disabled in settings' });
      }
      if (action === 'restore' && !set.staff_can_restore) {
        return json(res, 403, { error: 'Restore is disabled in settings' });
      }
      try {
        if (action === 'service') {
          if (!x.service_id) return json(res, 400, { error: 'Service is required' });
          return json(
            res,
            200,
            q.changeService(e.id, Number(x.service_id), { by: s.id })
          );
        }
        if (action === 'restore') {
          return json(
            res,
            200,
            q.restore(e.id, { by: s.id, reason: cleanText(x.reason, 250) })
          );
        }
        let stationId = x.station_id ? Number(x.station_id) : null;
        if (action === 'start') {
          if (set.lock_staff_to_station && s.station_id) {
            stationId = s.station_id;
          } else if (!stationId && s.station_id) {
            stationId = s.station_id;
          }
          if (!stationId) {
            return json(res, 400, { error: 'Assign a station to this staff account first' });
          }
          if (
            set.lock_staff_to_station &&
            s.station_id &&
            stationId !== s.station_id
          ) {
            return json(res, 403, {
              error: 'This account can only serve from its assigned station',
            });
          }
        }
        const map = {
          call: 'CALLED',
          arrive: 'ARRIVED',
          start: 'SERVING',
          finish: 'COMPLETED',
          skip: 'SKIPPED',
          noshow: 'NO_SHOW',
          cancel: 'CANCELLED',
        };
        return json(
          res,
          200,
          q.transition(e.id, map[action], {
            by: s.id,
            reason: cleanText(x.reason, 250) || null,
            stationId,
          })
        );
      } catch (err) {
        return json(res, 409, { error: err.message });
      }
    }

    const ev = pathname.match(/^\/api\/staff\/queue\/(\d+)\/events$/);
    if (ev && req.method === 'GET') {
      const e = q.get(Number(ev[1]));
      if (!e || e.branch_id !== b.id) {
        return json(res, 404, { error: 'Queue entry not found' });
      }
      return json(
        res,
        200,
        db
          .prepare(
            `SELECT e.*,s.name staff_name
             FROM queue_events e LEFT JOIN staff s ON s.id=e.performed_by
             WHERE e.entry_id=? ORDER BY e.id`
          )
          .all(e.id)
      );
    }
  }

  return json(res, 404, { error: 'Not found' });
}

function isInsideFront(file) {
  const resolved = path.resolve(file);
  return (
    resolved === FRONT_RESOLVED ||
    resolved.startsWith(FRONT_RESOLVED + path.sep)
  );
}

function staticFile(req, res) {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/') p = '/index.html';
  if (p.includes('\0')) {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('Bad request');
  }
  const relative = p.replace(/^[/\\]+/, '').replace(/\\/g, '/');
  if (!relative || relative.split('/').some((part) => part === '..')) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('Not found');
  }
  const file = path.resolve(FRONT_RESOLVED, relative);
  if (!isInsideFront(file) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('Not found');
  }
  const ext = path.extname(file);
  const types = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
  };
  res.writeHead(200, {
    'content-type': types[ext] || 'application/octet-stream',
    'cache-control':
      NODE_ENV === 'production' ? 'public, max-age=3600' : 'no-cache',
    'x-content-type-options': 'nosniff',
  });
  fs.createReadStream(file).pipe(res);
}

seed();
(function assignMissingStations() {
  for (const b of db.prepare('SELECT id FROM branches WHERE is_active=1').all()) {
    const stations = db
      .prepare('SELECT id FROM service_stations WHERE branch_id=? AND is_active=1 ORDER BY id')
      .all(b.id);
    if (!stations.length) continue;
    const taken = new Set(
      db
        .prepare('SELECT station_id FROM staff WHERE branch_id=? AND station_id IS NOT NULL')
        .all(b.id)
        .map((r) => r.station_id)
    );
    const free = stations.filter((s) => !taken.has(s.id));
    const unassigned = db
      .prepare('SELECT id FROM staff WHERE branch_id=? AND station_id IS NULL ORDER BY id')
      .all(b.id);
    unassigned.forEach((s, i) => {
      const pick = free[i] || stations[i % stations.length];
      db.prepare('UPDATE staff SET station_id=? WHERE id=?').run(pick.id, s.id);
      taken.add(pick.id);
    });
  }
})();
(function ensureSecondDemoStaff() {
  if (NODE_ENV === 'production') return;
  const branch = db.prepare("SELECT id,org_id FROM branches WHERE code='QU-4827'").get();
  if (!branch) return;
  const stations = db
    .prepare('SELECT id FROM service_stations WHERE branch_id=? ORDER BY id')
    .all(branch.id);
  if (!stations.length) return;

  const reception = db
    .prepare("SELECT id,station_id FROM staff WHERE lower(email)='reception@qu.local'")
    .get();
  if (reception && stations[0] && reception.station_id !== stations[0].id) {
    db.prepare('UPDATE staff SET station_id=? WHERE id=?').run(stations[0].id, reception.id);
  }

  const exists = db
    .prepare("SELECT id,station_id FROM staff WHERE lower(email)='station2@qu.local'")
    .get();
  if (exists) {
    if (stations[1] && exists.station_id !== stations[1].id) {
      db.prepare('UPDATE staff SET station_id=? WHERE id=?').run(stations[1].id, exists.id);
    }
    return;
  }
  if (stations.length < 2) return;
  try {
    db.prepare(
      'INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)'
    ).run(
      branch.org_id,
      branch.id,
      stations[1].id,
      'Counter Two',
      'station2@qu.local',
      hashPassword('password'),
      'receptionist'
    );
  } catch {}
})();
noShow.start();
notifications.start();
setInterval(() => {
  q.tick();
  const payload = `data: ${JSON.stringify({ type: 'QUEUE_TICK', at: Date.now() })}\n\n`;
  for (const [r] of clients) {
    try {
      r.write(payload);
    } catch {
      clients.delete(r);
    }
  }
}, 5000).unref();

const requestHandler = async (req, res) => {
  try {
    if (!rate(req, res)) return;
    if (!req.url) return json(res, 400, { error: 'Bad request' });
    if (req.url.startsWith('/api/')) {
      await api(req, res, new URL(req.url, 'http://x').pathname);
    } else {
      staticFile(req, res);
    }
  } catch (e) {
    console.error(e);
    if (!res.headersSent) {
      json(res, 500, {
        error: NODE_ENV === 'production' ? 'Internal server error' : e.message,
      });
    }
  }
};

const server = TLS_CERT_PATH && TLS_KEY_PATH
  ? https.createServer({ cert: fs.readFileSync(TLS_CERT_PATH), key: fs.readFileSync(TLS_KEY_PATH) }, requestHandler)
  : http.createServer(requestHandler);

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`QueueOS running at http://${HOST}:${PORT}`);
  });
}

module.exports = {
  api,
  login,
  seed,
  server,
  organizationAccessData,
  resolveCompanyByAccess,
  getDefaultBranchForOrg,
  serviceSearchMatches,
};
