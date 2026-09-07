const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { DB_PATH } = require('../config');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(
  'PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;'
);

db.exec(`
CREATE TABLE IF NOT EXISTS organizations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  category TEXT,
  logo_url TEXT,
  company_public_code TEXT UNIQUE,
  company_qr_id TEXT UNIQUE,
  company_access_mode TEXT NOT NULL DEFAULT 'token' CHECK(company_access_mode IN ('code','token','qr','both')),
  company_access_token TEXT,
  company_qr_code_url TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  address TEXT,
  phone TEXT,
  opening_hours TEXT,
  access_mode TEXT NOT NULL DEFAULT 'code' CHECK(access_mode IN ('code','token','qr','both')),
  access_token TEXT,
  qr_code_url TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS staff(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  branch_id INTEGER REFERENCES branches(id) ON DELETE SET NULL,
  station_id INTEGER,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner','admin','receptionist')),
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS services(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  customer_name TEXT,
  category TEXT,
  search_keywords TEXT,
  estimated_duration INTEGER NOT NULL DEFAULT 15,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(branch_id,name)
);
CREATE TABLE IF NOT EXISTS service_stations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  service_id INTEGER REFERENCES services(id) ON DELETE SET NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS queue_settings(
  branch_id INTEGER PRIMARY KEY REFERENCES branches(id) ON DELETE CASCADE,
  grace_period_minutes INTEGER NOT NULL DEFAULT 5,
  no_show_action TEXT NOT NULL DEFAULT 'skip' CHECK(no_show_action IN ('skip','end_of_queue','staff_decides')),
  allow_customer_cancel INTEGER NOT NULL DEFAULT 1,
  allow_walkins INTEGER NOT NULL DEFAULT 1,
  staff_can_skip INTEGER NOT NULL DEFAULT 1,
  staff_can_cancel INTEGER NOT NULL DEFAULT 1,
  staff_can_restore INTEGER NOT NULL DEFAULT 1,
  show_customer_phone INTEGER NOT NULL DEFAULT 1,
  lock_staff_to_station INTEGER NOT NULL DEFAULT 1,
  return_soon_threshold INTEGER NOT NULL DEFAULT 5,
  return_now_threshold INTEGER NOT NULL DEFAULT 2,
  notify_thresholds TEXT NOT NULL DEFAULT '[5,2,0]',
  ticket_prefix TEXT NOT NULL DEFAULT 'Q',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS customers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL UNIQUE,
  name TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS queue_counters(
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  queue_date TEXT NOT NULL,
  sequence INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(branch_id,queue_date)
);
CREATE TABLE IF NOT EXISTS queue_entries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  service_id INTEGER NOT NULL REFERENCES services(id),
  customer_id INTEGER NOT NULL REFERENCES customers(id),
  ticket_number TEXT NOT NULL,
  queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  access_token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'WAITING' CHECK(status IN ('WAITING','CALLED','ARRIVED','SERVING','COMPLETED','SKIPPED','NO_SHOW','CANCELLED')),
  station_id INTEGER REFERENCES service_stations(id) ON DELETE SET NULL,
  served_by INTEGER REFERENCES staff(id) ON DELETE SET NULL,
  position INTEGER,
  people_ahead INTEGER NOT NULL DEFAULT 0,
  estimated_wait_low INTEGER NOT NULL DEFAULT 0,
  estimated_wait_high INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  called_at TEXT,
  arrived_at TEXT,
  started_at TEXT,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS queue_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id INTEGER NOT NULL REFERENCES queue_entries(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  performed_by INTEGER REFERENCES staff(id) ON DELETE SET NULL,
  reason TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_entries_branch_active ON queue_entries(branch_id,status,queued_at,id);
CREATE INDEX IF NOT EXISTS idx_entries_ticket ON queue_entries(ticket_number);
CREATE INDEX IF NOT EXISTS idx_events_entry ON queue_events(entry_id,created_at,id);
CREATE INDEX IF NOT EXISTS idx_staff_branch ON staff(branch_id,is_active);
`);

function ensureColumn(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (cols.some((c) => c.name === column)) return;

  const sanitizedDefinition = definition.replace(/\s+UNIQUE\b/gi, '');
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${sanitizedDefinition}`);

  if (/\bUNIQUE\b/i.test(definition)) {
    const indexName = `idx_${table}_${column}_unique`;
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS ${indexName} ON ${table}(${column})`);
  }
}

ensureColumn('staff', 'station_id', 'INTEGER');
ensureColumn('services', 'customer_name', 'TEXT');
ensureColumn('services', 'category', 'TEXT');
ensureColumn('services', 'search_keywords', 'TEXT');
ensureColumn('organizations', 'company_public_code', 'TEXT');
ensureColumn('organizations', 'company_qr_id', 'TEXT');
ensureColumn('organizations', 'company_access_mode', "TEXT NOT NULL DEFAULT 'token' CHECK(company_access_mode IN ('code','token','qr','both'))");
ensureColumn('organizations', 'company_access_token', 'TEXT');
ensureColumn('organizations', 'company_qr_code_url', 'TEXT');
db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_company_public_code ON organizations(company_public_code);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_company_qr_id ON organizations(company_qr_id);
`);
ensureColumn('branches', 'access_mode', "TEXT NOT NULL DEFAULT 'code' CHECK(access_mode IN ('code','token','qr','both'))");
ensureColumn('branches', 'access_token', 'TEXT');
ensureColumn('branches', 'qr_code_url', 'TEXT');
ensureColumn('queue_entries', 'served_by', 'INTEGER REFERENCES staff(id) ON DELETE SET NULL');
ensureColumn('queue_settings', 'allow_walkins', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('queue_settings', 'staff_can_skip', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('queue_settings', 'staff_can_cancel', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('queue_settings', 'staff_can_restore', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('queue_settings', 'show_customer_phone', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('queue_settings', 'lock_staff_to_station', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('queue_settings', 'return_soon_threshold', 'INTEGER NOT NULL DEFAULT 5');
ensureColumn('queue_settings', 'return_now_threshold', 'INTEGER NOT NULL DEFAULT 2');
ensureColumn('queue_settings', 'require_otp', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('queue_settings', 'notify_in_app', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('queue_settings', 'notify_sms', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('queue_settings', 'notify_push', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('organizations', 'is_active', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('organizations', 'last_activity_at', 'TEXT');
ensureColumn('queue_entries', 'last_notify_level', 'INTEGER');

db.exec('UPDATE queue_settings SET require_otp=0 WHERE require_otp IS NULL OR require_otp=1;');

function pruneLegacyDemoOrganizations() {
const realCount = db
  .prepare(
    "SELECT COUNT(*) AS n FROM organizations WHERE lower(email) NOT LIKE '%@qu.local' AND lower(name) <> 'queueos demo'"
  )
  .get().n;
if (realCount === 0) return;

const demoOrgIds = db
  .prepare(
    "SELECT id FROM organizations WHERE lower(name) = 'queueos demo' OR lower(email) LIKE '%@qu.local' OR lower(name) LIKE '%demo%'"
  )
  .all()
  .map((row) => row.id);

if (!demoOrgIds.length) return;

const placeholders = demoOrgIds.map(() => '?').join(',');
db.prepare(`DELETE FROM organizations WHERE id IN (${placeholders})`).run(...demoOrgIds);
}

pruneLegacyDemoOrganizations();

db.exec(`
CREATE TABLE IF NOT EXISTS staff_invitations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  invited_by INTEGER REFERENCES staff(id) ON DELETE SET NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner','admin','receptionist')),
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','cancelled','expired')),
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_invites_org_email ON staff_invitations(org_id,email,status,expires_at);
CREATE TABLE IF NOT EXISTS otp_codes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes(phone,branch_id,expires_at);
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id INTEGER NOT NULL REFERENCES queue_entries(id) ON DELETE CASCADE,
  channel TEXT NOT NULL,
  level INTEGER NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_notifications_entry ON notifications(entry_id,created_at);
CREATE TABLE IF NOT EXISTS user_sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  org_id INTEGER,
  branch_id INTEGER,
  role TEXT NOT NULL,
  email TEXT NOT NULL,
  session_id TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  device_id TEXT,
  remember_me INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  revoked_at TEXT,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id, is_active, revoked_at, expires_at);
CREATE TABLE IF NOT EXISTS audit_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER,
  user_id INTEGER,
  action TEXT NOT NULL,
  ticket_number TEXT,
  customer_name TEXT,
  service_name TEXT,
  staff_name TEXT,
  station_name TEXT,
  reason TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_events(org_id, created_at DESC);
CREATE TABLE IF NOT EXISTS platform_users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  last_login_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

module.exports = db;
