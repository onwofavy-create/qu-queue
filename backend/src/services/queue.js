const EventEmitter = require('node:events');
const crypto = require('node:crypto');
const db = require('../db/database');
const { randomToken, hashToken, normalizePhone, cleanText } = require('../utils/security');

const events = new EventEmitter();
const TRANSITIONS = {
  WAITING: ['CALLED', 'CANCELLED', 'SKIPPED'],
  CALLED: ['ARRIVED', 'NO_SHOW', 'CANCELLED', 'WAITING'],
  ARRIVED: ['SERVING', 'NO_SHOW', 'CANCELLED', 'WAITING'],
  SERVING: ['COMPLETED', 'CANCELLED'],
  COMPLETED: [],
  SKIPPED: ['WAITING'],
  NO_SHOW: ['WAITING'],
  CANCELLED: ['WAITING'],
};
const terminal = new Set(['COMPLETED', 'SKIPPED', 'NO_SHOW', 'CANCELLED']);
const now = () =>
  new Date().toISOString().replace('T', ' ').replace('Z', '').slice(0, 19);

function canTransition(a, b) {
  return !!TRANSITIONS[a]?.includes(b);
}

function log(id, type, by = null, reason = null, meta = null) {
  db.prepare(
    'INSERT INTO queue_events(entry_id,event_type,performed_by,reason,metadata) VALUES(?,?,?,?,?)'
  ).run(id, type, by, reason, meta ? JSON.stringify(meta) : null);
}

function settings(branchId) {
  return (
    db.prepare('SELECT * FROM queue_settings WHERE branch_id=?').get(branchId) || {
      ticket_prefix: 'Q',
      grace_period_minutes: 5,
      no_show_action: 'skip',
      allow_customer_cancel: 1,
      allow_walkins: 1,
      staff_can_skip: 1,
      staff_can_cancel: 1,
      staff_can_restore: 1,
      show_customer_phone: 1,
      lock_staff_to_station: 1,
      return_soon_threshold: 5,
      return_now_threshold: 2,
      require_otp: 0,
      notify_in_app: 1,
      notify_sms: 0,
      notify_push: 1,
    }
  );
}

function stations(branchId, serviceId) {
  return (
    db
      .prepare(
        'SELECT id FROM service_stations WHERE branch_id=? AND is_active=1 AND (service_id IS NULL OR service_id=?)'
      )
      .all(branchId, serviceId).length || 1
  );
}

function duration(branchId, serviceId) {
  const x = db
    .prepare(
      `SELECT AVG((julianday(completed_at)-julianday(started_at))*86400) avg
       FROM queue_entries
       WHERE branch_id=? AND service_id=? AND status='COMPLETED'
         AND started_at IS NOT NULL AND completed_at IS NOT NULL
         AND completed_at>=datetime('now','-30 days')`
    )
    .get(branchId, serviceId);
  if (x?.avg) return Math.max(60, Math.round(x.avg));
  const s = db
    .prepare('SELECT estimated_duration FROM services WHERE id=? AND branch_id=?')
    .get(serviceId, branchId);
  return Math.max(60, (s?.estimated_duration || 15) * 60);
}

function estimate(branchId, serviceId, ahead) {
  const mins = duration(branchId, serviceId) / 60;
  const cap = stations(branchId, serviceId);
  const serving =
    db
      .prepare(
        `SELECT COUNT(*) n FROM queue_entries q
         JOIN service_stations st ON st.id=q.station_id
         WHERE q.branch_id=? AND q.service_id=? AND q.status='SERVING' AND st.is_active=1`
      )
      .get(branchId, serviceId)?.n || 0;
  const load = Math.max(0, serving - cap);
  const base = (Math.max(0, ahead + load) * mins) / cap;
  return {
    low: Math.max(0, Math.floor(base * 0.8)),
    high: Math.max(1, Math.ceil(base * 1.35 + 3)),
  };
}

/** Recalculate positions per service so waits rearrange as people leave/join. */
function recalc(branchId) {
  const rows = db
    .prepare(
      `SELECT * FROM queue_entries
       WHERE branch_id=? AND status IN ('WAITING','CALLED','ARRIVED')
       ORDER BY queued_at,id`
    )
    .all(branchId);
  const byService = new Map();
  for (const e of rows) {
    if (!byService.has(e.service_id)) byService.set(e.service_id, []);
    byService.get(e.service_id).push(e);
  }
  const update = db.prepare(
    'UPDATE queue_entries SET position=?,people_ahead=?,estimated_wait_low=?,estimated_wait_high=? WHERE id=?'
  );
  try {
    db.exec('BEGIN IMMEDIATE');
  } catch (e) {
    if (/locked/i.test(String(e && e.message))) return rows;
    throw e;
  }
  try {
    for (const [serviceId, list] of byService) {
      list.forEach((e, i) => {
       const est = estimate(branchId, serviceId, i);
       update.run(i + 1, i, est.low, est.high, e.id);
      });
    }
    db.exec('COMMIT');
  } catch (e) {
    try {
      db.exec('ROLLBACK');
    } catch {}
    if (/locked/i.test(String(e && e.message))) return rows;
    throw e;
  }
  return rows;
}

function publicEntry(e) {
  if (!e) return e;
  const { access_token_hash, ...safe } = e;
  return safe;
}

function get(id) {
  return db
    .prepare(
      `SELECT q.*, s.name service_name, b.name branch_name, b.code branch_code,
              c.name customer_name, c.phone,
              st.name station_name, sf.name served_by_name
       FROM queue_entries q
       JOIN services s ON s.id=q.service_id
       JOIN branches b ON b.id=q.branch_id
       JOIN customers c ON c.id=q.customer_id
       LEFT JOIN service_stations st ON st.id=q.station_id
       LEFT JOIN staff sf ON sf.id=q.served_by
       WHERE q.id=?`
    )
    .get(id);
}

function customerView(id) {
  const e = get(id);
  if (!e) return null;
  const set = settings(e.branch_id);
  const waitingSame =
    db
      .prepare(
        `SELECT COUNT(*) n FROM queue_entries
       WHERE branch_id=? AND service_id=? AND status IN ('WAITING','CALLED','ARRIVED')`
      )
      .get(e.branch_id, e.service_id)?.n || 0;
  const notes = db
    .prepare(
      `SELECT id,channel,level,title,body,created_at
       FROM notifications WHERE entry_id=? ORDER BY id DESC LIMIT 8`
    )
    .all(id);
  return publicEntry({
    ...e,
    queue_length: waitingSame,
    return_soon_threshold: set.return_soon_threshold ?? 5,
    return_now_threshold: set.return_now_threshold ?? 2,
    allow_customer_cancel: !!set.allow_customer_cancel,
    notifications: notes,
    monitoring: ['WAITING', 'CALLED', 'ARRIVED'].includes(e.status),
  });
}

function nextTicket(branchId, prefix) {
  const date = new Date().toISOString().slice(0, 10);
  db.exec('BEGIN IMMEDIATE');
  try {
    const row = db
      .prepare('SELECT sequence FROM queue_counters WHERE branch_id=? AND queue_date=?')
      .get(branchId, date);
    let n;
    if (row) {
      n = row.sequence + 1;
      db.prepare(
        'UPDATE queue_counters SET sequence=? WHERE branch_id=? AND queue_date=?'
      ).run(n, branchId, date);
    } else {
      n = 1;
      db.prepare(
        'INSERT INTO queue_counters(branch_id,queue_date,sequence) VALUES(?,?,1)'
      ).run(branchId, date);
    }
    db.exec('COMMIT');
    return `${prefix}${String(n).padStart(3, '0')}`;
  } catch (e) {
    try {
      db.exec('ROLLBACK');
    } catch {}
    throw e;
  }
}

function resolveCustomer(phone, name) {
  const normalized = normalizePhone(phone);
  const customerPhone = normalized || `anonymous-${Date.now()}-${crypto.randomInt(100000, 999999)}`;
  let customer = db.prepare('SELECT * FROM customers WHERE phone=?').get(customerPhone);
  if (!customer) {
    const row = db.prepare('INSERT INTO customers(phone,name) VALUES(?,?)').run(customerPhone, cleanText(name, 120) || null);
    customer = { id: Number(row.lastInsertRowid) };
  } else if (name) {
    db.prepare('UPDATE customers SET name=? WHERE id=?').run(cleanText(name, 120), customer.id);
  }
  return customer;
}

function create({ branchId, serviceId, phone, name, by = null }) {
  const b = db.prepare('SELECT id FROM branches WHERE id=? AND is_active=1').get(branchId);
  if (!b) throw Error('Branch not found');
  const s = db
    .prepare('SELECT id FROM services WHERE id=? AND branch_id=? AND is_active=1')
    .get(serviceId, branchId);
  if (!s) throw Error('Service not found');
  const customer = resolveCustomer(phone, name);
  const set = settings(branchId);
  const token = randomToken();
  const ticket = nextTicket(branchId, set.ticket_prefix || 'Q');
  const r = db
    .prepare(
      'INSERT INTO queue_entries(branch_id,service_id,customer_id,ticket_number,access_token_hash) VALUES(?,?,?,?,?)'
    )
    .run(branchId, serviceId, customer.id, ticket, hashToken(token));
  log(Number(r.lastInsertRowid), 'CREATED', by, by ? 'Walk-in' : 'Customer joined', {
    serviceId,
  });
  recalc(branchId);
  events.emit('changed', branchId);
  return { entry: publicEntry(get(Number(r.lastInsertRowid))), accessToken: token };
}

function authorize(id, token) {
  const e = get(id);
  if (!e) return null;
  const h = db.prepare('SELECT access_token_hash FROM queue_entries WHERE id=?').get(id)
    ?.access_token_hash;
  if (!h || !token) return null;
  const actual = hashToken(token);
  try {
    const a = Buffer.from(actual, 'utf8');
    const b = Buffer.from(h, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return e;
  } catch {
    return null;
  }
}

function transition(id, to, { by = null, reason = null, stationId = null } = {}) {
  const e = get(id);
  if (!e) throw Error('Queue entry not found');
  if (!canTransition(e.status, to)) throw Error(`Invalid transition: ${e.status} → ${to}`);
  if (to === 'SERVING') {
    if (!stationId) throw Error('Select a station');
    const st = db
      .prepare('SELECT * FROM service_stations WHERE id=? AND branch_id=? AND is_active=1')
      .get(stationId, e.branch_id);
    if (!st || !(st.service_id === null || st.service_id === e.service_id)) {
      throw Error('Station cannot serve this service');
    }
    const busy = db
      .prepare("SELECT id FROM queue_entries WHERE station_id=? AND status='SERVING' AND id<>?")
      .get(stationId, id);
    if (busy) throw Error('Station is already serving another ticket');
  }

  if (to === 'WAITING') {
    const r = db
      .prepare(
        `UPDATE queue_entries
         SET status=?, station_id=NULL, served_by=NULL,
             called_at=NULL, arrived_at=NULL, started_at=NULL, completed_at=NULL,
             position=NULL, people_ahead=0, estimated_wait_low=0, estimated_wait_high=1,
             last_notify_level=NULL
         WHERE id=? AND status=?`
      )
      .run(to, id, e.status);
    if (r.changes !== 1) throw Error('Queue changed; refresh and try again');
    log(id, to, by, reason, { stationId });
    recalc(e.branch_id);
    events.emit('changed', e.branch_id);
    return publicEntry(get(id));
  }

  const fields = {
    CALLED: 'called_at',
    ARRIVED: 'arrived_at',
    SERVING: 'started_at',
    COMPLETED: 'completed_at',
    SKIPPED: 'completed_at',
    NO_SHOW: 'completed_at',
    CANCELLED: 'completed_at',
  };
  const f = fields[to];
  const setServed =
    by && ['COMPLETED', 'SKIPPED', 'NO_SHOW', 'CANCELLED', 'SERVING'].includes(to)
      ? ',served_by=?'
      : '';
  const sql = f
    ? `UPDATE queue_entries SET status=?,station_id=COALESCE(?,station_id),${f}=?${setServed} WHERE id=? AND status=?`
    : `UPDATE queue_entries SET status=?,station_id=COALESCE(?,station_id)${setServed} WHERE id=? AND status=?`;
  const args = f
    ? setServed
      ? [to, stationId || null, now(), by, id, e.status]
      : [to, stationId || null, now(), id, e.status]
    : setServed
      ? [to, stationId || null, by, id, e.status]
      : [to, stationId || null, id, e.status];
  const r = db.prepare(sql).run(...args);
  if (r.changes !== 1) throw Error('Queue changed; refresh and try again');
  log(id, to, by, reason, { stationId });
  recalc(e.branch_id);
  events.emit('changed', e.branch_id);
  return publicEntry(get(id));
}

function restore(id, { by = null, reason = 'Restored' } = {}) {
  const e = get(id);
  if (!e || !terminal.has(e.status) || e.status === 'COMPLETED') {
    throw Error('Only skipped, no-show or cancelled tickets can be restored');
  }
  const r = db
    .prepare(
      `UPDATE queue_entries
       SET status='WAITING',queued_at=?,position=NULL,people_ahead=0,
           estimated_wait_low=0,estimated_wait_high=1,station_id=NULL,served_by=NULL,
           called_at=NULL,arrived_at=NULL,started_at=NULL,completed_at=NULL,
           last_notify_level=NULL
       WHERE id=? AND status=?`
    )
    .run(now(), id, e.status);
  if (r.changes !== 1) throw Error('Queue changed; refresh and try again');
  log(id, 'RESTORED', by, reason);
  recalc(e.branch_id);
  events.emit('changed', e.branch_id);
  return publicEntry(get(id));
}

function active(branchId, { showPhone = true } = {}) {
  recalc(branchId);
  const rows = db
    .prepare(
      `SELECT q.id,q.ticket_number,q.status,q.position,q.people_ahead,
              q.estimated_wait_low,q.estimated_wait_high,q.service_id,
              s.name service_name,c.name customer_name,c.phone,q.station_id,
              st.name station_name
       FROM queue_entries q
       JOIN services s ON s.id=q.service_id
       JOIN customers c ON c.id=q.customer_id
       LEFT JOIN service_stations st ON st.id=q.station_id
       WHERE q.branch_id=? AND q.status IN ('WAITING','CALLED','ARRIVED','SERVING')
       ORDER BY CASE q.status WHEN 'SERVING' THEN 0 ELSE 1 END, q.queued_at, q.id`
    )
    .all(branchId);
  if (showPhone) return rows;
  return rows.map(({ phone, ...rest }) => ({ ...rest, phone: null }));
}

function history(branchId, { showPhone = true } = {}) {
  const rows = db
    .prepare(
      `SELECT q.id,q.ticket_number,q.status,q.completed_at,q.served_by,
              s.name service_name,c.name customer_name,c.phone,
              sf.name handled_by, st.name station_name
       FROM queue_entries q
       JOIN services s ON s.id=q.service_id
       JOIN customers c ON c.id=q.customer_id
       LEFT JOIN staff sf ON sf.id=q.served_by
       LEFT JOIN service_stations st ON st.id=q.station_id
       WHERE q.branch_id=? AND q.status IN ('COMPLETED','SKIPPED','NO_SHOW','CANCELLED')
         AND DATE(q.created_at)=DATE('now')
       ORDER BY q.completed_at DESC, q.id DESC
       LIMIT 200`
    )
    .all(branchId);
  if (showPhone) return rows;
  return rows.map(({ phone, ...rest }) => ({ ...rest, phone: null }));
}

function stats(branchId) {
  const countsRaw = db
    .prepare(
      `SELECT status, COUNT(*) n FROM queue_entries
       WHERE branch_id=? AND DATE(created_at)=DATE('now')
       GROUP BY status`
    )
    .all(branchId);
  const counts = {
    WAITING: 0,
    CALLED: 0,
    ARRIVED: 0,
    SERVING: 0,
    COMPLETED: 0,
    SKIPPED: 0,
    NO_SHOW: 0,
    CANCELLED: 0,
  };
  for (const r of countsRaw) counts[r.status] = r.n;

  const byStaff = db
    .prepare(
      `SELECT st.id staff_id, st.name staff_name, e.event_type, COUNT(*) n
       FROM queue_events e
       JOIN queue_entries q ON q.id=e.entry_id
       JOIN staff st ON st.id=e.performed_by
       WHERE q.branch_id=? AND DATE(e.created_at)=DATE('now')
         AND e.event_type IN ('COMPLETED','SKIPPED','NO_SHOW','CANCELLED','CALLED','SERVING')
       GROUP BY st.id, e.event_type
       ORDER BY st.name, e.event_type`
    )
    .all(branchId);

  const staffSummary = {};
  for (const row of byStaff) {
    if (!staffSummary[row.staff_id]) {
      staffSummary[row.staff_id] = {
        id: row.staff_id,
        name: row.staff_name,
        completed: 0,
        skipped: 0,
        no_show: 0,
        cancelled: 0,
        called: 0,
        serving: 0,
      };
    }
    const key = {
      COMPLETED: 'completed',
      SKIPPED: 'skipped',
      NO_SHOW: 'no_show',
      CANCELLED: 'cancelled',
      CALLED: 'called',
      SERVING: 'serving',
    }[row.event_type];
    if (key) staffSummary[row.staff_id][key] = row.n;
  }

  return {
    counts,
    done: counts.COMPLETED,
    skipped: counts.SKIPPED,
    no_show: counts.NO_SHOW,
    cancelled: counts.CANCELLED,
    total:
      counts.WAITING +
      counts.CALLED +
      counts.ARRIVED +
      counts.SERVING +
      counts.COMPLETED +
      counts.SKIPPED +
      counts.NO_SHOW +
      counts.CANCELLED,
    staff: Object.values(staffSummary),
  };
}

function analytics(branchId) {
  const base = stats(branchId);
  const wait = db
    .prepare(
      `SELECT AVG((julianday(COALESCE(started_at,completed_at))-julianday(queued_at))*1440) avg_wait,
              MAX((julianday(COALESCE(started_at,completed_at))-julianday(queued_at))*1440) max_wait
       FROM queue_entries
       WHERE branch_id=? AND DATE(created_at)=DATE('now')
         AND status IN ('COMPLETED','SERVING','SKIPPED','NO_SHOW','CANCELLED')
         AND queued_at IS NOT NULL`
    )
    .get(branchId);
  const service = db
    .prepare(
      `SELECT AVG((julianday(completed_at)-julianday(started_at))*1440) avg_service
       FROM queue_entries
       WHERE branch_id=? AND DATE(created_at)=DATE('now')
         AND status='COMPLETED' AND started_at IS NOT NULL AND completed_at IS NOT NULL`
    )
    .get(branchId);
  const hourly = db
    .prepare(
      `SELECT CAST(strftime('%H', queued_at) AS INTEGER) hour, COUNT(*) n
       FROM queue_entries
       WHERE branch_id=? AND DATE(created_at)=DATE('now')
       GROUP BY hour ORDER BY hour`
    )
    .all(branchId);
  const peaks = Array.from({ length: 24 }, (_, h) => ({
    hour: h,
    count: hourly.find((x) => x.hour === h)?.n || 0,
  }));
  return {
    ...base,
    average_wait_min: wait?.avg_wait ? Math.round(wait.avg_wait) : null,
    longest_wait_min: wait?.max_wait ? Math.round(wait.max_wait) : null,
    average_service_min: service?.avg_service ? Math.round(service.avg_service) : null,
    peak_hours: peaks,
  };
}

function nowServing(branchId) {
  return db
    .prepare(
      `SELECT q.id,q.ticket_number,q.status,q.station_id,s.name service_name,
              c.name customer_name,c.phone,st.name station_name,sf.name served_by_name
       FROM queue_entries q
       JOIN services s ON s.id=q.service_id
       JOIN customers c ON c.id=q.customer_id
       LEFT JOIN service_stations st ON st.id=q.station_id
       LEFT JOIN staff sf ON sf.id=q.served_by
       WHERE q.branch_id=? AND q.status='SERVING'
       ORDER BY q.started_at,q.id`
    )
    .all(branchId);
}

function nextWaiting(branchId) {
  return db
    .prepare(
      `SELECT q.id,q.ticket_number,q.status,q.service_id,s.name service_name,
              c.name customer_name,c.phone,q.people_ahead
       FROM queue_entries q
       JOIN services s ON s.id=q.service_id
       JOIN customers c ON c.id=q.customer_id
       WHERE q.branch_id=? AND q.status='WAITING'
       ORDER BY q.queued_at,q.id LIMIT 1`
    )
    .get(branchId);
}

function search(branchId, query, { showPhone = true } = {}) {
  const qstr = String(query || '').trim();
  if (!qstr) return [];
  const phone = qstr.replace(/[^0-9+]/g, '');
  const rows = db
    .prepare(
      `SELECT q.id,q.ticket_number,q.status,q.people_ahead,q.estimated_wait_low,q.estimated_wait_high,
              s.name service_name,c.name customer_name,c.phone,st.name station_name
       FROM queue_entries q
       JOIN services s ON s.id=q.service_id
       JOIN customers c ON c.id=q.customer_id
       LEFT JOIN service_stations st ON st.id=q.station_id
       WHERE q.branch_id=? AND DATE(q.created_at)=DATE('now')
         AND (upper(q.ticket_number) LIKE upper(?) OR c.phone LIKE ?)
       ORDER BY q.id DESC LIMIT 25`
    )
    .all(branchId, `%${qstr}%`, phone ? `%${phone}%` : `%${qstr}%`);
  if (showPhone) return rows;
  return rows.map(({ phone: p, ...rest }) => ({ ...rest, phone: null }));
}

function changeService(id, serviceId, { by = null } = {}) {
  const e = get(id);
  if (!e) throw Error('Queue entry not found');
  if (!['WAITING', 'CALLED', 'ARRIVED'].includes(e.status)) {
    throw Error('Can only change service before serving starts');
  }
  const s = db
    .prepare('SELECT id FROM services WHERE id=? AND branch_id=? AND is_active=1')
    .get(serviceId, e.branch_id);
  if (!s) throw Error('Service not found');
  const r = db
    .prepare('UPDATE queue_entries SET service_id=? WHERE id=? AND status=?')
    .run(serviceId, id, e.status);
  if (r.changes !== 1) throw Error('Queue changed; refresh and try again');
  log(id, 'SERVICE_CHANGED', by, null, { from: e.service_id, to: serviceId });
  recalc(e.branch_id);
  events.emit('changed', e.branch_id);
  return publicEntry(get(id));
}

function tick() {
  try {
    for (const b of db
      .prepare(
        "SELECT DISTINCT branch_id FROM queue_entries WHERE status IN ('WAITING','CALLED','ARRIVED','SERVING')"
      )
      .all()) {
      recalc(b.branch_id);
    }
  } catch (e) {
    if (!/locked/i.test(String(e && e.message))) throw e;
  }
}

module.exports = {
  events,
  canTransition,
  create,
  get,
  publicEntry,
  customerView,
  authorize,
  transition,
  restore,
  active,
  history,
  stats,
  analytics,
  settings,
  nowServing,
  nextWaiting,
  search,
  changeService,
  recalc,
  tick,
  log,
};
