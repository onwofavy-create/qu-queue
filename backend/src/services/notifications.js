const db = require('../db/database');
const q = require('./queue');

function parseThresholds(set) {
  try {
    const arr = JSON.parse(set.notify_thresholds || '[5,2,0]');
    if (Array.isArray(arr) && arr.length) {
      return [...new Set(arr.map(Number).filter((n) => n >= 0))].sort((a, b) => b - a);
    }
  } catch {}
  const soon = Number(set.return_soon_threshold ?? 5);
  const now = Number(set.return_now_threshold ?? 2);
  return [...new Set([soon, now, 0])].sort((a, b) => b - a);
}

function messageFor(level, entry) {
  if (level === 0 || entry.status === 'CALLED' || entry.status === 'SERVING') {
    return {
      title: `${entry.ticket_number} — Your turn is now`,
      body: 'Please report to the service desk.',
      level: 0,
    };
  }
  if (level <= (entry.return_now_threshold ?? 2)) {
    return {
      title: `${entry.ticket_number} — Your turn is approaching`,
      body: `${entry.people_ahead} people ahead. Estimated wait ${entry.estimated_wait_low}–${entry.estimated_wait_high} min.`,
      level,
    };
  }
  return {
    title: `${entry.ticket_number} — Start returning`,
    body: `${entry.people_ahead} people ahead. Estimated wait ${entry.estimated_wait_low}–${entry.estimated_wait_high} min.`,
    level,
  };
}

function emitForEntry(entry, set, level) {
  const msg = messageFor(level, {
    ...entry,
    return_now_threshold: set.return_now_threshold,
  });
  const channels = [];
  if (set.notify_in_app) channels.push('in_app');
  if (set.notify_push) channels.push('push');
  if (set.notify_sms) channels.push('sms');
  if (!channels.length) channels.push('in_app');

  for (const channel of channels) {
    db.prepare(
      'INSERT INTO notifications(entry_id,channel,level,title,body) VALUES(?,?,?,?,?)'
    ).run(entry.id, channel, level, msg.title, msg.body);
  }
  db.prepare('UPDATE queue_entries SET last_notify_level=? WHERE id=?').run(level, entry.id);
  return msg;
}

function evaluateBranch(branchId) {
  const set = q.settings(branchId);
  const thresholds = parseThresholds(set);
  const rows = db
    .prepare(
      `SELECT q.*, s.return_soon_threshold, s.return_now_threshold
       FROM queue_entries q
       JOIN queue_settings s ON s.branch_id=q.branch_id
       WHERE q.branch_id=? AND q.status IN ('WAITING','CALLED','ARRIVED','SERVING')`
    )
    .all(branchId);

  const fired = [];
  for (const e of rows) {
    let target = null;
    if (e.status === 'CALLED' || e.status === 'SERVING') target = 0;
    else {
      for (const t of thresholds) {
        if (e.people_ahead <= t) {
          target = t;
          break;
        }
      }
    }
    if (target === null) continue;
    const last = e.last_notify_level;
    // Fire when crossing into a more urgent (lower) level, or first time.
    if (last !== null && last !== undefined && Number(last) <= Number(target)) continue;
    fired.push(emitForEntry(e, set, target));
  }
  return fired;
}

function recentForEntry(entryId, limit = 10) {
  return db
    .prepare(
      `SELECT id,channel,level,title,body,created_at
       FROM notifications WHERE entry_id=? ORDER BY id DESC LIMIT ?`
    )
    .all(entryId, limit);
}

function start() {
  const run = () => {
    for (const b of db.prepare('SELECT id FROM branches WHERE is_active=1').all()) {
      try {
        evaluateBranch(b.id);
      } catch (e) {
        console.error('notification evaluate', e.message);
      }
    }
  };
  run();
  return setInterval(run, 8000).unref();
}

module.exports = { evaluateBranch, recentForEntry, start, parseThresholds };
