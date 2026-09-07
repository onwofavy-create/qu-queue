const db = require('../db/database');
const { hashToken } = require('../utils/security');
const { NODE_ENV } = require('../config');

function requestOtp(phone, branchId) {
  db.prepare('DELETE FROM otp_codes WHERE phone=? AND branch_id=?').run(phone, branchId);
  db.prepare(
    "DELETE FROM otp_codes WHERE expires_at < datetime('now')"
  ).run();
  const recent = db
    .prepare(
      `SELECT COUNT(*) n FROM otp_codes
       WHERE phone=? AND created_at >= datetime('now','-10 minutes')`
    )
    .get(phone)?.n || 0;
  if (recent >= 5) throw Error('Too many OTP requests. Try again later.');

  const code = String(Math.floor(100000 + Math.random() * 900000));
  db.prepare(
    `INSERT INTO otp_codes(phone,branch_id,code_hash,expires_at)
     VALUES(?,?,?,datetime('now','+10 minutes'))`
  ).run(phone, branchId, hashToken(code));

  // V1: no SMS provider yet — return demo code in non-production for testing.
  const payload = { ok: true, expires_in_seconds: 600 };
  if (NODE_ENV !== 'production') {
    payload.demo_code = code;
    console.log(`[OTP] ${phone} branch=${branchId} code=${code}`);
  }
  return payload;
}

function verifyOtp(phone, branchId, code) {
  const row = db
    .prepare(
      `SELECT * FROM otp_codes
       WHERE phone=? AND branch_id=? AND expires_at >= datetime('now')
       ORDER BY id DESC LIMIT 1`
    )
    .get(phone, branchId);
  if (!row) throw Error('OTP expired or not found. Request a new code.');
  if (row.attempts >= 5) throw Error('Too many incorrect OTP attempts.');
  if (hashToken(String(code || '')) !== row.code_hash) {
    db.prepare('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?').run(row.id);
    throw Error('Invalid OTP code');
  }
  db.prepare('DELETE FROM otp_codes WHERE phone=? AND branch_id=?').run(phone, branchId);
  return true;
}

module.exports = { requestOtp, verifyOtp };
