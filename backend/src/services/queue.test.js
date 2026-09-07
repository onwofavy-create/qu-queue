const test=require('node:test');const assert=require('node:assert/strict');const db=require('../db/database');const q=require('./queue');
test('queue state machine rejects impossible transitions',()=>{assert.equal(q.canTransition('WAITING','SERVING'),false);assert.equal(q.canTransition('WAITING','CALLED'),true);assert.equal(q.canTransition('SERVING','COMPLETED'),true);assert.equal(q.canTransition('COMPLETED','WAITING'),false)});
test('queue state machine supports return to queue after no-show',()=>{assert.equal(q.canTransition('NO_SHOW','WAITING'),true);assert.equal(q.canTransition('CANCELLED','WAITING'),true)});
test('requeue clears prior call state and notification level',()=>{
  const branchCode=`T${Date.now()}${Math.random().toString(16).slice(2,6)}`.slice(0,12).toUpperCase();
  const org = db.prepare('INSERT INTO organizations(name,email,password_hash,category) VALUES(?,?,?,?)').run(`Temp Org ${Date.now()}`,`owner-${Date.now()}@example.com`,'hash','Demo').lastInsertRowid;
  const branch = db.prepare('INSERT INTO branches(org_id,name,code) VALUES(?,?,?)').run(org,'Temp Queue', branchCode).lastInsertRowid;
  db.prepare('INSERT INTO queue_settings(branch_id) VALUES(?)').run(branch);
  const service = db.prepare('INSERT INTO services(branch_id,name,estimated_duration) VALUES(?,?,?)').run(branch,'Temp Service',10).lastInsertRowid;
  const station = db.prepare('INSERT INTO service_stations(branch_id,name,service_id) VALUES(?,?,?)').run(branch,'Temp Station',service).lastInsertRowid;
  const staffMember = db.prepare('INSERT INTO staff(org_id,branch_id,station_id,name,email,password_hash,role) VALUES(?,?,?,?,?,?,?)').run(org,branch,station,'Queue Staff',`staff-${Date.now()}@example.com`,'hash','receptionist').lastInsertRowid;
  const customer = db.prepare('INSERT INTO customers(phone,name) VALUES(?,?)').run(`+1555${Date.now()}`,'Temp Customer').lastInsertRowid;
  const entry = db.prepare('INSERT INTO queue_entries(branch_id,service_id,customer_id,ticket_number,access_token_hash,status,station_id,served_by,called_at,arrived_at,started_at,completed_at,last_notify_level) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(branch,service,customer,'QTEST',`hash-${Date.now()}`,'CALLED',station,staffMember,'2026-01-01 00:00:00','2026-01-01 00:01:00','2026-01-01 00:02:00','2026-01-01 00:03:00',2).lastInsertRowid;
  const updated = q.transition(entry,'WAITING',{by:staffMember,reason:'Retry'});
  assert.equal(updated.status,'WAITING');
  const row = db.prepare('SELECT station_id,served_by,called_at,arrived_at,started_at,completed_at,last_notify_level FROM queue_entries WHERE id=?').get(entry);
  assert.equal(row.station_id,null);assert.equal(row.served_by,null);assert.equal(row.called_at,null);assert.equal(row.arrived_at,null);assert.equal(row.started_at,null);assert.equal(row.completed_at,null);assert.equal(row.last_notify_level,null);
  db.prepare('DELETE FROM queue_events WHERE entry_id=?').run(entry);db.prepare('DELETE FROM queue_entries WHERE id=?').run(entry);db.prepare('DELETE FROM customers WHERE id=?').run(customer);db.prepare('DELETE FROM service_stations WHERE id=?').run(station);db.prepare('DELETE FROM staff WHERE id=?').run(staffMember);db.prepare('DELETE FROM services WHERE id=?').run(service);db.prepare('DELETE FROM queue_settings WHERE branch_id=?').run(branch);db.prepare('DELETE FROM branches WHERE id=?').run(branch);db.prepare('DELETE FROM organizations WHERE id=?').run(org);
});
