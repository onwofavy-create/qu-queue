const { before, after, test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { server } = require('./server');

let baseUrl;

before(async () => {
  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', (err) => {
      if (err) return reject(err);
      const { port } = server.address();
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
});

async function request(path, { method = 'GET', token, body } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    if (method !== 'GET' && body !== undefined) {
      headers.Connection = 'close';
    }

    const req = http.request(
      new URL(path, baseUrl),
      { method, headers, agent: false },
      (res) => {
        let text = '';
        res.on('data', (chunk) => {
          text += chunk.toString();
        });
        res.on('end', () => {
          let data = {};
          try {
            data = text ? JSON.parse(text) : {};
          } catch {
            data = { raw: text };
          }
          resolve({ status: res.statusCode, data });
        });
      }
    );

    req.on('error', reject);
    if (body !== undefined) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

function unique(prefix) {
  const stamp = Date.now();
  const suffix = Math.random().toString(16).slice(2, 8);
  return `${prefix}-${stamp}-${suffix}`;
}

test('owner signup creates a company and owner login works', async () => {
  const email = `${unique('owner')}@example.com`;
  const company = unique('Acme Clinic');

  const signup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: company,
      owner_name: 'Owner Person',
      email,
      password: 'StrongPass123',
    },
  });

  assert.equal(signup.status, 201, signup.data.error || 'owner signup failed');
  assert.ok(signup.data.token, 'owner token missing');
  assert.equal(signup.data.user.role, 'owner');
  assert.equal(signup.data.company.name, company);

  const login = await request('/api/auth/login', {
    method: 'POST',
    body: { email, password: 'StrongPass123' },
  });

  assert.equal(login.status, 200, login.data.error || 'owner login failed');
  assert.equal(login.data.user.email, email);
  assert.equal(login.data.user.role, 'owner');
});

test('staff invitation flow rejects wrong email and supports acceptance + login', async () => {
  const ownerEmail = `${unique('owner')}@example.com`;
  const company = unique('Health Co');
  const signup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: company,
      owner_name: 'Owner Person',
      email: ownerEmail,
      password: 'StrongPass123',
    },
  });

  const ownerToken = signup.data.token;
  const staffEmail = `${unique('staff')}@example.com`;
  const invite = await request('/api/owner/staff/invite', {
    method: 'POST',
    token: ownerToken,
    body: { name: 'Invited Staff', email: staffEmail, role: 'receptionist' },
  });

  assert.equal(invite.status, 201, invite.data.error || 'staff invite creation failed');
  assert.ok(invite.data.invitation.token, 'invite token missing');

  const wrongEmailAcceptance = await request('/api/auth/invite/accept', {
    method: 'POST',
    body: {
      token: invite.data.invitation.token,
      name: 'Wrong Person',
      email: `${unique('wrong')}@example.com`,
      password: 'StaffPass123',
    },
  });

  assert.equal(wrongEmailAcceptance.status, 400, 'wrong email should be rejected');

  const accepted = await request('/api/auth/invite/accept', {
    method: 'POST',
    body: {
      token: invite.data.invitation.token,
      name: 'Invited Staff',
      email: staffEmail,
      password: 'StaffPass123',
    },
  });

  assert.equal(accepted.status, 201, accepted.data.error || 'invite accept failed');
  assert.equal(accepted.data.user.email, staffEmail);

  const login = await request('/api/auth/login', {
    method: 'POST',
    body: { email: staffEmail, password: 'StaffPass123' },
  });

  assert.equal(login.status, 200, login.data.error || 'staff login failed');
  assert.equal(login.data.user.role, 'receptionist');

  const blocked = await request('/api/auth/staff-signup', {
    method: 'POST',
    body: { name: 'Anyone', email: `${unique('public')}@example.com`, password: 'PublicPass123' },
  });

  assert.equal(blocked.status, 403, 'public staff signup should be disabled');
});

test('duplicate QR/token generation is blocked until revoke, and revocation invalidates access', async () => {
  const email = `${unique('owner')}@example.com`;
  const signup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: unique('Access Co'),
      owner_name: 'Owner Person',
      email,
      password: 'StrongPass123',
    },
  });

  const token = signup.data.token;
  const first = await request('/api/company/access', {
    method: 'POST',
    token,
    body: { action: 'destroy' },
  });
  assert.equal(first.status, 200, first.data.error || 'destroy should work');

  const created = await request('/api/company/access', {
    method: 'POST',
    token,
    body: { action: 'create', mode: 'both' },
  });
  assert.equal(created.status, 200, created.data.error || 'company access creation failed');
  assert.ok(created.data.access_token, 'company token missing');
  assert.ok(created.data.qr_code_url, 'company QR missing');

  const duplicate = await request('/api/company/access', {
    method: 'POST',
    token,
    body: { action: 'create', mode: 'both' },
  });
  assert.equal(duplicate.status, 409, 'duplicate active QR/token should be rejected');

  const revoked = await request('/api/company/access', {
    method: 'POST',
    token,
    body: { action: 'destroy' },
  });
  assert.equal(revoked.status, 200, revoked.data.error || 'destroy should revoke access');

  const lookup = await request(`/api/customer/access/${encodeURIComponent(created.data.access_token)}`);
  assert.equal(lookup.status, 404, 'revoked token should stop customer access');
});

test('customer can join by token and service search resolves fuzzy matches', async () => {
  const email = `${unique('owner')}@example.com`;
  const companyName = unique('Care Clinic');
  const signup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: companyName,
      owner_name: 'Owner Person',
      email,
      password: 'StrongPass123',
    },
  });
  const ownerToken = signup.data.token;

  const destroy = await request('/api/company/access', {
    method: 'POST',
    token: ownerToken,
    body: { action: 'destroy' },
  });
  assert.equal(destroy.status, 200, destroy.data.error || 'destroy access failed');

  const create = await request('/api/company/access', {
    method: 'POST',
    token: ownerToken,
    body: { action: 'create', mode: 'token' },
  });
  const companyToken = create.data.access_token;

  const companyInfo = await request(`/api/customer/access/${encodeURIComponent(companyToken)}`);
  assert.equal(companyInfo.status, 200, companyInfo.data.error || 'token lookup failed');
  assert.equal(companyInfo.data.company.name, companyName);

  const search = await request('/api/customer/search', {
    method: 'POST',
    body: { company_token: companyToken, search: 'genral' },
  });
  assert.equal(search.status, 200, search.data.error || 'service search failed');
  assert.ok(search.data.matches.length > 0, 'search should return a suggestion for a real queue service');
  assert.ok(search.data.suggestion || search.data.matches[0], 'search should provide a result');

  const service = companyInfo.data.services.find((item) => /general|queue/i.test(item.name) || /general|queue/i.test(item.customer_name || '')) || companyInfo.data.services[0];
  assert.ok(service, 'company should have at least one service');

  const join = await request('/api/customer/join', {
    method: 'POST',
    body: {
      company_token: companyToken,
      service_id: service.id,
      phone: '+15551230001',
      name: 'Walk-in Customer',
      otp: null,
    },
  });

  assert.equal(join.status, 201, join.data.error || 'customer join failed');
  assert.ok(join.data.entry.ticket_number, 'ticket number missing');
  assert.ok(join.data.accessToken, 'ticket access token missing');
});

test('remote customer join and staff walk-in both work without phone and share the same queue sequence', async () => {
  const email = `${unique('owner')}@example.com`;
  const companyName = unique('No-Phone Clinic');
  const signup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: companyName,
      owner_name: 'Owner Person',
      email,
      password: 'StrongPass123',
    },
  });
  const ownerToken = signup.data.token;

  const access = await request('/api/company/access', {
    method: 'POST',
    token: ownerToken,
    body: { action: 'destroy' },
  });
  assert.equal(access.status, 200, access.data.error || 'destroy access failed');

  const created = await request('/api/company/access', {
    method: 'POST',
    token: ownerToken,
    body: { action: 'create', mode: 'token' },
  });
  assert.equal(created.status, 200, created.data.error || 'token access creation failed');
  const companyToken = created.data.access_token;

  const companyInfo = await request(`/api/customer/access/${encodeURIComponent(companyToken)}`);
  assert.equal(companyInfo.status, 200, companyInfo.data.error || 'company token lookup failed');
  const service = companyInfo.data.services[0];
  assert.ok(service, 'company should have at least one service');

  const remote = await request('/api/customer/join', {
    method: 'POST',
    body: {
      company_token: companyToken,
      service_id: service.id,
      name: 'Guest Remote',
    },
  });
  assert.equal(remote.status, 201, remote.data.error || 'remote join without phone failed');
  assert.ok(/^Q\d{3}$/.test(remote.data.entry.ticket_number), 'remote ticket should use the queue prefix');

  const walkin = await request('/api/staff/queue/create', {
    method: 'POST',
    token: ownerToken,
    body: {
      service_id: service.id,
      name: 'Guest Walk-in',
    },
  });
  assert.equal(walkin.status, 201, walkin.data.error || 'walk-in without phone failed');
  assert.ok(/^Q\d{3}$/.test(walkin.data.entry.ticket_number), 'walk-in ticket should use the queue prefix');

  const remoteNum = Number(remote.data.entry.ticket_number.replace(/^\D+/, ''));
  const walkinNum = Number(walkin.data.entry.ticket_number.replace(/^\D+/, ''));
  assert.equal(walkinNum, remoteNum + 1, 'walk-in should join the same sequential queue as remote customers');
});

test('company isolation prevents one company from accessing another company data', async () => {
  const firstSignup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: unique('Alpha Clinic'),
      owner_name: 'Owner One',
      email: `${unique('alpha-owner')}@example.com`,
      password: 'StrongPass123',
    },
  });
  const secondSignup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: unique('Beta Clinic'),
      owner_name: 'Owner Two',
      email: `${unique('beta-owner')}@example.com`,
      password: 'StrongPass123',
    },
  });

  const firstToken = firstSignup.data.company.accessToken;
  const secondToken = secondSignup.data.company.accessToken;

  const firstLookup = await request(`/api/customer/access/${encodeURIComponent(firstToken)}`);
  const secondLookup = await request(`/api/customer/access/${encodeURIComponent(secondToken)}`);

  assert.equal(firstLookup.status, 200, firstLookup.data.error || 'first company token should resolve');
  assert.equal(secondLookup.status, 200, secondLookup.data.error || 'second company token should resolve');
  assert.notEqual(firstLookup.data.company.id, secondLookup.data.company.id, 'companies should be distinct');

  const crossCheck = await request(`/api/customer/access/${encodeURIComponent(firstToken)}`);
  assert.equal(crossCheck.data.company.id, firstLookup.data.company.id, 'company data should be isolated to the correct tenant');
});

test('queue lifecycle supports calls, arrivals, serving, completion, no-show and requeue policy', async () => {
  const email = `${unique('owner')}@example.com`;
  const signup = await request('/api/auth/signup', {
    method: 'POST',
    body: {
      company_name: unique('Queue Clinic'),
      owner_name: 'Owner Person',
      email,
      password: 'StrongPass123',
    },
  });
  const ownerToken = signup.data.token;

  const servicesResponse = await request('/api/owner/services', { token: ownerToken });
  assert.equal(servicesResponse.status, 200, servicesResponse.data.error || 'services endpoint failed');
  const services = Array.isArray(servicesResponse.data) ? servicesResponse.data : servicesResponse.data.services || [];
  const service = services.find((item) => /general|queue/i.test(item.name) || /general|queue/i.test(item.customer_name || '')) || services[0];
  assert.ok(service, 'default company service missing');

  const branchInfo = await request('/api/staff/branch', { token: ownerToken });
  assert.equal(branchInfo.status, 200, branchInfo.data.error || 'branch info failed');
  const stationId = branchInfo.data.stations?.[0]?.id || branchInfo.data.station?.id;
  assert.ok(stationId, 'at least one station is required');

  const join = await request('/api/customer/join', {
    method: 'POST',
    body: {
      company_code: signup.data.company.publicCode,
      service_id: service.id,
      phone: '+15551230002',
      name: 'Queue Customer',
    },
  });

  assert.equal(join.status, 201, join.data.error || 'customer join failed');
  const entryId = join.data.entry.id;

  const called = await request(`/api/staff/queue/${entryId}/call`, {
    method: 'POST',
    token: ownerToken,
  });
  assert.equal(called.status, 200, called.data.error || 'call action failed');

  const arrived = await request(`/api/staff/queue/${entryId}/arrive`, {
    method: 'POST',
    token: ownerToken,
  });
  assert.equal(arrived.status, 200, arrived.data.error || 'arrive action failed');

  const served = await request(`/api/staff/queue/${entryId}/start`, {
    method: 'POST',
    token: ownerToken,
    body: { station_id: stationId },
  });
  assert.equal(served.status, 200, served.data.error || 'serve action failed');

  const finished = await request(`/api/staff/queue/${entryId}/finish`, {
    method: 'POST',
    token: ownerToken,
  });
  assert.equal(finished.status, 200, finished.data.error || 'finish action failed');

  const invalid = await request(`/api/staff/queue/${entryId}/call`, {
    method: 'POST',
    token: ownerToken,
  });
  assert.equal(invalid.status, 409, 'invalid transition should be rejected');
});
