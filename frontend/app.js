const $ = (s, root = document) => root.querySelector(s);

const api = async (path, opt = {}) => {
  const headers = { 'content-type': 'application/json', ...(opt.headers || {}) };
  const r = await fetch(path, { ...opt, headers });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw Error(d.error || 'Request failed');
  return d;
};

const token = () => '';
const authHeaders = () => ({});
const esc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (m) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])
  );

function requireAuth() {
  return true;
}

async function signOut() {
  await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
  location.href = '/login.html';
}

function rememberedAccounts() {
  try {
    const value = JSON.parse(localStorage.getItem('qu_accounts') || '[]');
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function saveRememberedAccount(account) {
  const accounts = rememberedAccounts().filter((item) => item.email !== account.email);
  accounts.unshift(account);
  localStorage.setItem('qu_accounts', JSON.stringify(accounts.slice(0, 8)));
}

function renderAccountSwitcher(me) {
  const root = $('#accountSwitcher');
  if (!root) return;
  const accounts = rememberedAccounts();
  root.innerHTML = `
    <details class="account-menu">
      <summary>Account</summary>
      <div class="account-menu-panel">
        <strong>Current account</strong>
        <span>${esc(me.name)} · ${esc(me.email)}</span>
        <label>Switch account
          <select id="switchAccount">
            <option value="">Choose remembered account</option>
            ${accounts.filter((item) => item.email !== me.email).map((item) =>
              `<option value="${esc(item.email)}">${esc(item.email)} · ${esc(item.company || 'QueueOS')}</option>`
            ).join('')}
          </select>
        </label>
        <button type="button" class="button sub small" id="addAccount">Add account</button>
        <button type="button" class="button sub small" id="removeAccount">Remove this account</button>
      </div>
    </details>`;
  $('#switchAccount').onchange = (event) => {
    if (!event.target.value) return;
    sessionStorage.setItem('qu_login_email', event.target.value);
    location.href = '/login.html';
  };
  $('#addAccount').onclick = () => {
    sessionStorage.setItem('qu_return_after_login', location.pathname);
    location.href = '/login.html';
  };
  $('#removeAccount').onclick = async () => {
    const remaining = rememberedAccounts().filter((item) => item.email !== me.email);
    localStorage.setItem('qu_accounts', JSON.stringify(remaining));
    await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    location.href = '/login.html';
  };
}

function saveTicket(payload) {
  sessionStorage.setItem('qu_ticket', JSON.stringify(payload));
  if (payload?.entry?.id && payload?.accessToken) {
    localStorage.setItem(
      `qu_ticket_${payload.entry.id}`,
      JSON.stringify({
        id: payload.entry.id,
        accessToken: payload.accessToken,
        ticket: payload.entry.ticket_number,
      })
    );
  }
}

function loadTicketAccess(id) {
  const fromSession = JSON.parse(sessionStorage.getItem('qu_ticket') || 'null');
  if (fromSession?.entry?.id == id && fromSession?.accessToken) {
    return fromSession.accessToken;
  }
  const fromLocal = JSON.parse(localStorage.getItem(`qu_ticket_${id}`) || 'null');
  if (fromLocal?.accessToken) return fromLocal.accessToken;
  return new URLSearchParams(location.search).get('t') || '';
}

function statusClass(status) {
  return String(status || '').toLowerCase().replace(/_/g, '-');
}

function pulse(el) {
  if (!el) return;
  el.classList.remove('pulse');
  void el.offsetWidth;
  el.classList.add('pulse');
}

function setLive(el, value) {
  if (!el) return;
  const next = String(value);
  if (el.textContent !== next) {
    el.textContent = next;
    pulse(el);
  }
}

async function staff() {
  if (!requireAuth()) return;
  const meAuth = await api('/api/auth/me', { headers: authHeaders() }).catch(() => {
    location.href = '/login.html';
  });
  if (!meAuth) return;

  if (meAuth.role === 'owner' || meAuth.role === 'admin') {
    $('#ownerLink')?.classList.remove('hidden');
  }

  let data = await api('/api/staff/company', { headers: authHeaders() }).catch(() => api('/api/staff/branch', { headers: authHeaders() }));
  saveRememberedAccount({
    email: meAuth.email,
    name: meAuth.name,
    role: meAuth.role,
    company: data.company?.name,
  });
  renderAccountSwitcher(meAuth);
  let historyFilter = 'ALL';
  let selectedStation = data.me?.station_id
    ? String(data.me.station_id)
    : data.stations.length === 1
      ? String(data.stations[0].id)
      : '';

  const stationSelect = $('#stationSelect');

  const fillStations = () => {
    const locked = !!data.settings?.lock_staff_to_station && data.me?.station_id;
    const wrap = $('#stationPickWrap');
    const note = $('#stationLockedNote');
    if (locked) {
      wrap?.classList.add('hidden');
      note?.classList.remove('hidden');
      if (note) {
        note.textContent = `Serving from ${data.me.station_name || 'your assigned station'} only.`;
      }
      selectedStation = String(data.me.station_id);
      return;
    }
    note?.classList.add('hidden');
    wrap?.classList.remove('hidden');
    if (!stationSelect) return;
    stationSelect.innerHTML =
      `<option value="">Select station</option>` +
      data.stations
        .map(
          (s) =>
            `<option value="${s.id}" ${String(s.id) === selectedStation ? 'selected' : ''}>${esc(s.name)}</option>`
        )
        .join('');
  };

  const fillServices = () => {
    const serviceSelect = $('#walkinService');
    if (!serviceSelect) return;
    serviceSelect.innerHTML = data.services
      .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
      .join('');
  };

  const renderHistory = () => {
    const el = $('#history');
    if (!el) return;
    const set = data.settings || {};
    const rows = (data.history || []).filter(
      (x) => historyFilter === 'ALL' || x.status === historyFilter
    );
    el.innerHTML = rows.length
      ? rows
          .map(
            (x) => `<article class="qrow compact">
          <div class="qnum">${esc(x.ticket_number)}</div>
          <div class="qinfo">
            <strong>${esc(x.customer_name || 'Customer')}</strong>
            <span>${esc(x.service_name)}${x.handled_by ? ` Â· by ${esc(x.handled_by)}` : ''}${x.station_name ? ` Â· ${esc(x.station_name)}` : ''}</span>
          </div>
          <div class="qstatus ${statusClass(x.status)}">${esc(x.status)}</div>
          <div class="qactions">${
            set.staff_can_restore &&
            ['SKIPPED', 'NO_SHOW', 'CANCELLED'].includes(x.status)
              ? `<button class="sub" data-act="restore" data-id="${x.id}">Restore</button>`
              : ''
          }</div>
        </article>`
          )
          .join('')
      : '<div class="empty">No outcomes in this filter yet.</div>';
  };

  const renderPerf = () => {
    const el = $('#staffPerf');
    if (!el) return;
    const staff = data.stats?.staff || [];
    el.innerHTML = staff.length
      ? `<div class="perftable">
          <div class="perfhead"><span>Staff</span><span>Done</span><span>Skip</span><span>No-show</span><span>Cancel</span></div>
          ${staff
            .map(
              (s) => `<div class="perfrow">
            <span>${esc(s.name)}</span>
            <span>${s.completed}</span>
            <span>${s.skipped}</span>
            <span>${s.no_show}</span>
            <span>${s.cancelled}</span>
          </div>`
            )
            .join('')}
        </div>`
      : '<div class="empty">No staff activity recorded yet today.</div>';
  };

  const render = () => {
    const q = data.queue;
    const set = data.settings || {};
    const st = data.stats || {};

    const company = data.company || data.branch || {};
    $('#companyName').textContent = company.name || data.branch?.name || 'Company';
    $('#staffName').textContent = data.me?.name || meAuth.name;
    $('#staffStation').textContent = data.me?.station_name
      ? `Â· ${data.me.station_name}`
      : 'Â· No station assigned';
    $('#staffHint').textContent = data.me?.station_name
      ? `Signed in as ${data.me.name} at ${data.me.station_name}`
      : 'Ask the owner to assign this account to a station.';

    $('#waitingCount').textContent = q.filter((x) => x.status === 'WAITING').length;
    $('#servingCount').textContent = q.filter((x) => x.status === 'SERVING').length;
    $('#completedCount').textContent = st.done || 0;
    $('#skippedCount').textContent = st.skipped || 0;
    $('#noshowCount').textContent = st.no_show || 0;
    $('#cancelledCount').textContent = st.cancelled || 0;

    const walkin = $('#walkinCard');
    if (walkin) walkin.classList.toggle('hidden', !set.allow_walkins);

    fillStations();
    fillServices();

    $('#queue').innerHTML = q.length
      ? q
          .map((x) => {
            const actions = [];
            if (x.status === 'WAITING') {
              actions.push(`<button data-act="call" data-id="${x.id}">Call</button>`);
            }
            if (x.status === 'CALLED') {
              actions.push(
                `<button data-act="arrive" data-id="${x.id}">Arrived</button>`
              );
              actions.push(
                `<button class="sub" data-act="noshow" data-id="${x.id}">No-show</button>`
              );
            }
            if (x.status === 'ARRIVED') {
              actions.push(
                `<button data-act="start" data-id="${x.id}">Start</button>`
              );
            }
            if (x.status === 'SERVING') {
              actions.push(
                `<button data-act="finish" data-id="${x.id}">Finish</button>`
              );
            }
            if (['WAITING', 'CALLED', 'ARRIVED'].includes(x.status)) {
              if (set.staff_can_skip) {
                actions.push(
                  `<button class="sub" data-act="skip" data-id="${x.id}">Skip</button>`
                );
              }
              if (set.staff_can_cancel) {
                actions.push(
                  `<button class="sub" data-act="cancel" data-id="${x.id}">Cancel</button>`
                );
              }
            }
            const phoneBit =
              set.show_customer_phone && x.phone ? ` Â· ${esc(x.phone)}` : '';
            return `<article class="qrow">
          <div class="qnum">${esc(x.ticket_number)}</div>
          <div class="qinfo"><strong>${esc(x.customer_name || 'Customer')}</strong><span>${esc(x.service_name)} Â· #${x.position || 'â€”'} Â· ${x.people_ahead} ahead Â· ~${x.estimated_wait_low}â€“${x.estimated_wait_high} min${phoneBit}</span></div>
          <div class="qstatus ${statusClass(x.status)}">${esc(x.status)}</div>
          <div class="qactions">${actions.join('')}</div>
        </article>`;
          })
          .join('')
      : '<div class="empty">No one is currently waiting.</div>';

    renderHistory();
    renderPerf();
  };

  const refresh = async () => {
    data = await api('/api/staff/company', { headers: authHeaders() }).catch(() => api('/api/staff/branch', { headers: authHeaders() }));
    render();
  };

  window.act = async (id, action) => {
    try {
      const body = {};
      if (action === 'start') {
        const stationId =
          data.settings?.lock_staff_to_station && data.me?.station_id
            ? data.me.station_id
            : stationSelect?.value || selectedStation || data.me?.station_id;
        if (!stationId) {
          alert('This account needs an assigned station before starting service.');
          return;
        }
        body.station_id = Number(stationId);
        selectedStation = String(stationId);
      }
      await api(`/api/staff/queue/${id}/${action}`, {
        method: 'POST',
        headers: { ...authHeaders() },
        body: JSON.stringify(body),
      });
      await refresh();
    } catch (e) {
      alert(e.message);
    }
  };

  $('#queue').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    act(Number(btn.dataset.id), btn.dataset.act);
  });
  $('#history')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    act(Number(btn.dataset.id), btn.dataset.act);
  });

  $('#historyFilter')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-filter]');
    if (!btn) return;
    historyFilter = btn.dataset.filter;
    $('#historyFilter').querySelectorAll('.tab').forEach((t) => {
      t.classList.toggle('active', t === btn);
    });
    renderHistory();
  });

  stationSelect?.addEventListener('change', () => {
    selectedStation = stationSelect.value;
  });

  $('#refresh').onclick = () => refresh().catch((e) => alert(e.message));

  $('#walkinForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const x = Object.fromEntries(new FormData(form));
    try {
      await api('/api/staff/queue/create', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(x),
      });
      form.reset();
      fillServices();
      await refresh();
    } catch (err) {
      alert(err.message);
    }
  });

  render();

  const companyCode = (data.company && (data.company.public_code || data.company.code || data.company.id)) || data.branch?.code || data.branch?.id;
  const es = new EventSource(
    `/api/events?company=${encodeURIComponent(String(companyCode || ''))}`
  );
  es.onmessage = () => refresh().catch(() => {});

  $('#logout').onclick = () => {
    signOut();
  };
}

async function owner() {
  if (!requireAuth()) return;
  const me = await api('/api/auth/me', { headers: authHeaders() }).catch(() => {
    location.href = '/login.html';
  });
  if (!me) return;
  if (me.role !== 'owner' && me.role !== 'admin') {
    location.href = '/staff.html';
    return;
  }

  $('#ownerName').textContent = me.name;
  let selectedId = null;
  let detail = null;
  let activity = [];

  const serviceName = (id) =>
    detail?.services?.find((s) => s.id === id)?.name || 'Any service';

  async function loadBranches() {
    const bs = await api('/api/owner/branches', { headers: authHeaders() });
    if (!bs.length) return;
    selectedId = Number(bs[0].id);
    $('#branches').innerHTML = '';
  }

  function renderDetail() {
    const panel = $('#branchDetail');
    if (!detail) {
      panel.classList.add('hidden');
      return;
    }
    const company = detail.company || detail.branch || {};
    panel.classList.remove('hidden');
    $('#detailTitle').textContent = company.name || detail.branch?.name || 'Company';
    $('#detailCode').textContent = company.public_code || company.code || detail.branch?.code || '';

    const access = detail.access || {};
    const accessMode = access.access_mode || access.mode || 'code';
    const accessSelect = $('#accessModeSelect');
    if (accessSelect) accessSelect.value = accessMode === 'code' ? 'token' : accessMode;

    const accessPreview = $('#accessPreview');
    if (accessPreview) {
      const tokenLabel = access.access_token ? `<div><strong>Access token</strong><p>${esc(access.access_token)}</p></div>` : '<div><strong>Access token</strong><p>Not active</p></div>';
      const qrBlock = access.qr_code_url ? `<div><strong>QR code</strong><img src="${esc(access.qr_code_url)}" alt="QR code" class="qr-image"></div>` : '<div><strong>QR code</strong><p>Not active</p></div>';
      const joinCode = company.public_code || company.code || detail.branch?.code || '';
      const joinBlock = joinCode ? `<div><strong>Join link</strong><p>${esc(`https://queueos.app/join?company=${joinCode}`)}</p></div>` : '';
      accessPreview.classList.toggle('hidden', !(access.access_token || access.qr_code_url));
      accessPreview.innerHTML = `<div class="access-grid">${tokenLabel}${qrBlock}${joinBlock}</div>`;
    }

    const st = detail.stats || {};
    $('#oDone').textContent = st.done || 0;
    $('#oSkip').textContent = st.skipped || 0;
    $('#oNoshow').textContent = st.no_show || 0;
    $('#oCancel').textContent = st.cancelled || 0;
    $('#oWait').textContent = st.counts?.WAITING || 0;
    $('#oServe').textContent = st.counts?.SERVING || 0;

    $('#serviceList').innerHTML = detail.services.length
      ? detail.services
          .map(
            (s) =>
              `<li><strong>${esc(s.customer_name || s.name)}</strong><span>${esc(s.category || 'General')} Â· ~${s.estimated_duration} min</span></li>`
          )
          .join('')
      : '<li class="muted">No services yet.</li>';

    $('#stationList').innerHTML = detail.stations.length
      ? detail.stations
          .map(
            (s) =>
              `<li><strong>${esc(s.name)}</strong><span>${esc(serviceName(s.service_id))}</span></li>`
          )
          .join('')
      : '<li class="muted">No stations yet.</li>';

    const stationOpts =
      `<option value="">No station</option>` +
      detail.stations
        .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
        .join('');

    $('#staffList').innerHTML = detail.staff.length
      ? detail.staff
          .map(
            (s) => `<li class="staffrow">
              <div>
                <strong>${esc(s.name)}</strong>
                <span>${esc(s.email)} Â· ${esc(s.role)}${s.is_active ? '' : ' Â· inactive'}</span>
              </div>
              <select data-staff-station="${s.id}">
                ${detail.stations
                  .map(
                    (stn) =>
                      `<option value="${stn.id}" ${s.station_id === stn.id ? 'selected' : ''}>${esc(stn.name)}</option>`
                  )
                  .join('')}
                <option value="" ${!s.station_id ? 'selected' : ''}>Unassigned</option>
              </select>
            </li>`
          )
          .join('')
      : '<li class="muted">No staff yet.</li>';

    $('#stationService').innerHTML =
      `<option value="">Any service</option>` +
      detail.services
        .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
        .join('');
    $('#staffStation').innerHTML =
      `<option value="">Assign stationâ€¦</option>` +
      detail.stations
        .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
        .join('');

    const set = detail.settings || {};
    $('#gracePeriod').value = set.grace_period_minutes ?? 5;
    $('#noShowAction').value = set.no_show_action || 'skip';
    $('#ticketPrefix').value = set.ticket_prefix || 'Q';
    $('#returnSoon').value = set.return_soon_threshold ?? 5;
    $('#returnNow').value = set.return_now_threshold ?? 2;
    $('#allowCancel').checked = !!set.allow_customer_cancel;
    $('#allowWalkins').checked = !!set.allow_walkins;
    $('#staffSkip').checked = !!set.staff_can_skip;
    $('#staffCancel').checked = !!set.staff_can_cancel;
    $('#staffRestore').checked = !!set.staff_can_restore;
    $('#showPhone').checked = !!set.show_customer_phone;
    $('#lockStation').checked = !!set.lock_staff_to_station;

    const hist = detail.history || [];
    $('#ownerHistory').innerHTML = hist.length
      ? hist
          .map(
            (x) => `<article class="qrow compact">
          <div class="qnum">${esc(x.ticket_number)}</div>
          <div class="qinfo"><strong>${esc(x.customer_name || 'Customer')}</strong><span>${esc(x.service_name)}${x.handled_by ? ` Â· ${esc(x.handled_by)}` : ''}</span></div>
          <div class="qstatus ${statusClass(x.status)}">${esc(x.status)}</div>
        </article>`
          )
          .join('')
      : '<div class="empty">No finished tickets today.</div>';

    $('#ownerActivity').innerHTML = activity.length
      ? activity.map((event) => `<article class="qrow compact">
          <div class="qinfo">
            <strong>${esc(event.action)}${event.ticket_number ? ` · ${esc(event.ticket_number)}` : ''}</strong>
            <span>${esc(event.created_at)}${event.customer_name ? ` · ${esc(event.customer_name)}` : ''}${event.service_name ? ` · ${esc(event.service_name)}` : ''}</span>
          </div>
          <span>${esc(event.staff_name || 'Customer/system')}${event.station_name ? ` · ${esc(event.station_name)}` : ''}${event.reason ? ` · ${esc(event.reason)}` : ''}</span>
        </article>`).join('')
      : '<div class="empty">No activity recorded yet.</div>';
  }

  async function openBranch(id) {
    selectedId = Number(id);
    detail = await api(`/api/owner/branches/${selectedId}`, {
      headers: authHeaders(),
    });
    const audit = await api('/api/owner/audit', { headers: authHeaders() });
    activity = audit.events || [];
    await loadBranches();
    renderDetail();
  }

  await loadBranches();
  if (selectedId) {
    await openBranch(selectedId);
  }
  saveRememberedAccount({
    email: me.email,
    name: me.name,
    role: me.role,
    company: detail?.company?.name,
  });
  renderAccountSwitcher(me);

  $('#staffList')?.addEventListener('change', async (e) => {
    const sel = e.target.closest('[data-staff-station]');
    if (!sel || !selectedId) return;
    try {
      await api(`/api/owner/branches/${selectedId}/staff/${sel.dataset.staffStation}`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          station_id: sel.value === '' ? null : Number(sel.value),
        }),
      });
      await openBranch(selectedId);
    } catch (err) {
      alert(err.message);
    }
  });

  $('#serviceForm').onsubmit = async (e) => {
    e.preventDefault();
    if (!selectedId) return;
    const x = Object.fromEntries(new FormData(e.target));
    x.customer_name = (x.customer_name || x.name || '').trim();
    x.category = (x.category || '').trim();
    x.search_keywords = (x.search_keywords || '').trim();
    x.estimated_duration = Number(x.estimated_duration) || 15;
    try {
      await api(`/api/owner/branches/${selectedId}/services`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(x),
      });
      e.target.reset();
      await openBranch(selectedId);
    } catch (err) {
      alert(err.message);
    }
  };

  $('#quickServiceBtn')?.addEventListener('click', async () => {
    if (!selectedId) return;
    const preset = $('#quickServicePreset').value;
    const templates = {
      general: ['General Queue'],
      diagnostic: ['Blood Test', 'Malaria Test', 'X-Ray', 'Ultrasound', 'Consultation', 'Registration'],
      clinic: ['Consultation', 'Checkup', 'Vaccination', 'Lab Test', 'Pharmacy'],
      custom: [],
    };
    try {
      await api(`/api/owner/branches/${selectedId}/services/quick`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ templates: templates[preset] || [] }),
      });
      await openBranch(selectedId);
    } catch (err) {
      alert(err.message);
    }
  });

  $('#stationForm').onsubmit = async (e) => {
    e.preventDefault();
    if (!selectedId) return;
    const x = Object.fromEntries(new FormData(e.target));
    if (!x.service_id) delete x.service_id;
    try {
      await api(`/api/owner/branches/${selectedId}/stations`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(x),
      });
      e.target.reset();
      await openBranch(selectedId);
    } catch (err) {
      alert(err.message);
    }
  };

  $('#staffForm').onsubmit = async (e) => {
    e.preventDefault();
    if (!selectedId) return;
    const x = Object.fromEntries(new FormData(e.target));
    if (!x.station_id) delete x.station_id;
    try {
      await api(`/api/owner/branches/${selectedId}/staff`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(x),
      });
      e.target.reset();
      await openBranch(selectedId);
    } catch (err) {
      alert(err.message);
    }
  };

  $('#settingsForm').onsubmit = async (e) => {
    e.preventDefault();
    if (!selectedId) return;
    const body = {
      grace_period_minutes: Number($('#gracePeriod').value),
      no_show_action: $('#noShowAction').value,
      ticket_prefix: $('#ticketPrefix').value,
      return_soon_threshold: Number($('#returnSoon').value),
      return_now_threshold: Number($('#returnNow').value),
      allow_customer_cancel: $('#allowCancel').checked,
      allow_walkins: $('#allowWalkins').checked,
      staff_can_skip: $('#staffSkip').checked,
      staff_can_cancel: $('#staffCancel').checked,
      staff_can_restore: $('#staffRestore').checked,
      show_customer_phone: $('#showPhone').checked,
      lock_staff_to_station: $('#lockStation').checked,
    };
    try {
      await api(`/api/owner/branches/${selectedId}/settings`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      await openBranch(selectedId);
      alert('Settings saved');
    } catch (err) {
      alert(err.message);
    }
  };

  $('#createAccessBtn')?.addEventListener('click', async () => {
    if (!selectedId) return;
    try {
      const access = await api(`/api/owner/branches/${selectedId}/access`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ mode: $('#accessModeSelect').value }),
      });
      await openBranch(selectedId);
      const summary = access.access_token ? `Token: ${access.access_token}` : 'QR code created';
      alert(`${summary}. Customers can join using this method.`);
    } catch (err) {
      alert(err.message);
    }
  });

  $('#destroyAccessBtn')?.addEventListener('click', async () => {
    if (!selectedId) return;
    if (!confirm('Destroy the active QR code and access token for this branch?')) return;
    try {
      await api(`/api/owner/branches/${selectedId}/access`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ action: 'destroy' }),
      });
      await openBranch(selectedId);
      alert('The active access has been destroyed.');
    } catch (err) {
      alert(err.message);
    }
  });

  $('#ownerLogout').onclick = () => {
    signOut();
  };
}

async function join() {
  const params = new URLSearchParams(location.search);
  if (params.get('company')) $('#companyAccess').value = params.get('company');
  if (params.get('branch')) $('#companyAccess').value = params.get('branch');
  if (params.get('token')) $('#companyAccess').value = params.get('token');

  $('#companyForm').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const input = $('#companyAccess').value.trim();
      const lookup = input.toUpperCase();
      let companyData = null;
      if (input) {
        companyData = await api('/api/customer/company/' + encodeURIComponent(lookup)).catch(() => null);
        if (!companyData) {
          companyData = await api('/api/customer/access/' + encodeURIComponent(input)).catch(() => null);
        }
      }
      if (!companyData || !companyData.company) {
        throw Error('Company code or access token not found');
      }
      if (!companyData.services.length) {
        alert('This company has no active services yet.');
        return;
      }
      $('#companyForm').classList.add('hidden');
      $('#services').classList.remove('hidden');
      $('#services').innerHTML = `
        <h2>${esc(companyData.company.name)}</h2>
        <p class="muted">${esc(companyData.company.category || '')} · Choose what you need.</p>
        <div class="notice-box">${companyData.access?.access_token ? `Use token: <strong>${esc(companyData.access.access_token)}</strong> or scan the QR at the desk.` : `Use the desk QR code or company access code to check in.`}</div>
        <form id="joinForm">
          <label>Describe what you need
            <textarea id="problemDescription" rows="3" maxlength="500" placeholder="I need to see a doctor because I have a headache."></textarea>
          </label>
          <label>Search services
            <input id="serviceSearch" type="search" maxlength="120" placeholder="Blood Test, consultation, scan…">
          </label>
          <p class="tiny muted">You can describe your need, search directly, or use both.</p>
          <div id="serviceResults" class="servicegrid"></div>
          <div id="serviceNoMatch" class="notice-box hidden"></div>
          <label>Name<input name="name" placeholder="Optional" maxlength="120"></label>
          <label>Phone number<input name="phone" inputmode="tel" placeholder="Optional — 080…" maxlength="20"></label>
          <button class="button primary" id="getTicketButton" disabled>Get my ticket →</button>
        </form>`;

      const serviceResults = $('#serviceResults');
      const serviceNoMatch = $('#serviceNoMatch');
      const getTicketButton = $('#getTicketButton');
      const problemDescription = $('#problemDescription');
      const serviceSearch = $('#serviceSearch');
      let selectedServiceId = '';

      const normalize = (value) =>
        String(value || '')
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, ' ')
          .trim();
      const levenshtein = (a, b) => {
        const left = normalize(a);
        const right = normalize(b);
        const row = Array.from({ length: right.length + 1 }, (_, i) => i);
        for (let i = 1; i <= left.length; i++) {
          let diagonal = row[0];
          row[0] = i;
          for (let j = 1; j <= right.length; j++) {
            const above = row[j];
            row[j] = left[i - 1] === right[j - 1]
              ? diagonal
              : Math.min(row[j] + 1, row[j - 1] + 1, diagonal + 1);
            diagonal = above;
          }
        }
        return row[right.length];
      };
      const matchesService = (service, query) => {
        const normalizedQuery = normalize(query);
        if (!normalizedQuery) return true;
        const meaningfulWords = normalizedQuery.split(' ').filter((word) => word.length >= 3);
        if (!meaningfulWords.length) return false;
        const fields = [
          service.name,
          service.customer_name,
          service.category,
          service.search_keywords,
        ].map(normalize);
        const exact = normalizedQuery.length >= 3 && fields.some((field) => field.includes(normalizedQuery));
        const keywordHits = meaningfulWords.filter((word) => fields.some((field) => field.includes(word))).length;
        const closeName = normalizedQuery.length >= 4 &&
          fields.slice(0, 2).some((field) => levenshtein(normalizedQuery, field) <= Math.max(1, Math.floor(normalizedQuery.length / 4)));
        return exact || keywordHits > 0 || closeName;
      };

      const renderServices = () => {
        const query = `${problemDescription.value} ${serviceSearch.value}`.trim();
        const matches = companyData.services.filter((service) => matchesService(service, query));
        if (!matches.some((service) => String(service.id) === String(selectedServiceId))) {
          selectedServiceId = '';
        }
        serviceResults.innerHTML = matches.length
          ? matches.map((service) => `
              <label class="servicecard">
                <input type="radio" name="service_id" value="${service.id}" ${String(service.id) === String(selectedServiceId) ? 'checked' : ''}>
                <b>${esc(service.customer_name || service.name)}</b>
                <span>${esc(service.category || 'Service')} · ${service.estimated_duration} min</span>
              </label>`).join('')
          : '';
        getTicketButton.disabled = !selectedServiceId;
        if (!matches.length) {
          const general = companyData.services.find((service) =>
            normalize(service.name) === 'general queue' ||
            normalize(service.customer_name) === 'general queue'
          );
          serviceNoMatch.innerHTML = `
            <strong>We couldn't find that service.</strong>
            <p>This company may not offer what you're looking for.</p>
            <button type="button" class="button ghost small" id="searchAgainButton">Search again</button>
            <button type="button" class="button ghost small" id="viewServicesButton">View available services</button>
            ${general ? '<button type="button" class="button primary small" id="generalQueueButton">Join General Queue</button>' : ''}
            <button type="button" class="button sub small" id="cancelSearchButton">Cancel</button>`;
          serviceNoMatch.classList.remove('hidden');
          $('#searchAgainButton').onclick = () => {
            problemDescription.value = '';
            serviceSearch.value = '';
            problemDescription.focus();
            renderServices();
          };
          $('#viewServicesButton').onclick = () => {
            problemDescription.value = '';
            serviceSearch.value = '';
            renderServices();
          };
          $('#cancelSearchButton').onclick = () => {
            problemDescription.value = '';
            serviceSearch.value = '';
            selectedServiceId = '';
            serviceNoMatch.classList.add('hidden');
            renderServices();
          };
          if (general) {
            $('#generalQueueButton').onclick = () => {
              selectedServiceId = String(general.id);
              problemDescription.value = '';
              serviceSearch.value = '';
              renderServices();
            };
          }
        } else {
          serviceNoMatch.classList.add('hidden');
        }
      };

      problemDescription.oninput = renderServices;
      serviceSearch.oninput = renderServices;
      serviceResults.onchange = (event) => {
        if (event.target.name === 'service_id') {
          selectedServiceId = event.target.value;
          getTicketButton.disabled = false;
        }
      };
      renderServices();

      $('#joinForm').onsubmit = async (ev) => {
        ev.preventDefault();
        const x = Object.fromEntries(new FormData(ev.target));
        x.service_id = selectedServiceId;
        if (!x.service_id) {
          alert('Select the service you want to join.');
          return;
        }
        x.company_code = companyData.company.public_code || companyData.company.company_public_code || companyData.access?.public_code || input;
        try {
          const r = await api('/api/customer/join', {
            method: 'POST',
            body: JSON.stringify(x),
          });
          saveTicket(r);
          location.href = `customer.html?id=${r.entry.id}&t=${encodeURIComponent(r.accessToken)}`;
        } catch (err) {
          alert(err.message);
        }
      };
    } catch (err) {
      alert(err.message);
    }
  };
}

async function ticket() {
  const params = new URLSearchParams(location.search);
  const id = params.get('id');
  const access = loadTicketAccess(id);
  const view = $('#ticketView');

  if (!id || !access) {
    view.innerHTML =
      '<h1>Ticket unavailable</h1><p class="muted">Return to Join queue and create a new ticket.</p><p><a class="button primary" href="join.html">Join a queue â†’</a></p>';
    return;
  }

  if (!params.get('t')) {
    history.replaceState(
      null,
      '',
      `customer.html?id=${encodeURIComponent(id)}&t=${encodeURIComponent(access)}`
    );
  }

  const headers = { 'X-Ticket-Token': access };
  let lastAhead = null;
  let lastWait = null;

  async function load() {
    try {
      const e = await api('/api/customer/ticket/' + id, { headers });
      $('#ticketNo').textContent = e.ticket_number;
      $('#serviceName').textContent = e.service_name;
      if ($('#branchLabel')) {
        $('#branchLabel').textContent = e.branch_name
          ? `${e.branch_name} Â· ${e.branch_code || ''}`
          : '';
      }

      const pos =
        e.status === 'SERVING'
          ? 'Now'
          : e.position != null
            ? `#${e.position}`
            : 'â€”';
      setLive($('#position'), pos);

      const aheadVal =
        e.status === 'SERVING' || e.status === 'COMPLETED' ? 0 : e.people_ahead;
      setLive($('#ahead'), aheadVal);

      const waitVal =
        e.status === 'SERVING'
          ? 'Now'
          : e.status === 'COMPLETED'
            ? 'Done'
            : e.status === 'CANCELLED' || e.status === 'SKIPPED' || e.status === 'NO_SHOW'
              ? 'â€”'
              : `${e.estimated_wait_low}â€“${e.estimated_wait_high} min`;
      setLive($('#wait'), waitVal);

      if (lastAhead !== null && lastAhead !== aheadVal) pulse($('#ahead'));
      if (lastWait !== null && lastWait !== waitVal) pulse($('#wait'));
      lastAhead = aheadVal;
      lastWait = waitVal;

      const soon = e.return_soon_threshold ?? 5;
      const nowT = e.return_now_threshold ?? 2;

      let state = 'You can leave for now â€” we will update this page as the queue moves.';
      let tone = 'return';
      if (e.status === 'SERVING') {
        state = 'You are being served';
        tone = 'return';
      } else if (e.status === 'CALLED') {
        state = 'You have been called â€” go to the counter now';
        tone = 'return urgent';
      } else if (e.status === 'ARRIVED') {
        state = 'Checked in â€” wait to be served';
        tone = 'return';
      } else if (e.status === 'COMPLETED') {
        state = 'Service completed. Thank you.';
        tone = 'return';
      } else if (e.status === 'CANCELLED') {
        state = 'This ticket was cancelled';
        tone = 'return danger';
      } else if (e.status === 'NO_SHOW' || e.status === 'SKIPPED') {
        state = 'This ticket is no longer active';
        tone = 'return danger';
      } else if (e.people_ahead <= nowT) {
        state = 'Your turn is here â€” return now';
        tone = 'return urgent';
      } else if (e.people_ahead <= soon) {
        state = 'Start returning soon â€” your place is moving up';
        tone = 'return urgent';
      }

      const box = $('#returnState');
      if (box.textContent !== state) {
        box.textContent = state;
        pulse(box);
      }
      box.className = tone;

      const cancelBtn = $('#cancelBtn');
      const terminal = ['COMPLETED', 'CANCELLED', 'NO_SHOW', 'SKIPPED', 'SERVING'];
      const canCancel = e.allow_customer_cancel !== false && !terminal.includes(e.status);
      cancelBtn.style.display = canCancel ? '' : 'none';

      const reminder = $('#appReminder');
      if (reminder) {
        const tokenText = e.branch_code ? `Use your company access code: ${esc(e.branch_code)}` : 'Use your company access code to open the app faster next time.';
        reminder.innerHTML = `Install the app for quicker reminder alerts. ${tokenText}`;
      }
    } catch (err) {
      view.innerHTML = `<h1>Ticket unavailable</h1><p class="muted">${esc(err.message)}</p><p><a class="button primary" href="join.html">Join a queue â†’</a></p>`;
    }
  }

  await load();
  setInterval(load, 4000);

  api('/api/customer/ticket/' + id, { headers })
    .then((e) => {
      if (!e.branch_code) return;
      const es = new EventSource(
        `/api/events?branch=${encodeURIComponent(e.branch_code)}`
      );
      es.onmessage = () => load();
    })
    .catch(() => {});

  $('#cancelBtn').onclick = async () => {
    if (!confirm('Cancel this ticket?')) return;
    try {
      await api('/api/customer/ticket/' + id + '/cancel', {
        method: 'POST',
        headers,
      });
      await load();
    } catch (err) {
      alert(err.message);
    }
  };
}

if ($('#companyForm')) join();
if ($('#ticketView')) ticket();
if ($('#queue')) staff();
if ($('#branches')) owner();
