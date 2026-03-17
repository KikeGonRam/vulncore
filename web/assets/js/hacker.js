const API = '/api';
let donutChart = null, timelineChart = null;
let allPkgs = [], activeScanId = null, pollInterval = null;

// ── Severity helpers ──────────────────────────────────
function sevBg(s)   { return {CRITICAL:'rgba(255,62,62,0.15)',HIGH:'rgba(255,170,0,0.15)',MEDIUM:'rgba(255,213,0,0.1)',LOW:'rgba(0,255,102,0.1)'}[s]||'rgba(255,255,255,0.05)'; }
function sevFg(s)   { return {CRITICAL:'#ff3e3e',HIGH:'#ffaa00',MEDIUM:'#ffd500',LOW:'#00ff66'}[s]||'#888'; }
function chip(sev)  { return `<span style="font-family:var(--font-mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;background:${sevBg(sev)};color:${sevFg(sev)};">${sev}</span>`; }
function empty(msg) { return `<tr><td colspan="99" style="color:var(--text-dim);padding:20px;font-family:var(--font-mono);font-size:11px;">[NO_DATA] ${msg}</td></tr>`; }

document.addEventListener('DOMContentLoaded', () => {
  setupNav();
  loadDashboard();
});

// ── Navigation ────────────────────────────────────────
function setupNav() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const page = item.dataset.page;
      if (!page) return;
      navigate(page, item);
    });
  });
}

async function navigate(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + page)?.classList.add('active');
  el?.classList.add('active');
  const viewEl = document.getElementById('current-view');
  if (viewEl) viewEl.textContent = page.toUpperCase();

  const loaders = {
    dashboard:       loadDashboard,
    vulnerabilities: loadVulns,
    ports:           loadPorts,
    packages:        loadPackages,
    history:         loadHistory,
  };
  if (loaders[page]) await loaders[page]();
}

// ── Dashboard ─────────────────────────────────────────
async function loadDashboard() {
  try {
    const [stats, tl] = await Promise.all([
      fetch(`${API}/dashboard/stats`).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }),
      fetch(`${API}/dashboard/timeline`).then(r => r.json()),
    ]);

    const b = stats.severity_breakdown || {};
    setEl('stat-exploited', stats.total_exploited  ?? 0);
    setEl('stat-risky',     stats.high_risk_count  ?? 0);
    setEl('stat-critical',  b.CRITICAL             ?? 0);
    setEl('stat-ports',     stats.total_open_ports ?? 0);
    setEl('nav-vuln-count', (b.CRITICAL||0)+(b.HIGH||0));
    setEl('nav-port-count', stats.total_open_ports ?? 0);

    renderDonut(b);
    renderTimeline(tl.data || []);
    renderTopPkgs(stats.top_vulnerable_packages || []);
  } catch (e) {
    console.error('Dashboard error:', e);
    // Show zeros instead of blank
    ['stat-exploited','stat-risky','stat-critical','stat-ports'].forEach(id => setEl(id, 0));
    renderDonut({});
    renderTimeline([]);
    renderTopPkgs([]);
  }
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = (val !== undefined && val !== null) ? val : '0';
}

// ── Vulnerabilities ───────────────────────────────────
async function loadVulns() {
  const tbody = document.getElementById('vuln-body');
  if (!tbody) return;
  tbody.innerHTML = empty('LOADING_THREAT_DATABASE...');

  try {
    const json = await fetch(`${API}/vulnerabilities?limit=200`).then(r => r.json());
    const data = json.data || [];

    if (!data.length) {
      tbody.innerHTML = empty('NO_THREATS_DETECTED — RUN_SCAN_TO_POPULATE');
      return;
    }

    tbody.innerHTML = data.map(v => `
      <tr>
        <td style="color:var(--cyan);font-weight:700;">${v.cve_id}</td>
        <td>${v.package_name}</td>
        <td style="color:var(--text-dim)">${v.installed_version}</td>
        <td style="color:var(--green)">${v.fixed_version || '---'}</td>
        <td style="font-family:var(--font-mono)">${v.cvss_score ? v.cvss_score.toFixed(1) : '0.0'}</td>
        <td>${chip(v.severity)}</td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = empty('SYNC_ERROR: ' + e.message);
  }
}

// ── Ports ─────────────────────────────────────────────
async function loadPorts() {
  const tbody = document.getElementById('ports-body');
  if (!tbody) return;
  tbody.innerHTML = empty('LOADING_PORT_DATA...');

  try {
    const json = await fetch(`${API}/reports/last`).then(r => r.json());
    if (!json.scan) {
      tbody.innerHTML = empty('NO_SCAN_RECORDS — RUN_SCAN_FIRST');
      return;
    }

    const ports = (json.ports || []).filter(p => (p.state||p.State) === 'open');
    if (!ports.length) {
      tbody.innerHTML = empty('NO_OPEN_PORTS_DETECTED');
      return;
    }

    tbody.innerHTML = ports.map(p => `
      <tr>
        <td style="color:var(--cyan);font-family:var(--font-mono);font-weight:700;">${p.Port??p.port}</td>
        <td>${p.Protocol??p.protocol}</td>
        <td style="color:var(--green)">OPEN</td>
        <td>${p.Service??p.service??'---'}</td>
        <td style="color:var(--text-dim)">${p.Version??p.version??'---'}</td>
        <td style="color:var(--text-dim);font-size:10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${p.Banner??p.banner??'---'}</td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = empty('SYNC_ERROR: ' + e.message);
  }
}

// ── Packages ──────────────────────────────────────────
async function loadPackages() {
  const tbody = document.getElementById('pkg-body');
  if (!tbody) return;
  tbody.innerHTML = empty('LOADING_INVENTORY...');

  try {
    const json = await fetch(`${API}/reports/last`).then(r => r.json());
    allPkgs = json.packages || [];

    if (!json.scan || !allPkgs.length) {
      tbody.innerHTML = empty('NO_PACKAGES — RUN_SCAN_FIRST');
      return;
    }

    renderPkgs(allPkgs);
  } catch (e) {
    tbody.innerHTML = empty('SYNC_ERROR: ' + e.message);
  }
}

function renderPkgs(list) {
  const tbody = document.getElementById('pkg-body');
  if (!tbody) return;
  tbody.innerHTML = list.slice(0, 300).map(p => `
    <tr>
      <td style="font-family:var(--font-mono)">${p.Name??p.name}</td>
      <td style="color:var(--green);font-family:var(--font-mono)">${p.Version??p.version}</td>
      <td style="color:var(--text-dim)">${p.Arch??p.arch??'---'}</td>
      <td>${p.Manager??p.manager}</td>
    </tr>`).join('');
}

// ── History ───────────────────────────────────────────
async function loadHistory() {
  const tbody = document.getElementById('history-body');
  if (!tbody) return;
  tbody.innerHTML = empty('LOADING_AUDIT_LOG...');

  try {
    const json = await fetch(`${API}/history`).then(r => r.json());
    const data = json.data || [];

    if (!data.length) {
      tbody.innerHTML = empty('NO_SCAN_HISTORY');
      return;
    }

    tbody.innerHTML = data.map(s => {
      const started  = new Date(s.started_at ?? s.StartedAt);
      const finished = s.finished_at ?? s.FinishedAt;
      const dur      = finished ? ((new Date(finished) - started) / 1000).toFixed(0) + 's' : '---';
      const status   = s.status ?? s.Status ?? 'unknown';
      const statusColor = {done:'var(--green)', error:'var(--red)', running:'var(--cyan)'}[status] || 'var(--text-dim)';
      return `<tr>
        <td style="color:var(--text-dim);font-family:var(--font-mono)">${(s.ID??s.id??'').substring(0,8)}</td>
        <td>${s.target??s.Target}</td>
        <td>${s.scan_type??s.ScanType}</td>
        <td style="color:${statusColor}">${status.toUpperCase()}</td>
        <td style="color:var(--text-dim)">${started.toLocaleString()}</td>
        <td style="font-family:var(--font-mono)">${s.vuln_count??s.VulnCount??'0'}</td>
        <td style="font-family:var(--font-mono)">${s.port_count??s.PortCount??'0'}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = empty('SYNC_ERROR: ' + e.message);
  }
}

// ── Charts ────────────────────────────────────────────
function renderDonut(b) {
  const ctx = document.getElementById('donut-chart');
  if (!ctx) return;
  if (donutChart) donutChart.destroy();
  donutChart = new Chart(ctx.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{
        data: [b.CRITICAL||0, b.HIGH||0, b.MEDIUM||0, b.LOW||0],
        backgroundColor: ['#ff3e3e','#ffaa00','#ffd500','#00ff66'],
        borderColor: '#0a0c0f',
        borderWidth: 2,
      }],
    },
    options: {
      cutout: '80%',
      plugins: { legend: { display: false } },
    },
  });
}

function renderTimeline(data) {
  const ctx = document.getElementById('timeline-chart');
  if (!ctx) return;
  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(ctx.getContext('2d'), {
    type: 'line',
    data: {
      labels: data.map(d => d.date),
      datasets: [
        { label:'Critical', data:data.map(d=>d.critical), borderColor:'#ff3e3e', borderWidth:2, tension:0.4, pointRadius:0, fill:true, backgroundColor:'rgba(255,62,62,0.05)' },
        { label:'High',     data:data.map(d=>d.high),     borderColor:'#ffaa00', borderWidth:2, tension:0.4, pointRadius:0 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display:false }, ticks: { color:'#404040', font:{family:'JetBrains Mono',size:10} } },
        y: { ticks: { color:'#404040', font:{family:'JetBrains Mono',size:10} }, grid: { color:'rgba(255,255,255,0.03)' } },
      },
    },
  });
}

function renderTopPkgs(list) {
  const tbody = document.getElementById('top-pkg-body');
  if (!tbody) return;
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:var(--text-dim);padding:15px;font-size:11px;">[EMPTY] NO_DATA</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(p => `
    <tr>
      <td style="font-family:var(--font-mono);font-weight:600">${p.package_name}</td>
      <td style="color:var(--cyan);font-family:var(--font-mono);font-weight:700">${p.count}</td>
      <td>${chip(p.max_severity)}</td>
    </tr>`).join('');
}

// ── Modal & Scan ──────────────────────────────────────
function openModal()  { const m = document.getElementById('modal'); if(m) m.style.display='flex'; }
function closeModal() { const m = document.getElementById('modal'); if(m) m.style.display='none'; }

async function startScan() {
  const target = document.getElementById('scan-target')?.value?.trim();
  const range  = document.getElementById('scan-range')?.value?.trim();
  if (!target) return;
  closeModal();

  const consoleEl = document.getElementById('scan-console');
  const outputEl  = document.getElementById('console-output');
  if (consoleEl) consoleEl.style.display = 'flex';
  if (outputEl)  outputEl.innerHTML = '';

  updateProgress(0, 'INITIATING_SCAN_SEQUENCE...');
  log(`[INIT] TARGET: ${target}  RANGE: ${range}`, 'cyan');

  try {
    const res  = await fetch(`${API}/scan/full`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, port_range: range }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'API_ERROR');

    activeScanId = json.scan_id;
    log(`[OK] SESSION: ${activeScanId.substring(0,8)}...`, 'green');
    pollStatus();
  } catch (e) {
    log(`[ERROR] ${e.message}`, 'red');
    setTimeout(() => { if(consoleEl) consoleEl.style.display='none'; }, 5000);
  }
}

function log(msg, color = 'white') {
  const out = document.getElementById('console-output');
  if (!out) return;
  const line = document.createElement('div');
  line.style.color = color === 'dim' ? 'var(--text-dim)' : `var(--${color}, #fff)`;
  line.textContent = `> ${new Date().toLocaleTimeString()} ${msg}`;
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

function updateProgress(pct, step) {
  const bar  = document.getElementById('scan-progress-bar');
  const perc = document.getElementById('console-percent');
  const stp  = document.getElementById('console-step');
  if (bar)  bar.style.width = `${pct}%`;
  if (perc) perc.textContent = `${pct}%`;
  if (stp)  stp.textContent  = step;
}

function pollStatus() {
  let progress = 5;
  let ticks = 0;

  pollInterval = setInterval(async () => {
    ticks++;
    if (ticks > 300) { clearInterval(pollInterval); return; } // max 10min

    try {
      const json = await fetch(`${API}/scan/${activeScanId}/status`).then(r => r.json());

      if (progress < 90) progress += 1;
      updateProgress(progress, `PROBING... OPEN_PORTS: ${json.open_ports ?? 0}`);

      if (json.status === 'done') {
        clearInterval(pollInterval);
        updateProgress(100, 'SCAN_COMPLETE');
        log('[OK] SCAN_COMPLETE — SYNCHRONIZING_DATA', 'green');

        const tag = document.getElementById('scan-status-tag');
        if (tag) { tag.textContent = 'COMPLETED'; tag.style.color = 'var(--green)'; }

        setTimeout(async () => {
          const c = document.getElementById('scan-console');
          if (c) c.style.display = 'none';
          await loadDashboard();
          navigate('vulnerabilities', document.querySelector('[data-page="vulnerabilities"]'));
        }, 1500);

      } else if (json.status === 'error') {
        clearInterval(pollInterval);
        updateProgress(progress, 'EXECUTION_HALTED');
        log('[FATAL] ENGINE_ERROR', 'red');
        setTimeout(() => { const c=document.getElementById('scan-console'); if(c) c.style.display='none'; }, 4000);
        await loadDashboard();
      }
    } catch {
      clearInterval(pollInterval);
      log('[ERROR] CONNECTION_LOST', 'red');
    }
  }, 3000);
}