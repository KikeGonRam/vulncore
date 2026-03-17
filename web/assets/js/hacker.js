const API = '/api';
let donutChart = null, timelineChart = null;
let allPkgs = [], activeScanId = null, pollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  loadDashboard();
  setupEventListeners();
});

function setupEventListeners() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const page = item.getAttribute('data-page');
      navigate(page, item);
    });
  });
}

async function navigate(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  
  document.getElementById('page-' + page).classList.add('active');
  el.classList.add('active');
  document.getElementById('current-view').textContent = page.toUpperCase();

  switch(page) {
    case 'dashboard':       await loadDashboard(); break;
    case 'vulnerabilities': await loadVulns(); break;
    case 'ports':           await loadPorts(); break;
    case 'packages':        await loadPackages(); break;
    case 'history':         await loadHistory(); break;
  }
}

async function loadDashboard() {
  try {
    const stats = await fetch(`${API}/dashboard/stats`).then(r => r.json());
    const tl = await fetch(`${API}/dashboard/timeline`).then(r => r.json());
    const b = stats.severity_breakdown || {};
    updateEl('stat-exploited', stats.total_exploited);
    updateEl('stat-risky',     stats.high_risk_count);
    updateEl('stat-critical',  b.CRITICAL);
    updateEl('stat-ports',     stats.total_open_ports);
    updateEl('nav-vuln-count', (b.CRITICAL||0)+(b.HIGH||0));
    updateEl('nav-port-count', stats.total_open_ports);
    renderDonut(b);
    renderTimeline(tl.data || []);
    renderTopPkgs(stats.top_vulnerable_packages || []);
  } catch (e) { console.error('Dashboard sync error'); }
}

function updateEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val !== undefined ? val : '0';
}

// ── SCAN ENGINE LOGIC ────────────────────────────────
function openModal()  { document.getElementById('modal').style.display = 'flex'; }
function closeModal() { document.getElementById('modal').style.display = 'none'; }

async function startScan() {
  const target = document.getElementById('scan-target').value;
  const range  = document.getElementById('scan-range').value;
  closeModal();
  
  // Show Console
  const consoleEl = document.getElementById('scan-console');
  const outputEl  = document.getElementById('console-output');
  consoleEl.style.display = 'flex';
  outputEl.innerHTML = '';
  updateProgressBar(0, 'INITIATING_SCAN_SEQUENCE...');

  addLog(`[INIT] ESTABLISHING_BRIDGE_CONNECTION_TO_RUST_ENGINE...`, 'cyan');
  addLog(`[CONF] TARGET_SPECIFIED: ${target}`, 'dim');
  addLog(`[CONF] PORT_RANGE_POLICY: ${range}`, 'dim');

  try {
    const res = await fetch(`${API}/scan/full`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, port_range: range }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'API_REJECTED_REQUEST');

    activeScanId = json.scan_id;
    addLog(`[OK] SESSION_CREATED: ${activeScanId.substring(0,8)}...`, 'green');
    pollScanStatus();
  } catch (e) {
    addLog(`[ERROR] CRITICAL_FAILURE: ${e.message}`, 'red');
    setTimeout(() => consoleEl.style.display = 'none', 5000);
  }
}

function addLog(msg, color = 'white') {
  const output = document.getElementById('console-output');
  const line = document.createElement('div');
  line.style.color = color === 'dim' ? 'var(--text-dim)' : `var(--${color})`;
  line.textContent = `> ${new Date().toLocaleTimeString()} ${msg}`;
  output.appendChild(line);
  output.scrollTop = output.scrollHeight;
}

function updateProgressBar(percent, step) {
    document.getElementById('scan-progress-bar').style.width = `${percent}%`;
    document.getElementById('console-percent').textContent = `${percent}%`;
    document.getElementById('console-step').textContent = step;
}

function pollScanStatus() {
  let progress = 5;
  pollInterval = setInterval(async () => {
    try {
      const res = await fetch(`${API}/scan/${activeScanId}/status`);
      const json = await res.json();

      if (progress < 90) progress += 2;
      
      if (json.status === 'running') {
          updateProgressBar(progress, `PROBING_TARGET_ASSETS... [OPEN_PORTS: ${json.open_ports || 0}]`);
          if (progress % 10 === 0) addLog(`[SCAN] PROBING_NETWORK_INTERFACES...`, 'cyan');
      } else if (json.status === 'done') {
          clearInterval(pollInterval);
          updateProgressBar(100, 'SCAN_COMPLETE_SYNCHRONIZING_DATA...');
          addLog(`[OK] DATA_FLUSH_SUCCESSFUL`, 'green');
          addLog(`[OK] TERMINATING_ENGINE_PROCESS`, 'green');
          document.getElementById('scan-status-tag').textContent = 'COMPLETED';
          document.getElementById('scan-status-tag').style.color = 'var(--green)';
          
          setTimeout(() => {
              document.getElementById('scan-console').style.display = 'none';
              loadDashboard();
              navigate('dashboard', document.querySelector('[data-page="dashboard"]'));
          }, 2000);
      } else if (json.status === 'error') {
          clearInterval(pollInterval);
          addLog(`[FATAL] ENGINE_RETURNED_ERROR`, 'red');
          updateProgressBar(progress, 'EXECUTION_HALTED');
      }
    } catch (e) {
      clearInterval(pollInterval);
      addLog(`[ERROR] CONNECTION_LOST_TO_API`, 'red');
    }
  }, 2000);
}

// ── DATA LOADING ─────────────────────────────────────
async function loadVulns() {
  const tbody = document.getElementById('vuln-body');
  try {
    const json = await fetch(`${API}/vulnerabilities?limit=100`).then(r => r.json());
    tbody.innerHTML = (json.data || []).map(v => `
      <tr>
        <td style="color:var(--cyan); font-weight:bold;">${v.cve_id}</td>
        <td>${v.package_name}</td>
        <td>${v.installed_version}</td>
        <td style="color:var(--green)">${v.fixed_version || '---'}</td>
        <td>${v.cvss_score ? v.cvss_score.toFixed(1) : '0.0'}</td>
        <td><span class="chip-chip-${v.severity}">${v.severity}</span></td>
      </tr>`).join('');
  } catch (e) { tbody.innerHTML = '<tr><td colspan="6">SYNC_ERROR</td></tr>'; }
}

async function loadPorts() {
  const tbody = document.getElementById('ports-body');
  try {
    const json = await fetch(`${API}/reports/last`).then(r => r.json());
    const ports = (json.ports || []).filter(p => (p.state||p.State) === 'open');
    tbody.innerHTML = ports.map(p => `
      <tr>
        <td style="color:var(--cyan)">${p.Port??p.port}</td>
        <td>${p.Protocol??p.protocol}</td>
        <td style="color:var(--green)">OPEN</td>
        <td>${p.Service??p.service??'---'}</td>
        <td>${p.Version??p.version??'---'}</td>
        <td style="color:var(--text-dim); font-size:10px">${p.Banner??p.banner??'---'}</td>
      </tr>`).join('');
  } catch (e) { tbody.innerHTML = '<tr><td colspan="6">SYNC_ERROR</td></tr>'; }
}

async function loadPackages() {
    const tbody = document.getElementById('pkg-body');
    try {
      const json = await fetch(`${API}/reports/last`).then(r => r.json());
      tbody.innerHTML = (json.packages || []).slice(0, 100).map(p => `
        <tr>
          <td>${p.Name??p.name}</td>
          <td style="color:var(--green)">${p.Version??p.version}</td>
          <td>${p.Arch??p.arch??'---'}</td>
          <td>${p.Manager??p.manager}</td>
        </tr>`).join('');
    } catch (e) { tbody.innerHTML = '<tr><td colspan="4">SYNC_ERROR</td></tr>'; }
}

async function loadHistory() {
  const tbody = document.getElementById('history-body');
  try {
    const json = await fetch(`${API}/history`).then(r => r.json());
    tbody.innerHTML = (json.data || []).map(s => `
      <tr>
        <td style="color:var(--text-dim)">${(s.ID ?? s.id ?? '').substring(0,8)}</td>
        <td>${s.target ?? s.Target}</td>
        <td>${s.scan_type ?? s.ScanType}</td>
        <td>${s.status??s.Status}</td>
        <td>${new Date(s.started_at ?? s.StartedAt).toLocaleString()}</td>
        <td>${s.vuln_count ?? s.VulnCount ?? '0'}</td>
        <td>${s.port_count ?? s.PortCount ?? '0'}</td>
      </tr>`).join('');
  } catch (e) { tbody.innerHTML = '<tr><td colspan="7">SYNC_ERROR</td></tr>'; }
}

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
        borderColor: '#0a0c0f', borderWidth: 2,
      }],
    },
    options: { cutout: '85%', plugins: { legend: { display: false } } },
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
        { label:'Critical', data:data.map(d=>d.critical), borderColor:'#ff3e3e', borderWidth: 2, tension:0.4, pointRadius:0, fill: true, backgroundColor: 'rgba(255,62,62,0.05)' },
        { label:'High',     data:data.map(d=>d.high),     borderColor:'#ffaa00', borderWidth: 2, tension:0.4, pointRadius:0 },
      ],
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: '#404040' } },
        y: { ticks: { color: '#404040' }, grid: { color:'rgba(255,255,255,0.03)' } },
      },
    },
  });
}

function renderTopPkgs(list) {
  const tbody = document.getElementById('top-pkg-body');
  if (!tbody) return;
  tbody.innerHTML = list.map(p => `
    <tr>
      <td style="font-weight:600">${p.package_name}</td>
      <td style="color:var(--cyan); font-weight:bold">${p.count}</td>
      <td>${p.max_severity}</td>
    </tr>`).join('');
}
