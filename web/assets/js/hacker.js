const API = '/api';
let donutChart = null, timelineChart = null;
let allPkgs = [], activeScanId = null, pollInterval = null;
let selectedScanType = 'full';

// ── Helpers ────────────────────────────────────
function str(v)     { return v != null ? String(v) : ''; }
function num(v, d)  { return v != null ? v : (d ?? 0); }

function sevBg(s)   { return {CRITICAL:'rgba(255,23,68,0.12)',HIGH:'rgba(255,145,0,0.12)',MEDIUM:'rgba(255,213,0,0.08)',LOW:'rgba(0,230,118,0.08)'}[s]||'rgba(255,255,255,0.04)'; }
function sevFg(s)   { return {CRITICAL:'#ff1744',HIGH:'#ff9100',MEDIUM:'#ffd600',LOW:'#00e676'}[s]||'#7a8594'; }

function chip(sev) {
  const s = str(sev).toUpperCase().replace(/[^A-Z]/g,'') || 'UNKNOWN';
  const label = {CRITICAL:'CRITICAL',HIGH:'HIGH',MEDIUM:'MEDIUM',LOW:'LOW'}[s] || s;
  return `<span style="font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 10px;border-radius:4px;background:${sevBg(label)};color:${sevFg(label)};border:1px solid ${sevFg(label)}22;letter-spacing:0.08em;">${label}</span>`;
}

function empty(msg) {
  return `<tr><td colspan="99" style="color:var(--text-3);padding:24px;font-family:var(--mono);font-size:11px;text-align:center;letter-spacing:0.05em;">${msg}</td></tr>`;
}

function gf(obj, ...keys) {
  for (const k of keys) { if (obj[k] != null) return obj[k]; }
  return null;
}

// ── Clock ───────────────────────────────────────
function updateClock() {
  const el = document.getElementById('sys-time');
  if (el) el.textContent = new Date().toLocaleTimeString('en-US', {hour12:false});
}
updateClock();
setInterval(updateClock, 1000);

document.addEventListener('DOMContentLoaded', () => {
  setupNav();
  loadDashboard();
});

// ── Navigation ──────────────────────────────────
function setupNav() {
  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', () => navigate(item.dataset.page, item));
  });
}

async function navigate(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + page)?.classList.add('active');
  el?.classList.add('active');
  const viewEl = document.getElementById('current-view');
  if (viewEl) viewEl.textContent = page.toLowerCase();
  const loaders = { dashboard:loadDashboard, vulnerabilities:loadVulns, ports:loadPorts, packages:loadPackages, history:loadHistory };
  if (loaders[page]) await loaders[page]();
}

// ── Dashboard ───────────────────────────────────
async function loadDashboard() {
  if (donutChart)    { donutChart.destroy();    donutChart = null; }
  if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
  try {
    const [stats, tl] = await Promise.all([
      fetch(`${API}/dashboard/stats`).then(r => r.json()),
      fetch(`${API}/dashboard/timeline`).then(r => r.json()),
    ]);
    const b = stats.severity_breakdown || {};
    animateNum('stat-exploited', num(stats.total_exploited));
    animateNum('stat-risky',     num(stats.high_risk_count));
    animateNum('stat-critical',  num(b.CRITICAL));
    animateNum('stat-ports',     num(stats.total_open_ports));
    setEl('nav-vuln-count', num(b.CRITICAL) + num(b.HIGH));
    setEl('nav-port-count', num(stats.total_open_ports));
    renderDonut(b);
    renderTimeline(tl.data || []);
    renderTopPkgs(stats.top_vulnerable_packages || []);
  } catch (e) {
    console.error('Dashboard:', e);
    ['stat-exploited','stat-risky','stat-critical','stat-ports'].forEach(id => setEl(id, '—'));
    renderDonut({}); renderTimeline([]); renderTopPkgs([]);
  }
}

function animateNum(id, target) {
  const el = document.getElementById(id);
  if (!el || target === 0) { if (el) el.textContent = '0'; return; }
  let start = 0;
  const step = Math.ceil(target / 20);
  const timer = setInterval(() => {
    start = Math.min(start + step, target);
    el.textContent = start;
    if (start >= target) clearInterval(timer);
  }, 30);
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '0';
}

// ── Table filter ─────────────────────────────────
function filterTable(query, tbodyId, countId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const q = query.trim().toLowerCase();
  let visible = 0;
  tbody.querySelectorAll('tr').forEach(row => {
    const text = row.textContent.toLowerCase();
    const match = !q || text.includes(q);
    row.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  const countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = `${visible} rows`;
}

// ── Animate table rows ─────────────────────────────
function animateRows(tbody, delay = 18) {
  if (!tbody) return;
  const rows = tbody.querySelectorAll('tr');
  rows.forEach((row, i) => {
    row.style.animationDelay = `${Math.min(i * delay, 350)}ms`;
    row.classList.add('row-animated');
  });
  updateRowCount(tbody);
}

function updateRowCount(tbody) {
  if (!tbody) return;
  const countMap = {
    'vuln-body': 'vuln-count',
    'ports-body': 'ports-count',
    'pkg-body': 'pkg-count',
    'history-body': 'hist-count',
  };
  const countId = countMap[tbody.id];
  if (countId) {
    const countEl = document.getElementById(countId);
    if (countEl) countEl.textContent = `${tbody.querySelectorAll('tr').length} rows`;
  }
}

// ── Vulnerabilities ─────────────────────────────
async function loadVulns() {
  const tbody = document.getElementById('vuln-body');
  if (!tbody) return;
  tbody.innerHTML = empty('QUERYING_THREAT_DATABASE...');
  try {
    const json = await fetch(`${API}/vulnerabilities?limit=300`).then(r => r.json());
    const data = json.data || [];
    if (!data.length) { tbody.innerHTML = empty('NO_THREATS_DETECTED — EXECUTE_SCAN_TO_POPULATE'); updateRowCount(tbody); return; }
    tbody.innerHTML = data.map(v => {
      const sev  = str(gf(v,'severity','Severity')).toUpperCase();
      const cve  = str(gf(v,'cve_id','CveID'));
      const pkg  = str(gf(v,'package_name','PackageName'));
      const ins  = str(gf(v,'installed_version','InstalledVersion'));
      const fix  = str(gf(v,'fixed_version','FixedVersion') || '---');
      const cvss = gf(v,'cvss_score','CvssScore');
      const kev  = gf(v,'is_exploited','IsExploited') ? ' <span style="font-family:var(--mono);font-size:8px;color:var(--red);border:1px solid rgba(255,23,68,0.4);padding:1px 5px;border-radius:3px;background:rgba(255,23,68,0.08)">KEV</span>' : '';
      return `<tr>
        <td style="color:var(--cyan);font-weight:700;font-family:var(--mono)">${cve}${kev}</td>
        <td>${pkg}</td>
        <td style="color:var(--text-2)">${ins}</td>
        <td style="color:var(--green)">${fix}</td>
        <td style="color:var(--text-2)">${cvss ? Number(cvss).toFixed(1) : '—'}</td>
        <td>${chip(sev)}</td>
      </tr>`;
    }).join('');
    animateRows(tbody);
    const fi = document.getElementById('vuln-filter');
    if (fi && fi.value) filterTable(fi.value, 'vuln-body', 'vuln-count');
  } catch (e) { tbody.innerHTML = empty(`ERROR: ${e.message}`); }
}

// ── Ports ────────────────────────────────────────
async function loadPorts() {
  const tbody = document.getElementById('ports-body');
  if (!tbody) return;
  tbody.innerHTML = empty('LOADING_PORT_DATA...');
  try {
    const json = await fetch(`${API}/reports/last`).then(r => r.json());
    if (!json.scan) { tbody.innerHTML = empty('NO_COMPLETED_SCANS — RUN_SCAN_FIRST'); updateRowCount(tbody); return; }
    const ports = (json.ports || []).filter(p => str(gf(p,'state','State')).toLowerCase() === 'open');
    if (!ports.length) { tbody.innerHTML = empty('NO_OPEN_PORTS_IN_LAST_SCAN'); updateRowCount(tbody); return; }
    tbody.innerHTML = ports.map(p => `<tr>
      <td style="color:var(--cyan);font-weight:700">${gf(p,'Port','port')}</td>
      <td style="color:var(--text-2)">${str(gf(p,'Protocol','protocol')||'tcp')}</td>
      <td style="color:var(--green)">OPEN</td>
      <td>${str(gf(p,'Service','service')||'---')}</td>
      <td style="color:var(--text-2)">${str(gf(p,'Version','version')||'---')}</td>
      <td style="color:var(--text-3);font-size:10px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${str(gf(p,'Banner','banner')||'---')}</td>
    </tr>`).join('');
    animateRows(tbody);
    const fi = document.getElementById('ports-filter');
    if (fi && fi.value) filterTable(fi.value, 'ports-body', 'ports-count');
  } catch (e) { tbody.innerHTML = empty(`ERROR: ${e.message}`); }
}

// ── Packages ─────────────────────────────────────
async function loadPackages() {
  const tbody = document.getElementById('pkg-body');
  if (!tbody) return;
  tbody.innerHTML = empty('LOADING_INVENTORY...');
  try {
    const json = await fetch(`${API}/reports/last`).then(r => r.json());
    allPkgs = json.packages || [];
    if (!json.scan) { tbody.innerHTML = empty('NO_COMPLETED_SCANS — RUN_SCAN_FIRST'); updateRowCount(tbody); return; }
    if (!allPkgs.length) { tbody.innerHTML = empty('NO_PACKAGES_FOUND'); updateRowCount(tbody); return; }
    renderPkgs(allPkgs);
  } catch (e) { tbody.innerHTML = empty(`ERROR: ${e.message}`); }
}

function renderPkgs(list) {
  const tbody = document.getElementById('pkg-body');
  if (!tbody) return;
  tbody.innerHTML = list.slice(0, 500).map(p => `<tr>
    <td style="color:var(--text)">${str(gf(p,'Name','name'))}</td>
    <td style="color:var(--green)">${str(gf(p,'Version','version'))}</td>
    <td style="color:var(--text-2)">${str(gf(p,'Arch','arch')||'---')}</td>
    <td style="color:var(--text-3)">${str(gf(p,'Manager','manager'))}</td>
  </tr>`).join('');
  animateRows(tbody);
  const fi = document.getElementById('pkg-filter');
  if (fi && fi.value) filterTable(fi.value, 'pkg-body', 'pkg-count');
}

// ── History ──────────────────────────────────────
async function loadHistory() {
  const tbody = document.getElementById('history-body');
  if (!tbody) return;
  tbody.innerHTML = empty('READING_AUDIT_LOG...');
  try {
    const json = await fetch(`${API}/history`).then(r => r.json());
    const data = json.data || [];
    if (!data.length) { tbody.innerHTML = empty('NO_SCAN_HISTORY'); updateRowCount(tbody); return; }
    tbody.innerHTML = data.map(s => {
      const id        = str(gf(s,'ID','id')).substring(0, 8);
      const target    = str(gf(s,'target','Target')||'---');
      const scanType  = str(gf(s,'scan_type','ScanType')||'---');
      const status    = str(gf(s,'status','Status')||'unknown');
      const startRaw  = gf(s,'started_at','StartedAt');
      const endRaw    = gf(s,'finished_at','FinishedAt');
      const started   = startRaw ? new Date(startRaw) : null;
      const dur       = (started && endRaw) ? ((new Date(endRaw) - started)/1000).toFixed(0)+'s' : '---';
      const startStr  = started ? started.toLocaleString() : '---';
      const vulnCnt   = num(gf(s,'vuln_count','VulnCount'));
      const portCnt   = num(gf(s,'port_count','PortCount'));
      const statusFg  = {done:'var(--green)',error:'var(--red)',running:'var(--cyan)'}[status]||'var(--text-2)';
      return `<tr>
        <td style="color:var(--text-3)">${id}…</td>
        <td style="color:var(--cyan)">${target}</td>
        <td style="color:var(--text-2)">${scanType}</td>
        <td style="color:${statusFg};font-weight:600">${status.toUpperCase()}</td>
        <td style="color:var(--text-3);font-size:11px">${startStr}</td>
        <td style="color:var(--text-2)">${dur}</td>
        <td style="color:${vulnCnt>0?'var(--red)':'var(--text-3)'}">${vulnCnt}</td>
        <td style="color:var(--text-2)">${portCnt}</td>
      </tr>`;
    }).join('');
    animateRows(tbody);
    const fi = document.getElementById('hist-filter');
    if (fi && fi.value) filterTable(fi.value, 'history-body', 'hist-count');
  } catch (e) { tbody.innerHTML = empty(`ERROR: ${e.message}`); }
}

// ── Charts ────────────────────────────────────────
function renderDonut(b) {
  const ctx = document.getElementById('donut-chart');
  if (!ctx) return;
  if (donutChart) donutChart.destroy();
  const vals = [num(b.CRITICAL), num(b.HIGH), num(b.MEDIUM), num(b.LOW)];
  const total = vals.reduce((a,v)=>a+v,0);
  donutChart = new Chart(ctx.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{ data: vals, backgroundColor: ['#ff1744','#ff9100','#ffd600','#00e676'], borderColor:'#090c10', borderWidth:3 }]
    },
    options: {
      cutout: '84%',
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw} (${total?((ctx.raw/total)*100).toFixed(0):0}%)` } }
      }
    }
  });
}

function renderTimeline(data) {
  const ctx = document.getElementById('timeline-chart');
  if (!ctx) return;
  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(ctx.getContext('2d'), {
    type: 'line',
    data: {
      labels: data.map(d=>d.date),
      datasets: [
        { label:'Critical', data:data.map(d=>d.critical), borderColor:'#ff1744', borderWidth:2, tension:0.4, pointRadius:0, fill:true, backgroundColor:'rgba(255,23,68,0.07)' },
        { label:'High',     data:data.map(d=>d.high),     borderColor:'#ff9100', borderWidth:2, tension:0.4, pointRadius:0, fill:true, backgroundColor:'rgba(255,145,0,0.05)' },
        { label:'Medium',   data:data.map(d=>d.medium),   borderColor:'#ffd600', borderWidth:1, tension:0.4, pointRadius:0 },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode:'index', intersect:false },
      plugins: { legend: { display:true, position:'bottom', labels:{ color:'#3d4550', font:{family:'JetBrains Mono',size:9}, boxWidth:8, padding:10 } } },
      scales: {
        x: { grid:{display:false}, ticks:{color:'#3d4550', font:{family:'JetBrains Mono',size:9}} },
        y: { ticks:{color:'#3d4550', font:{family:'JetBrains Mono',size:9}}, grid:{color:'rgba(255,255,255,0.02)'}, beginAtZero:true }
      }
    }
  });
}

function renderTopPkgs(list) {
  const tbody = document.getElementById('top-pkg-body');
  if (!tbody) return;
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:var(--text-3);padding:20px;font-family:var(--mono);font-size:11px;text-align:center">[EMPTY] — EXECUTE_SCAN_TO_POPULATE</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(p => `
    <tr style="cursor:pointer" onclick="navigate('vulnerabilities',document.querySelector('[data-page=vulnerabilities]'))">
      <td style="color:var(--text)">${p.package_name}</td>
      <td style="color:var(--cyan);font-weight:700">${p.count}</td>
      <td>${chip(p.max_severity)}</td>
    </tr>`).join('');
}

// ── Modal ─────────────────────────────────────────
function openModal()  { document.getElementById('modal').style.display='flex'; }
function closeModal() { document.getElementById('modal').style.display='none'; }

function selectScanType(type, el) {
  selectedScanType = type;
  document.querySelectorAll('.scan-type-card').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  // Hide range input for packages-only scan
  const rangeGroup = document.getElementById('range-group');
  const targetRow  = document.getElementById('target-row');
  if (type === 'packages') {
    rangeGroup.style.opacity = '0.3';
    rangeGroup.querySelector('input').disabled = true;
    targetRow.style.gridTemplateColumns = '1fr';
  } else {
    rangeGroup.style.opacity = '1';
    rangeGroup.querySelector('input').disabled = false;
    targetRow.style.gridTemplateColumns = '2fr 1fr';
  }
}

// ── Scan execution ────────────────────────────────
async function startScan() {
  const target = document.getElementById('scan-target')?.value?.trim();
  const range  = document.getElementById('scan-range')?.value?.trim();
  if (!target && selectedScanType !== 'packages') return;
  closeModal();

  const consoleEl = document.getElementById('scan-console');
  const outputEl  = document.getElementById('console-output');
  if (consoleEl) consoleEl.style.display = 'flex';
  if (outputEl)  outputEl.innerHTML = '';

  updateProgress(0, 'INITIALIZING...');
  log(`[BOOT]  SCAN_MODE=${selectedScanType.toUpperCase()}`, 'cyan');
  if (selectedScanType !== 'packages') log(`[INIT]  TARGET=${target}  RANGE=${range}`, 'cyan');
  log('[INFO]  CONNECTING_TO_RUST_ENGINE...', 'dim');

  try {
    const payload = { target: target || '127.0.0.1', port_range: range, scan_type: selectedScanType };
    const res  = await fetch(`${API}/scan/full`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'API_REJECTED');

    activeScanId = json.scan_id;
    log(`[OK]    SESSION_ID=${activeScanId.substring(0,8)}...`, 'green');
    log('[INFO]  POLLING_STATUS_EVERY_3s', 'dim');
    pollStatus();
  } catch (e) {
    log(`[FATAL] ${e.message}`, 'red');
    setTimeout(() => { if(consoleEl) consoleEl.style.display='none'; }, 5000);
  }
}

// ── Console state ──────────────────────────────
let consoleFilter = 'all';
const logTagGroups = {
  info:  ['INFO','INIT','BOOT','POLL'],
  ok:    ['OK'],
  warn:  ['RSLT','WARN','TIMEOUT'],
  error: ['FATAL','ERROR'],
};

function setConsoleFilter(filter, btn) {
  consoleFilter = filter;
  document.querySelectorAll('.console-filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const out = document.getElementById('console-output');
  if (!out) return;
  out.querySelectorAll('.log-line').forEach(line => {
    const tag = line.dataset.tag || '';
    line.style.display = shouldShowLine(tag) ? '' : 'none';
  });
}

function shouldShowLine(tag) {
  if (consoleFilter === 'all') return true;
  return (logTagGroups[consoleFilter] || []).includes(tag.toUpperCase());
}

function clearConsole() {
  const out = document.getElementById('console-output');
  if (out) out.innerHTML = '';
}

function log(msg, color='white') {
  const out = document.getElementById('console-output');
  if (!out) return;

  const line = document.createElement('div');
  line.className = 'log-line';

  // Parse log type prefix [TAG]
  const tagMatch = msg.match(/^\[(\w+)\]/);
  const tag  = tagMatch ? tagMatch[1].toUpperCase() : '';
  const rest = tagMatch ? msg.substring(tagMatch[0].length).trimStart() : msg;
  line.dataset.tag = tag;

  const tagStyles = {
    BOOT:    { bg:'rgba(0,229,255,0.12)',  color:'var(--cyan)',  border:'rgba(0,229,255,0.3)' },
    INIT:    { bg:'rgba(0,229,255,0.08)',  color:'var(--cyan)',  border:'rgba(0,229,255,0.2)' },
    INFO:    { bg:'rgba(41,121,255,0.12)', color:'var(--blue)',  border:'rgba(41,121,255,0.3)' },
    OK:      { bg:'rgba(0,230,118,0.12)',  color:'var(--green)', border:'rgba(0,230,118,0.3)' },
    FATAL:   { bg:'rgba(255,23,68,0.14)',  color:'var(--red)',   border:'rgba(255,23,68,0.3)' },
    ERROR:   { bg:'rgba(255,23,68,0.14)',  color:'var(--red)',   border:'rgba(255,23,68,0.3)' },
    WARN:    { bg:'rgba(255,145,0,0.12)',  color:'var(--amber)', border:'rgba(255,145,0,0.3)' },
    POLL:    { bg:'rgba(255,255,255,0.04)',color:'var(--text-3)',border:'rgba(255,255,255,0.08)' },
    RSLT:    { bg:'rgba(255,145,0,0.1)',   color:'var(--amber)', border:'rgba(255,145,0,0.25)' },
    TIMEOUT: { bg:'rgba(255,23,68,0.14)',  color:'var(--red)',   border:'rgba(255,23,68,0.3)' },
  };

  const colors = { cyan:'var(--cyan)', green:'var(--green)', red:'var(--red)', amber:'var(--amber)', dim:'var(--text-3)', white:'var(--text)' };
  const msgColor = colors[color] || 'var(--text)';

  // Timestamp
  const ts = document.createElement('span');
  ts.className = 'log-ts';
  ts.textContent = new Date().toLocaleTimeString('en-US', {hour12:false});
  line.appendChild(ts);

  // Badge
  const tc = tag && tagStyles[tag];
  if (tc) {
    const badge = document.createElement('span');
    badge.className = 'log-badge';
    badge.textContent = tag;
    badge.style.cssText = `background:${tc.bg};color:${tc.color};border:1px solid ${tc.border};`;
    line.appendChild(badge);
  }

  // Message text
  const text = document.createElement('span');
  text.className = 'log-msg';
  text.style.color = msgColor;
  text.textContent = rest;
  line.appendChild(text);

  if (!shouldShowLine(tag)) line.style.display = 'none';

  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

function updateProgress(pct, step) {
  const bar  = document.getElementById('scan-progress-bar');
  const perc = document.getElementById('console-percent');
  const stp  = document.getElementById('console-step');
  if (bar)  bar.style.width  = `${Math.min(pct,100)}%`;
  if (perc) perc.textContent = `${Math.min(pct,100)}%`;
  if (stp)  stp.textContent  = step;
}

function pollStatus() {
  let progress = 5, ticks = 0;
  pollInterval = setInterval(async () => {
    if (++ticks > 300) { clearInterval(pollInterval); log('[TIMEOUT] MAX_EXCEEDED','red'); return; }
    try {
      const json = await fetch(`${API}/scan/${activeScanId}/status`).then(r=>r.json());
      if (progress < 88) progress += 1;
      updateProgress(progress, `SCANNING...  OPEN_PORTS=${num(json.open_ports)}`);
      if (ticks % 5 === 0) log(`[POLL]  T+${ticks*3}s  PROGRESS=${progress}%`, 'dim');

      if (json.status === 'done') {
        clearInterval(pollInterval);
        updateProgress(100, 'SCAN_COMPLETE');
        log('[OK]    SCAN_COMPLETE — FLUSHING_RESULTS', 'green');
        const s = json.summary || {};
        if (s.total_vulnerabilities > 0) log(`[RSLT]  VULNS=${s.total_vulnerabilities}  CRIT=${s.critical||0}  HIGH=${s.high||0}`, 'amber');
        if (s.open_ports > 0) log(`[RSLT]  OPEN_PORTS=${s.open_ports}`, 'cyan');
        const tag = document.getElementById('scan-status-tag');
        if (tag) { tag.textContent = 'COMPLETE'; tag.style.color='var(--green)'; tag.style.borderColor='rgba(0,230,118,0.4)'; }
        setTimeout(async () => {
          document.getElementById('scan-console').style.display='none';
          const tag2 = document.getElementById('scan-status-tag');
          if (tag2) { tag2.textContent='RUNNING'; tag2.style.color='var(--cyan)'; tag2.style.borderColor='rgba(0,229,255,0.4)'; }
          const dashEl = document.querySelector('[data-page="dashboard"]');
          navigate('dashboard', dashEl);
          await new Promise(r => setTimeout(r, 120));
          await loadDashboard();
        }, 2000);

      } else if (json.status === 'error') {
        clearInterval(pollInterval);
        updateProgress(progress, 'EXECUTION_FAILED');
        log('[FATAL] ENGINE_RETURNED_ERROR', 'red');
        setTimeout(async () => {
          document.getElementById('scan-console').style.display='none';
          await loadDashboard(); await loadHistory();
        }, 4000);
      }
    } catch(e) { clearInterval(pollInterval); log(`[ERROR] POLL_FAILED: ${e.message}`, 'red'); }
  }, 3000);
}

// ── Auth guard ────────────────────────────────────────
(function checkAuth() {
  const token = localStorage.getItem('vc_token');
  if (!token && !window.location.pathname.includes('login')) {
    window.location.href = '/login';
    return;
  }
})();

// Intercepta todos los fetch para agregar Authorization automáticamente
const _fetch = window.fetch;
window.fetch = function(url, opts = {}) {
  const token = localStorage.getItem('vc_token');
  if (token && typeof url === 'string' && url.startsWith('/api')) {
    opts.headers = { ...(opts.headers || {}), 'Authorization': 'Bearer ' + token };
  }
  return _fetch(url, opts).then(res => {
    if (res.status === 401) {
      localStorage.removeItem('vc_token');
      window.location.href = '/login';
    }
    return res;
  });
};

function logout() {
  localStorage.removeItem('vc_token');
  localStorage.removeItem('vc_user');
  window.location.href = '/login';
}

function exportReport(format) {
  window.open(`/api/reports/last/export?format=${format}`, '_blank');
}

// En DOMContentLoaded, mostrar el usuario:
const userEl = document.getElementById('sys-user');
if (userEl) userEl.textContent = localStorage.getItem('vc_user') || 'admin';