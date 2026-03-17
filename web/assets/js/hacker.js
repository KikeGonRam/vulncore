const API = '/api';
let donutChart = null, timelineChart = null;
let allPkgs = [], activeScanId = null, pollInterval = null;

// ── Helpers ───────────────────────────────────────────
// Safely convert any value to string (GORM IDs can be uint numbers)
function str(v)     { return v != null ? String(v) : ''; }
function num(v, d)  { return v != null ? v : (d ?? 0); }

function sevBg(s)   { return {CRITICAL:'rgba(255,62,62,0.15)',HIGH:'rgba(255,170,0,0.15)',MEDIUM:'rgba(255,213,0,0.1)',LOW:'rgba(0,255,102,0.1)'}[s]||'rgba(255,255,255,0.05)'; }
function sevFg(s)   { return {CRITICAL:'#ff3e3e',HIGH:'#ffaa00',MEDIUM:'#ffd500',LOW:'#00ff66'}[s]||'#888'; }

function chip(sev) {
  const s = str(sev).toUpperCase().replace(/[^A-Z]/g,'') || 'UNKNOWN';
  const label = {CRITICAL:'CRITICAL',HIGH:'HIGH',MEDIUM:'MEDIUM',LOW:'LOW'}[s] || s;
  return `<span style="font-family:var(--font-mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;background:${sevBg(label)};color:${sevFg(label)};">${label}</span>`;
}

function empty(msg) {
  return `<tr><td colspan="99" style="color:var(--text-dim);padding:20px;font-family:var(--font-mono);font-size:11px;text-align:center;">${msg}</td></tr>`;
}

// Read a field that might be PascalCase (Go) or snake_case (JSON)
function gf(obj, ...keys) {
  for (const k of keys) {
    if (obj[k] != null) return obj[k];
  }
  return null;
}

document.addEventListener('DOMContentLoaded', () => {
  setupNav();
  loadDashboard();
});

// ── Navigation ────────────────────────────────────────
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
      fetch(`${API}/dashboard/stats`).then(r => r.json()),
      fetch(`${API}/dashboard/timeline`).then(r => r.json()),
    ]);

    const b = stats.severity_breakdown || {};
    setEl('stat-exploited', num(stats.total_exploited));
    setEl('stat-risky',     num(stats.high_risk_count));
    setEl('stat-critical',  num(b.CRITICAL));
    setEl('stat-ports',     num(stats.total_open_ports));
    setEl('nav-vuln-count', num(b.CRITICAL) + num(b.HIGH));
    setEl('nav-port-count', num(stats.total_open_ports));

    renderDonut(b);
    renderTimeline(tl.data || []);
    renderTopPkgs(stats.top_vulnerable_packages || []);
  } catch (e) {
    console.error('Dashboard load error:', e);
    ['stat-exploited','stat-risky','stat-critical','stat-ports'].forEach(id => setEl(id, '—'));
    renderDonut({});
    renderTimeline([]);
    renderTopPkgs([]);
  }
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '0';
}

// ── Vulnerabilities ───────────────────────────────────
async function loadVulns() {
  const tbody = document.getElementById('vuln-body');
  if (!tbody) return;
  tbody.innerHTML = empty('QUERYING_THREAT_DATABASE...');

  try {
    const json = await fetch(`${API}/vulnerabilities?limit=300`).then(r => r.json());
    const data = json.data || [];

    if (!data.length) {
      tbody.innerHTML = empty('NO_THREATS_DETECTED — RUN_SCAN_TO_POPULATE');
      return;
    }

    tbody.innerHTML = data.map(v => {
      const sev = str(gf(v,'severity','Severity')).toUpperCase();
      const cve = str(gf(v,'cve_id','CveID'));
      const pkg = str(gf(v,'package_name','PackageName'));
      const ins = str(gf(v,'installed_version','InstalledVersion'));
      const fix = str(gf(v,'fixed_version','FixedVersion') || '---');
      const cvss = gf(v,'cvss_score','CvssScore');
      const kev  = gf(v,'is_exploited','IsExploited') ? '<span style="color:var(--red);font-size:9px;font-weight:700;padding:1px 5px;border:1px solid var(--red);border-radius:2px;">KEV</span>' : '';
      return `<tr>
        <td style="color:var(--cyan);font-weight:700;font-family:var(--font-mono)">${cve} ${kev}</td>
        <td style="font-family:var(--font-mono)">${pkg}</td>
        <td style="color:var(--text-dim);font-family:var(--font-mono)">${ins}</td>
        <td style="color:var(--green);font-family:var(--font-mono)">${fix}</td>
        <td style="font-family:var(--font-mono)">${cvss ? Number(cvss).toFixed(1) : '—'}</td>
        <td>${chip(sev)}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = empty(`SYNC_ERROR: ${e.message}`);
  }
}

// ── Ports ─────────────────────────────────────────────
async function loadPorts() {
  const tbody = document.getElementById('ports-body');
  if (!tbody) return;
  tbody.innerHTML = empty('QUERYING_PORT_TABLE...');

  try {
    const json = await fetch(`${API}/reports/last`).then(r => r.json());

    if (!json.scan) {
      tbody.innerHTML = empty('NO_COMPLETED_SCANS — RUN_SCAN_FIRST');
      return;
    }

    // GORM returns lowercase state from SQLite
    const ports = (json.ports || []).filter(p => {
      const state = str(gf(p,'state','State')).toLowerCase();
      return state === 'open';
    });

    if (!ports.length) {
      tbody.innerHTML = empty('NO_OPEN_PORTS_FOUND_IN_LAST_SCAN');
      return;
    }

    tbody.innerHTML = ports.map(p => {
      const port    = gf(p,'Port','port');
      const proto   = str(gf(p,'Protocol','protocol') || 'tcp');
      const service = str(gf(p,'Service','service') || '---');
      const version = str(gf(p,'Version','version') || '---');
      const banner  = str(gf(p,'Banner','banner') || '---');
      return `<tr>
        <td style="color:var(--cyan);font-family:var(--font-mono);font-weight:700">${port}</td>
        <td style="color:var(--text-dim)">${proto}</td>
        <td style="color:var(--green)">OPEN</td>
        <td style="font-family:var(--font-mono)">${service}</td>
        <td style="color:var(--text-dim);font-family:var(--font-mono)">${version}</td>
        <td style="color:var(--text-dim);font-size:10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${banner}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = empty(`SYNC_ERROR: ${e.message}`);
  }
}

// ── Packages ──────────────────────────────────────────
async function loadPackages() {
  const tbody = document.getElementById('pkg-body');
  if (!tbody) return;
  tbody.innerHTML = empty('QUERYING_PACKAGE_INVENTORY...');

  try {
    const json = await fetch(`${API}/reports/last`).then(r => r.json());
    allPkgs = json.packages || [];

    if (!json.scan) {
      tbody.innerHTML = empty('NO_COMPLETED_SCANS — RUN_SCAN_FIRST');
      return;
    }

    if (!allPkgs.length) {
      tbody.innerHTML = empty('NO_PACKAGES_FOUND');
      return;
    }

    renderPkgs(allPkgs);
  } catch (e) {
    tbody.innerHTML = empty(`SYNC_ERROR: ${e.message}`);
  }
}

function renderPkgs(list) {
  const tbody = document.getElementById('pkg-body');
  if (!tbody) return;
  tbody.innerHTML = list.slice(0, 400).map(p => {
    const name    = str(gf(p,'Name','name'));
    const version = str(gf(p,'Version','version'));
    const arch    = str(gf(p,'Arch','arch') || '---');
    const mgr     = str(gf(p,'Manager','manager'));
    return `<tr>
      <td style="font-family:var(--font-mono)">${name}</td>
      <td style="color:var(--green);font-family:var(--font-mono)">${version}</td>
      <td style="color:var(--text-dim)">${arch}</td>
      <td style="color:var(--text-dim)">${mgr}</td>
    </tr>`;
  }).join('');
}

// ── History ───────────────────────────────────────────
async function loadHistory() {
  const tbody = document.getElementById('history-body');
  if (!tbody) return;
  tbody.innerHTML = empty('READING_AUDIT_LOG...');

  try {
    const json = await fetch(`${API}/history`).then(r => r.json());
    const data = json.data || [];

    if (!data.length) {
      tbody.innerHTML = empty('NO_SCAN_HISTORY');
      return;
    }

    tbody.innerHTML = data.map(s => {
      // ID from GORM is uint — must convert to string before .substring
      const id       = str(gf(s,'ID','id')).substring(0, 8);
      const target   = str(gf(s,'target','Target') || '---');
      const scanType = str(gf(s,'scan_type','ScanType') || '---');
      const status   = str(gf(s,'status','Status') || 'unknown');
      const startRaw = gf(s,'started_at','StartedAt');
      const endRaw   = gf(s,'finished_at','FinishedAt');
      const started  = startRaw ? new Date(startRaw) : null;
      const dur      = (started && endRaw) ? ((new Date(endRaw) - started) / 1000).toFixed(0) + 's' : '---';
      const startStr = started ? started.toLocaleString() : '---';
      const vulnCnt  = num(gf(s,'vuln_count','VulnCount'));
      const portCnt  = num(gf(s,'port_count','PortCount'));
      const statusColor = {done:'var(--green)',error:'var(--red)',running:'var(--cyan)'}[status] || 'var(--text-dim)';

      return `<tr>
        <td style="color:var(--text-dim);font-family:var(--font-mono)">${id}…</td>
        <td>${target}</td>
        <td style="color:var(--text-dim)">${scanType}</td>
        <td style="color:${statusColor}">${status.toUpperCase()}</td>
        <td style="color:var(--text-dim);font-size:11px">${startStr}</td>
        <td style="font-family:var(--font-mono)">${dur}</td>
        <td style="font-family:var(--font-mono);color:${vulnCnt>0?'var(--red)':'var(--text-dim)'}">${vulnCnt}</td>
        <td style="font-family:var(--font-mono)">${portCnt}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = empty(`SYNC_ERROR: ${e.message}`);
  }
}

// ── Charts ────────────────────────────────────────────
function renderDonut(b) {
  const ctx = document.getElementById('donut-chart');
  if (!ctx) return;
  if (donutChart) donutChart.destroy();
  const vals = [num(b.CRITICAL), num(b.HIGH), num(b.MEDIUM), num(b.LOW)];
  const total = vals.reduce((a, v) => a + v, 0);

  donutChart = new Chart(ctx.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{
        data: vals,
        backgroundColor: ['#ff3e3e','#ffaa00','#ffd500','#00ff66'],
        borderColor: '#050608',
        borderWidth: 3,
      }],
    },
    options: {
      cutout: '82%',
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.raw} (${total ? ((ctx.raw/total)*100).toFixed(0) : 0}%)`
          }
        }
      },
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
        { label:'Critical', data:data.map(d=>d.critical), borderColor:'#ff3e3e', borderWidth:2, tension:0.4, pointRadius:0, fill:true, backgroundColor:'rgba(255,62,62,0.06)' },
        { label:'High',     data:data.map(d=>d.high),     borderColor:'#ffaa00', borderWidth:2, tension:0.4, pointRadius:0, fill:true, backgroundColor:'rgba(255,170,0,0.04)' },
        { label:'Medium',   data:data.map(d=>d.medium),   borderColor:'#ffd500', borderWidth:1, tension:0.4, pointRadius:0 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode:'index', intersect:false },
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
          labels: { color:'#606060', font:{ family:'JetBrains Mono', size:9 }, boxWidth:10, padding:12 }
        }
      },
      scales: {
        x: { grid:{ display:false }, ticks:{ color:'#404040', font:{family:'JetBrains Mono',size:9} } },
        y: { ticks:{ color:'#404040', font:{family:'JetBrains Mono',size:9} }, grid:{ color:'rgba(255,255,255,0.03)' }, beginAtZero:true },
      },
    },
  });
}

function renderTopPkgs(list) {
  const tbody = document.getElementById('top-pkg-body');
  if (!tbody) return;
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="3" style="color:var(--text-dim);padding:15px;font-size:11px;font-family:var(--font-mono);">[EMPTY] RUN_A_SCAN</td></tr>`;
    return;
  }
  tbody.innerHTML = list.map(p => `
    <tr style="cursor:pointer;" onclick="filterVulnsByPkg('${p.package_name}')">
      <td style="font-family:var(--font-mono);font-weight:600">${p.package_name}</td>
      <td style="color:var(--cyan);font-family:var(--font-mono);font-weight:700">${p.count}</td>
      <td>${chip(p.max_severity)}</td>
    </tr>`).join('');
}

function filterVulnsByPkg(name) {
  navigate('vulnerabilities', document.querySelector('[data-page="vulnerabilities"]'));
  // No filter input in hacker view — just navigate to threats
}

// ── Modal & Scan ──────────────────────────────────────
function openModal()  { const m = document.getElementById('modal'); if(m) m.style.display='flex'; }
function closeModal() { const m = document.getElementById('modal'); if(m) m.style.display='none'; }

async function startScan() {
  const target = document.getElementById('scan-target')?.value?.trim();
  const range  = document.getElementById('scan-range')?.value?.trim();
  if (!target) { log('[ERROR] TARGET_REQUIRED', 'red'); return; }
  closeModal();

  const consoleEl = document.getElementById('scan-console');
  const outputEl  = document.getElementById('console-output');
  if (consoleEl) consoleEl.style.display = 'flex';
  if (outputEl)  outputEl.innerHTML = '';

  updateProgress(0, 'INITIATING_SCAN_SEQUENCE...');
  log(`[INIT] TARGET=${target}  RANGE=${range}`, 'cyan');
  log(`[INFO] CONNECTING_TO_RUST_ENGINE...`, 'dim');

  try {
    const res  = await fetch(`${API}/scan/full`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, port_range: range }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'API_REJECTED');

    activeScanId = json.scan_id;
    log(`[OK]   SESSION_ID=${activeScanId.substring(0,8)}...`, 'green');
    log(`[INFO] POLLING_ENGINE_STATUS_EVERY_3s`, 'dim');
    pollStatus();
  } catch (e) {
    log(`[FATAL] ${e.message}`, 'red');
    setTimeout(() => { if(consoleEl) consoleEl.style.display='none'; }, 5000);
  }
}

function log(msg, color = 'white') {
  const out = document.getElementById('console-output');
  if (!out) return;
  const line = document.createElement('div');
  const colors = { cyan:'var(--cyan)', green:'var(--green)', red:'var(--red)', gold:'var(--gold)', dim:'var(--text-dim)', white:'var(--text)' };
  line.style.color = colors[color] || 'var(--text)';
  line.textContent = `> ${new Date().toLocaleTimeString('en-US',{hour12:false})}  ${msg}`;
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

function updateProgress(pct, step) {
  const bar  = document.getElementById('scan-progress-bar');
  const perc = document.getElementById('console-percent');
  const stp  = document.getElementById('console-step');
  if (bar)  bar.style.width = `${Math.min(pct,100)}%`;
  if (perc) perc.textContent = `${Math.min(pct,100)}%`;
  if (stp)  stp.textContent  = step;
}

function pollStatus() {
  let progress = 5, ticks = 0;

  pollInterval = setInterval(async () => {
    if (++ticks > 300) { clearInterval(pollInterval); log('[TIMEOUT] MAX_POLL_EXCEEDED','red'); return; }

    try {
      const json = await fetch(`${API}/scan/${activeScanId}/status`).then(r => r.json());
      if (progress < 88) progress += 1;

      const openPorts = num(json.open_ports);
      updateProgress(progress, `SCANNING...  OPEN=${openPorts}`);

      if (ticks % 5 === 0) {
        log(`[SCAN] PROGRESS=${progress}%  OPEN_PORTS=${openPorts}`, 'dim');
      }

      if (json.status === 'done') {
        clearInterval(pollInterval);
        updateProgress(100, 'SCAN_COMPLETE — FLUSHING_DATA');
        log('[OK]   SCAN_FINISHED_SUCCESSFULLY', 'green');

        const summary = json.summary || {};
        if (summary.total_vulnerabilities > 0) {
          log(`[RSLT] VULNS=${summary.total_vulnerabilities}  CRIT=${summary.critical||0}  HIGH=${summary.high||0}`, 'gold');
        }
        if (summary.open_ports > 0) {
          log(`[RSLT] OPEN_PORTS=${summary.open_ports}`, 'cyan');
        }

        const tag = document.getElementById('scan-status-tag');
        if (tag) { tag.textContent = 'COMPLETED'; tag.style.color = 'var(--green)'; tag.style.borderColor = 'var(--green)'; }

        // Esperar a que los writes del goroutine terminen antes de refrescar
        setTimeout(async () => {
          const c = document.getElementById('scan-console');
          if (c) c.style.display = 'none';
          const tag2 = document.getElementById('scan-status-tag');
          if (tag2) { tag2.textContent = 'ACTIVE'; tag2.style.color = 'var(--cyan)'; tag2.style.borderColor = 'var(--cyan)'; }

          // Navegar a dashboard PRIMERO — las gráficas necesitan canvas visible
          const dashEl = document.querySelector('[data-page="dashboard"]');
          navigate('dashboard', dashEl);

          // Dar un tick al DOM para que el canvas sea visible antes de renderizar
          await new Promise(r => setTimeout(r, 100));
          await loadDashboard();
        }, 2000);

      } else if (json.status === 'error') {
        clearInterval(pollInterval);
        updateProgress(progress, 'ENGINE_HALTED');
        log('[FATAL] SCAN_RETURNED_ERROR_STATE', 'red');
        setTimeout(async () => {
          const c = document.getElementById('scan-console');
          if (c) c.style.display = 'none';
          await loadDashboard();
          await loadHistory();
        }, 4000);
      }
    } catch (e) {
      clearInterval(pollInterval);
      log(`[ERROR] POLL_FAILED: ${e.message}`, 'red');
    }
  }, 3000);
}