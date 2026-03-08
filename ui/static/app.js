/**
 * Plasma V1 — app.js
 * Real-time scan monitoring via Server-Sent Events.
 * Supports all V1 CLI feature equivalents in the GUI.
 */

// ── State ──────────────────────────────────────────────────────────────────────
let currentScanId = null;
let sseSource     = null;
let _uploadedFilePath = null;
let _harFilePath      = null;
const activeDetectors = new Set();
const _counts  = { Critical: 0, High: 0, Medium: 0, Low: 0 };
const _logDedup = new Set();
let _lastProgress = 0;
let _findings = [];

const PHASE_STEPS = {
  crawl: 'ps-crawl', crawl_done: 'ps-crawl',
  recon: 'ps-recon', recon_done: 'ps-recon',
  legacy: 'ps-analyse', legacy_done: 'ps-analyse',
  detect: 'ps-detect', detect_progress: 'ps-detect', detect_done: 'ps-detect',
  fuzz: 'ps-fuzz', fuzz_done: 'ps-fuzz',
  websocket_fuzz: 'ps-fuzz',
  tls: 'ps-tls', tls_done: 'ps-tls',
  templates: 'ps-templates', templates_done: 'ps-templates',
  risk: 'ps-risk',
  reports: 'ps-report', pocs: 'ps-report',
};

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadDetectors();
  bindActions();
  bindToggleSubs();
});

// ── Detector chips ─────────────────────────────────────────────────────────────
async function loadDetectors() {
  const grid = document.getElementById('detector-list');
  try {
    const res  = await fetch('/api/detectors');
    const data = await res.json();
    grid.innerHTML = '';
    for (const det of (data.detectors || [])) {
      const chip = document.createElement('div');
      chip.className = 'det-chip' + (det.enabled ? ' active' : '');
      chip.textContent = det.name;
      chip.title = det.description || det.name;
      chip.dataset.name = det.name;
      if (det.enabled) activeDetectors.add(det.name);
      chip.addEventListener('click', () => {
        chip.classList.toggle('active');
        activeDetectors[chip.classList.contains('active') ? 'add' : 'delete'](det.name);
      });
      grid.appendChild(chip);
    }
  } catch (e) {
    grid.innerHTML = '<span style="color:var(--critical);font-size:11px">Could not load detectors</span>';
  }
}

// ── Toggle sub-sections ────────────────────────────────────────────────────────
function bindToggleSubs() {
  document.getElementById('opt-browser').addEventListener('change', function () {
    document.getElementById('browser-sub').style.display = this.checked ? 'flex' : 'none';
  });
}

// ── Button bindings ────────────────────────────────────────────────────────────
function bindActions() {
  document.getElementById('btn-scan').addEventListener('click', startScan);
  document.getElementById('btn-pause').addEventListener('click', () => scanAction('pause'));
  document.getElementById('btn-cancel').addEventListener('click', () => scanAction('cancel'));
  document.getElementById('drawer-close').addEventListener('click', closeDrawer);
  document.getElementById('overlay').addEventListener('click', closeDrawer);
  document.getElementById('btn-clear-log').addEventListener('click', clearLog);
  document.getElementById('btn-export-json').addEventListener('click', exportFindings);

  // Upload file
  const fileInput = document.getElementById('upload-file-input');
  document.getElementById('btn-select-file').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (!file) return;
    _uploadedFilePath = null;
    document.getElementById('upload-file-label').textContent = file.name;
    document.getElementById('btn-clear-file').style.display = 'flex';
    uploadFile(file).then(path => { _uploadedFilePath = path; });
  });
  document.getElementById('btn-clear-file').addEventListener('click', () => {
    fileInput.value = '';
    _uploadedFilePath = null;
    document.getElementById('upload-file-label').textContent = 'No file selected';
    document.getElementById('btn-clear-file').style.display = 'none';
  });

  // HAR file
  const harInput = document.getElementById('har-file-input');
  document.getElementById('btn-select-har').addEventListener('click', () => harInput.click());
  harInput.addEventListener('change', () => {
    const file = harInput.files[0];
    if (!file) return;
    _harFilePath = null;
    document.getElementById('har-file-label').textContent = file.name;
    document.getElementById('btn-clear-har').style.display = 'flex';
    uploadFile(file).then(path => { _harFilePath = path; });
  });
  document.getElementById('btn-clear-har').addEventListener('click', () => {
    harInput.value = '';
    _harFilePath = null;
    document.getElementById('har-file-label').textContent = 'No file selected';
    document.getElementById('btn-clear-har').style.display = 'none';
  });
}

// ── File upload ────────────────────────────────────────────────────────────────
async function uploadFile(file) {
  const form = new FormData();
  form.append('file', file);
  try {
    const res  = await fetch('/api/upload-file', { method: 'POST', body: form });
    const data = await res.json();
    return data.path || null;
  } catch (e) {
    addLog('Upload failed: ' + e.message, 'error');
    return null;
  }
}

// ── Start scan ─────────────────────────────────────────────────────────────────
async function startScan() {
  const url = document.getElementById('target').value.trim();
  if (!url) { addLog('No target URL specified.', 'warn'); return; }

  resetState();

  const payload = {
    target:           url,
    profile:          document.getElementById('profile').value,
    depth:            parseInt(document.getElementById('depth').value, 10),
    timeout:          parseInt(document.getElementById('timeout').value, 10),
    detectors:        activeDetectors.size ? [...activeDetectors].join(',') : null,
    browser:          document.getElementById('opt-browser').checked,
    browser_parallel: parseInt(document.getElementById('browser-parallel').value, 10),
    fuzz:             document.getElementById('opt-fuzz').checked,
    fuzz_websocket:   document.getElementById('opt-ws-fuzz').checked,
    api_mode:         document.getElementById('opt-api').checked,
    bypass:           document.getElementById('opt-bypass').checked,
    http2:            document.getElementById('opt-http2').checked,
    subdomains:       document.getElementById('opt-subdomains').checked,
    subdomain_takeover: document.getElementById('opt-takeover').checked,
    param_discovery:  document.getElementById('opt-params').checked,
    tls_analysis:     document.getElementById('opt-tls').checked,
    test_cache_poisoning: document.getElementById('opt-cache').checked,
    har_file:         _harFilePath,
    auth_cookie:      document.getElementById('auth-cookie').value.trim() || null,
    collaborator:     document.getElementById('collaborator').value.trim() || null,
    upload_file:      _uploadedFilePath,
    gen_poc:          document.getElementById('gen-poc').checked,
    gen_report:       document.getElementById('gen-report').checked,
    jsonl_output:     document.getElementById('opt-jsonl').checked,
    save_scan:        document.getElementById('opt-save-scan').checked,
  };

  try {
    const res  = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await res.json();
    if (data.error) { addLog('Scan error: ' + data.error, 'error'); return; }
    currentScanId = data.scan_id;
    addLog(`Scan started: ${currentScanId}`, 'ok');
    document.getElementById('progress-text').textContent = 'Running...';
    startSSE(currentScanId);
  } catch (e) {
    addLog('Failed to start scan: ' + e.message, 'error');
  }
}

// ── SSE ────────────────────────────────────────────────────────────────────────
function startSSE(scanId) {
  if (sseSource) sseSource.close();
  sseSource = new EventSource('/api/scan/' + scanId + '/stream');

  sseSource.addEventListener('progress', e => {
    try { handleProgress(JSON.parse(e.data)); } catch (_) {}
  });
  sseSource.addEventListener('finding', e => {
    try { handleFinding(JSON.parse(e.data)); } catch (_) {}
  });
  sseSource.addEventListener('log', e => {
    try { addLog(JSON.parse(e.data).message); } catch (_) {}
  });
  sseSource.addEventListener('done', e => {
    try {
      const d = JSON.parse(e.data);
      addLog(`Scan complete. ${d.total_findings || 0} findings in ${d.duration_s || '?'}s`, 'ok');
      if (d.waf_provider) showWafBanner(d.waf_provider);
      document.getElementById('progress-text').textContent = 'Complete';
      setProgress(100);
    } catch (_) {}
    sseSource.close();
    sseSource = null;
  });
  sseSource.addEventListener('error', e => {
    if (sseSource && sseSource.readyState === EventSource.CLOSED) {
      addLog('Stream closed.', 'warn');
    }
  });
}

function handleProgress(data) {
  const pct  = data.percent || 0;
  const phase = data.phase || '';
  if (pct > _lastProgress) { setProgress(pct); _lastProgress = pct; }
  if (data.status) document.getElementById('progress-text').textContent = data.status;
  const stepId = PHASE_STEPS[phase];
  if (stepId) advancePhase(stepId, phase.endsWith('_done'));
  if (data.log) addLog(data.log);
}

function handleFinding(f) {
  _findings.push(f);
  const sev = (f.severity || 'INFO').toUpperCase();
  if (sev in _counts) { _counts[sev]++; updateCount(sev); }
  appendFindingRow(f);
}

// ── DOM helpers ────────────────────────────────────────────────────────────────
function setProgress(pct) {
  document.getElementById('progress-bar').style.width = Math.min(100, pct) + '%';
}

function advancePhase(stepId, done) {
  document.querySelectorAll('.phase-step.active').forEach(el => {
    if (done || el.id !== stepId) el.classList.replace('active', 'done');
  });
  const el = document.getElementById(stepId);
  if (el && !el.classList.contains('done')) el.classList.add('active');
}

function updateCount(sev) {
  const map = { Critical: 'cnt-critical', High: 'cnt-high', Medium: 'cnt-medium', Low: 'cnt-low' };
  const id  = map[sev] || map[sev.charAt(0) + sev.slice(1).toLowerCase()];
  if (id) document.getElementById(id).textContent = _counts[sev];
}

function appendFindingRow(f) {
  const tbody = document.getElementById('findings-body');
  // Remove empty-state row if present
  if (tbody.querySelector('.empty-state')) tbody.innerHTML = '';
  const sev   = (f.severity || 'INFO').toUpperCase();
  const tr    = document.createElement('tr');
  tr.innerHTML = `
    <td><span class="sev-badge sev-${sev}">${sev}</span></td>
    <td class="td-title">${esc(f.title || '')}</td>
    <td class="td-det">${esc(f.detector || '')}</td>
    <td class="td-url">${esc(f.url || f.evidence?.request_url || '')}</td>
  `;
  tr.addEventListener('click', () => openDrawer(f));
  tbody.appendChild(tr);
}

function openDrawer(f) {
  const body = document.getElementById('drawer-body');
  const sev  = (f.severity || 'INFO').toUpperCase();
  body.innerHTML = `
    <div class="drawer-section">
      <div class="drawer-section-label">Severity / Confidence</div>
      <div class="drawer-section-value">
        <span class="sev-badge sev-${sev}">${sev}</span>
        &nbsp;${esc(f.confidence || '')}
      </div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-label">Title</div>
      <div class="drawer-section-value">${esc(f.title || '')}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-label">Description</div>
      <div class="drawer-section-value">${esc(f.description || '')}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-label">URL</div>
      <div class="code-block">${esc(f.url || (f.evidence && f.evidence.request_url) || '')}</div>
    </div>
    ${f.evidence && f.evidence.payload_used ? `
    <div class="drawer-section">
      <div class="drawer-section-label">Payload</div>
      <div class="code-block">${esc(f.evidence.payload_used)}</div>
    </div>` : ''}
    ${f.evidence && f.evidence.response_body ? `
    <div class="drawer-section">
      <div class="drawer-section-label">Response excerpt</div>
      <div class="code-block">${esc(f.evidence.response_body.substring(0, 800))}</div>
    </div>` : ''}
    <div class="drawer-section">
      <div class="drawer-section-label">Remediation</div>
      <div class="drawer-section-value">${esc(f.remediation || 'See OWASP guidelines.')}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-label">Tags / References</div>
      <div class="drawer-section-value">${esc((f.tags || []).join(', '))}${f.owasp_id ? ' &bull; ' + esc(f.owasp_id) : ''}${f.cwe_id ? ' &bull; ' + esc(f.cwe_id) : ''}</div>
    </div>
  `;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}

function closeDrawer() {
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
}

function showWafBanner(provider) {
  const b = document.getElementById('waf-banner');
  document.getElementById('waf-text').textContent = `WAF detected: ${provider} — scan rate has been reduced automatically.`;
  b.classList.add('visible');
}

// ── Log ────────────────────────────────────────────────────────────────────────
function addLog(msg, type = '') {
  if (_logDedup.has(msg)) return;
  _logDedup.add(msg);
  const el  = document.getElementById('log-output');
  const ts  = new Date().toTimeString().slice(0, 8);
  const div = document.createElement('div');
  div.className = 'log-line' + (type ? ' log-' + type : '');
  div.innerHTML = `<span class="log-ts">[${ts}]</span>${esc(String(msg))}`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function clearLog() {
  document.getElementById('log-output').innerHTML = '';
  _logDedup.clear();
}

// ── Scan controls ──────────────────────────────────────────────────────────────
async function scanAction(action) {
  if (!currentScanId) return;
  try { await fetch('/api/scan/' + currentScanId + '/' + action, { method: 'POST' }); }
  catch (e) { addLog('Action failed: ' + e.message, 'error'); }
}

// ── Export ─────────────────────────────────────────────────────────────────────
function exportFindings() {
  if (!_findings.length) { addLog('No findings to export.', 'warn'); return; }
  const blob = new Blob([JSON.stringify({ findings: _findings }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `plasma-findings-${Date.now()}.json`;
  a.click();
}

// ── Reset ──────────────────────────────────────────────────────────────────────
function resetState() {
  _counts.Critical = _counts.High = _counts.Medium = _counts.Low = 0;
  ['cnt-critical','cnt-high','cnt-medium','cnt-low'].forEach(id => {
    document.getElementById(id).textContent = '0';
  });
  document.getElementById('findings-body').innerHTML =
    '<tr><td colspan="4"><div class="empty-state">Scanning...</div></td></tr>';
  document.querySelectorAll('.phase-step').forEach(el => {
    el.classList.remove('active', 'done', 'error');
  });
  setProgress(0);
  _lastProgress = 0;
  _findings = [];
  document.getElementById('waf-banner').classList.remove('visible');
  _logDedup.clear();
}

// ── Utilities ──────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
