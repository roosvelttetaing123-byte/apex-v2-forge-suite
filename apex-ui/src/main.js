// main.js - APEX UI Logic

document.addEventListener('DOMContentLoaded', () => {
  const btnA = document.getElementById('btn-zone-a');
  const btnB = document.getElementById('btn-zone-b');
  const btnC = document.getElementById('btn-zone-c');
  const zoneA = document.getElementById('zone-a');
  const zoneB = document.getElementById('zone-b');
  const zoneC = document.getElementById('zone-c');

  function switchZone(activeBtn, activeZone) {
    [btnA, btnB, btnC].forEach(btn => btn.classList.remove('active'));
    [zoneA, zoneB, zoneC].forEach(zone => zone.classList.remove('active'));
    activeBtn.classList.add('active');
    activeZone.classList.add('active');
  }

  btnA.addEventListener('click', () => switchZone(btnA, zoneA));
  btnB.addEventListener('click', () => switchZone(btnB, zoneB));
  btnC.addEventListener('click', () => switchZone(btnC, zoneC));

  // APK Upload Drag and Drop
  const dropzone = document.getElementById('apk-dropzone');
  const fileInput = document.getElementById('apk-file-input');

  if (dropzone) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
      e.preventDefault();
      e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, () => dropzone.classList.add('highlight'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, () => dropzone.classList.remove('highlight'), false);
    });

    dropzone.addEventListener('drop', (e) => handleFiles(e.dataTransfer.files), false);
    fileInput.addEventListener('change', function() { handleFiles(this.files); });

    function handleFiles(files) {
      if (files.length > 0) {
        const file = files[0];
        if (file.name.endsWith('.apk')) {
          dropzone.innerHTML = `
            <svg class="upload-icon" viewBox="0 0 24 24" fill="none" stroke="var(--status-green)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            <h3 style="color: var(--status-green)">${escapeHtml(file.name)}</h3>
            <p class="upload-subtitle">Ready for decompilation and analysis</p>
            <button class="scan-btn" style="margin-top: 16px;">Initiate Static Analysis</button>
          `;
        } else {
          alert('Please upload a valid .apk file.');
        }
      }
    }
  }

  // ── Terminal Logging ───────────────────────────────────────────────
  const terminalBody = document.getElementById('terminal-body');

  function addLog(text, logClass = '', isPrompt = false) {
    if (!terminalBody) return;
    const cursor = terminalBody.querySelector('.cursor-blink');
    if (cursor) cursor.remove();

    const div = document.createElement('div');
    div.className = 'log-line';
    if (logClass) div.classList.add(logClass);

    if (isPrompt) {
      div.innerHTML = `<span class="prompt">apex></span> ${escapeHtml(text)}`;
    } else {
      div.innerText = text;
    }

    terminalBody.appendChild(div);

    const newCursor = document.createElement('div');
    newCursor.className = 'log-line cursor-blink';
    newCursor.innerText = '_';
    terminalBody.appendChild(newCursor);
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  // ── Live Data Helpers ──────────────────────────────────────────────
  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function setScanStatus(visible, phase, module) {
    const bar = document.getElementById('scan-status-bar');
    if (!bar) return;
    bar.style.display = visible ? 'flex' : 'none';
    if (phase !== null && phase !== undefined) {
      const el = document.getElementById('scan-phase-text');
      if (el) el.textContent = `PHASE: ${String(phase).toUpperCase()}`;
    }
    if (module !== null && module !== undefined) {
      const el = document.getElementById('scan-module-text');
      if (el) el.textContent = `MODULE: ${module}`;
    }
  }

  function setMetricCount(severity, value) {
    const sev = (severity || '').toLowerCase();
    const el = document.querySelector(`.metric-card.${sev} .metric-value`);
    if (el) el.textContent = value;
  }

  function incrementMetric(severity) {
    const sev = (severity || '').toLowerCase();
    const el = document.querySelector(`.metric-card.${sev} .metric-value`);
    if (el) el.textContent = (parseInt(el.textContent) || 0) + 1;
  }

  function initMetricsFromFindings(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      const sev = (f.severity || '').toLowerCase();
      if (sev in counts) counts[sev]++;
    }
    for (const [sev, count] of Object.entries(counts)) {
      setMetricCount(sev, count);
    }
  }

  // ── Severity Filter ───────────────────────────────────────────────
  let activeFilter = null;

  function applySeverityFilter(sev) {
    const tbody = document.getElementById('findings-tbody');
    if (!tbody) return;

    // Toggle off if same card clicked again
    if (activeFilter === sev) {
      activeFilter = null;
    } else {
      activeFilter = sev;
    }

    // Update card visual state
    document.querySelectorAll('.metric-card').forEach(card => {
      if (activeFilter && card.classList.contains(activeFilter)) {
        card.classList.add('filter-active');
      } else {
        card.classList.remove('filter-active');
      }
    });

    // Show/hide rows
    let visibleCount = 0;
    tbody.querySelectorAll('tr.clickable-row').forEach(row => {
      const match = !activeFilter || row.dataset.severity === activeFilter;
      row.style.display = match ? '' : 'none';
      if (match) visibleCount++;
    });

    // Show/hide empty-state placeholder
    const placeholder = document.getElementById('no-findings-row');
    if (placeholder) {
      placeholder.style.display = visibleCount === 0 ? '' : 'none';
      if (visibleCount === 0) {
        placeholder.querySelector('td').textContent = activeFilter
          ? `No ${activeFilter} findings`
          : 'No findings yet — start a scan to populate live data';
      }
    }
  }

  // Wire metric cards to filter
  document.querySelectorAll('.metric-card').forEach(card => {
    const sev = ['critical', 'high', 'medium', 'low'].find(s => card.classList.contains(s));
    if (!sev) return;
    card.style.cursor = 'pointer';
    card.addEventListener('click', () => applySeverityFilter(sev));
  });

  const SEV_TAG = { critical: 'crimson', high: 'orange', medium: 'cyan', low: '', info: '', informational: '' };

  // ── Finding Detail Panel ───────────────────────────────────────────
  const detailPanel   = document.getElementById('detail-panel');
  const detailOverlay = document.getElementById('detail-overlay');

  function openDetail(finding) {
    const sev = (finding.severity || 'info').toLowerCase();
    const tagColor = SEV_TAG[sev] || '';

    document.getElementById('detail-title').textContent      = finding.title || 'Untitled Finding';
    const badge = document.getElementById('detail-severity-badge');
    badge.textContent  = sev.toUpperCase();
    badge.className    = tagColor ? `tag ${tagColor}` : 'tag';
    document.getElementById('detail-cvss').textContent       = finding.cvss_score ? `CVSS ${finding.cvss_score}` : 'CVSS —';
    document.getElementById('detail-target').textContent     = finding.target || '—';
    document.getElementById('detail-module').textContent     = finding.module || '—';
    document.getElementById('detail-description').textContent = finding.description || 'No description provided.';

    const urlField = document.getElementById('detail-url-field');
    if (finding.url) {
      document.getElementById('detail-url').textContent = finding.url;
      urlField.style.display = '';
    } else {
      urlField.style.display = 'none';
    }

    const mitreField = document.getElementById('detail-mitre-field');
    const mitreEl    = document.getElementById('detail-mitre');
    const mitreList  = finding.mitre || [];
    if (mitreList.length > 0) {
      mitreEl.innerHTML = mitreList.map(m => `<span class="mitre-chip">${escapeHtml(m)}</span>`).join('');
      mitreField.style.display = '';
    } else {
      mitreField.style.display = 'none';
    }

    const ts = finding.timestamp ? new Date(finding.timestamp).toLocaleString() : '—';
    document.getElementById('detail-timestamp').textContent = ts;

    detailPanel.classList.add('open');
    detailOverlay.classList.add('open');
  }

  function closeDetail() {
    detailPanel.classList.remove('open');
    detailOverlay.classList.remove('open');
  }

  document.getElementById('detail-close-btn').addEventListener('click', closeDetail);
  detailOverlay.addEventListener('click', closeDetail);

  function addFindingRow(finding) {
    const tbody = document.getElementById('findings-tbody');
    if (!tbody) return;
    const placeholder = document.getElementById('no-findings-row');
    if (placeholder) placeholder.remove();

    const sev = (finding.severity || 'info').toLowerCase();
    const tagColor = SEV_TAG[sev] || '';
    const tagClass = tagColor ? `tag small ${tagColor}` : 'tag small';
    const time = finding.timestamp
      ? new Date(finding.timestamp).toLocaleTimeString()
      : new Date().toLocaleTimeString();

    const row = document.createElement('tr');
    row.className = 'clickable-row';
    row.dataset.severity = sev;
    row.innerHTML = `
      <td><span class="${tagClass}">${sev.toUpperCase()}</span></td>
      <td>${escapeHtml(finding.title || 'Unknown')}</td>
      <td class="font-mono">${escapeHtml(finding.target || '—')}</td>
      <td class="font-mono">${escapeHtml(finding.module || '—')}</td>
      <td class="font-mono">${escapeHtml(time)}</td>
    `;
    row.addEventListener('click', () => openDetail(finding));
    tbody.insertBefore(row, tbody.firstChild);
  }

  function loadSnapshot(snap) {
    if (snap.target) {
      addLog(`State sync. Target: ${snap.target}`, 'text-cyan');
    }
    const findings = snap.findings || [];
    if (findings.length > 0) {
      initMetricsFromFindings(findings);
      // Load newest-first into the table (snapshot is oldest-first)
      for (let i = findings.length - 1; i >= 0; i--) {
        addFindingRow(findings[i]);
      }
      addLog(`Loaded ${findings.length} finding(s).`, 'text-cyan');
    }
    // Show status bar if scan is active
    if (snap.scan_status === 'running') {
      let currentPhase = null, currentModule = null;
      if (snap.phases) {
        for (const p of Object.values(snap.phases)) {
          if (p.status === 'running') { currentPhase = p.name; break; }
        }
      }
      if (snap.modules) {
        for (const m of Object.values(snap.modules)) {
          if (m.status === 'running') { currentModule = m.name; break; }
        }
      }
      setScanStatus(true, currentPhase || 'running', currentModule || '—');
    }
  }

  // ── WebSocket Connection ───────────────────────────────────────────
  addLog('Initializing connection to APEX Core...', 'info');

  // Let the Vite proxy (or direct connection) handle routing via window.location.host.
  // On port 5173, Vite proxies /ws/* → wss://127.0.0.1:1337 (see vite.config.js).
  // On port 1337, direct WSS connection is used.
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;

  let ws = null;
  let reconnectTimer = null;

  function connectWS() {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    try {
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        addLog('Connection established.', 'text-green');
        ws.send(JSON.stringify({ action: 'get_state' }));
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'state_snapshot') {
            loadSnapshot(msg.data || {});
          } else if (msg.type === 'event') {
            handleEvent(msg.event_type, msg.data || {});
          }
        } catch (err) {
          console.error('WS parse error', err);
        }
      };

      ws.onclose = () => {
        addLog('Connection lost. Reconnecting in 3s...', 'text-red');
        reconnectTimer = setTimeout(connectWS, 3000);
      };

      ws.onerror = () => {
        // onclose fires after onerror — no need to schedule reconnect here
        addLog('WebSocket error.', 'text-red');
      };

    } catch (e) {
      addLog(`WebSocket failed: ${e.message}`, 'text-red');
      reconnectTimer = setTimeout(connectWS, 5000);
    }
  }

  function handleEvent(type, data) {
    switch (type) {
      case 'scan_start':
        setScanStatus(true, data.phase || 'recon', '—');
        addLog(`Scan started → ${data.target || data.engagement || 'target'}`, 'text-green', true);
        break;
      case 'phase_start':
        setScanStatus(true, data.name || data.phase, '—');
        addLog(`Phase ${data.number || ''}: ${data.name || data.phase}`, 'text-cyan');
        break;
      case 'module_start':
        setScanStatus(true, null, data.name || data.module);
        addLog(`Module: ${data.name || data.module}`, 'text-orange');
        break;
      case 'finding_new':
        addFindingRow(data);
        incrementMetric(data.severity);
        // Switch to Zone A so findings are visible
        if (zoneA && !zoneA.classList.contains('active')) {
          switchZone(btnA, zoneA);
        }
        break;
      case 'scan_complete':
        setScanStatus(false, null, null);
        addLog('Scan complete.', 'text-green', true);
        break;
      case 'scan_interrupted':
      case 'scan_aborted':
        setScanStatus(false, null, null);
        addLog(`Scan ${type.replace('scan_', '')}.`, 'text-red');
        break;
      case 'beacon_new':
        addLog(`[!] NEW BEACON from ${data.target || 'unknown'}`, 'text-red', true);
        break;
      case 'module_progress':
      case 'request_sent':
        break; // high-frequency events — skip terminal noise
      default:
        addLog(type, 'info');
    }
  }

  connectWS();
});
