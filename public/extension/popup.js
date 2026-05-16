// ============================================================
// PhishGuard v1.0 — Popup Script
// Controls the extension popup UI
// ============================================================

// ── DOM element cache ─────────────────────────────────────────
const $ = id => document.getElementById(id);
const E = {
  urlText:        $('pg-url'),
  scanningView:   $('pg-scanning'),
  resultView:     $('pg-result'),
  gaugeFill:      $('pg-gauge-fill'),
  scoreVal:       $('pg-score-val'),
  badge:          $('pg-badge'),
  conf:           $('pg-conf'),
  brandWarn:      $('pg-brand-warn'),
  brandName:      $('pg-brand-name'),
  mSslIcon:       $('m-ssl-icon'),
  mSslVal:        $('m-ssl-val'),
  mAgeIcon:       $('m-age-icon'),
  mAgeVal:        $('m-age-val'),
  mVtIcon:        $('m-vt-icon'),
  mVtVal:         $('m-vt-val'),
  mFeedsIcon:     $('m-feeds-icon'),
  mFeedsVal:      $('m-feeds-val'),
  signalsSection: $('pg-signals-section'),
  signalsCount:   $('pg-signals-count'),
  signalsList:    $('pg-signals-list'),
  vectorsSection: $('pg-vectors-section'),
  vectorsList:    $('pg-vectors-list'),
  posSection:     $('pg-pos-section'),
  posList:        $('pg-pos-list'),
  verdictSection: $('pg-verdict-section'),
  verdictText:    $('pg-verdict'),
  historyList:    $('pg-history'),
  scanBtn:        $('pg-scan-btn'),
  dashBtn:        $('pg-dashboard-btn'),
  clearBtn:       $('pg-clear'),
  step1:          $('step-1'),
  step2:          $('step-2'),
  step3:          $('step-3'),
  step4:          $('step-4'),
};

// ── SVG Gauge ─────────────────────────────────────────────────
// Uses the same 120°→60° sweep (300° arc) as the dashboard gauge.

const toRad = deg => deg * Math.PI / 180;

function buildArcPath(score) {
  const cx = 54, cy = 63, r = 45;
  const startDeg = 120;               // lower-left  (SVG coords)
  const totalSweep = 300;
  const filledSweep = (score / 100) * totalSweep;

  if (score <= 0) return '';

  const sDeg = startDeg;
  const eDeg = startDeg + filledSweep;

  const sx = cx + r * Math.cos(toRad(sDeg));
  const sy = cy + r * Math.sin(toRad(sDeg));
  const ex = cx + r * Math.cos(toRad(eDeg));
  const ey = cy + r * Math.sin(toRad(eDeg));

  const large = filledSweep > 180 ? 1 : 0;
  return `M ${sx.toFixed(2)} ${sy.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${ex.toFixed(2)} ${ey.toFixed(2)}`;
}

function scoreColor(score) {
  if (score >= 76) return '#ef4444';
  if (score >= 56) return '#f97316';
  if (score >= 26) return '#f59e0b';
  return '#22c55e';
}

function renderGauge(score) {
  const color = scoreColor(score);
  const path  = buildArcPath(score);
  E.gaugeFill.setAttribute('d', path);
  E.gaugeFill.setAttribute('stroke', color);
  E.scoreVal.textContent = score;
  E.scoreVal.setAttribute('fill', color);
}

// ── Scanning animation ────────────────────────────────────────
let _stepTimer = null;
let _pollTimer = null;

function showScanning() {
  E.scanningView.classList.remove('hidden');
  E.resultView.classList.add('hidden');

  const steps = [E.step1, E.step2, E.step3, E.step4];
  steps.forEach(s => { s.classList.remove('active','done'); });
  steps[0].classList.add('active');
  let cur = 0;

  _stepTimer = setInterval(() => {
    if (cur < steps.length - 1) {
      steps[cur].classList.remove('active');
      steps[cur].classList.add('done');
      cur++;
      steps[cur].classList.add('active');
    }
  }, 500);
}

function stopScanning() {
  if (_stepTimer) { clearInterval(_stepTimer); _stepTimer = null; }
}

// ── Metric helper ─────────────────────────────────────────────
function setMetric(iconEl, valEl, isGood, goodIcon, badIcon, valText) {
  iconEl.textContent = isGood ? goodIcon : badIcon;
  valEl.textContent  = valText;
  valEl.className    = `pg-metric-val ${isGood ? 'safe' : 'danger'}`;
}

// ── Render a complete scan result ─────────────────────────────
function renderResult(r) {
  stopScanning();
  E.scanningView.classList.add('hidden');
  E.resultView.classList.remove('hidden');

  const level = r.threatLevel || 'safe';

  // Gauge
  renderGauge(r.riskScore);

  // Classification badge
  E.badge.textContent = r.classification.toUpperCase();
  E.badge.className   = `pg-badge ${level}`;

  // Confidence
  E.conf.textContent = `${(r.confidence * 100).toFixed(1)}% confidence`;

  // Brand impersonation banner
  if (r.detectedBrand && level !== 'safe') {
    const cap = r.detectedBrand.charAt(0).toUpperCase() + r.detectedBrand.slice(1);
    E.brandName.textContent = `Impersonating ${cap}`;
    E.brandWarn.classList.remove('hidden');
  } else {
    E.brandWarn.classList.add('hidden');
  }

  // Metrics
  const ageOk = r.domainAge && (r.domainAge.includes('year') && parseInt(r.domainAge) >= 1);
  setMetric(E.mSslIcon,   E.mSslVal,   r.sslValid,                   '🔒','🔓', r.sslValid ? 'Valid' : 'Invalid');
  setMetric(E.mAgeIcon,   E.mAgeVal,   ageOk,                        '📅','⚠️', r.domainAge || 'N/A');
  setMetric(E.mVtIcon,    E.mVtVal,    r.virustotal.positives === 0, '🛡','⚠️', `${r.virustotal.positives}/${r.virustotal.total}`);
  const feedsClean = !r.urlhausListed && !r.phishtankListed;
  setMetric(E.mFeedsIcon, E.mFeedsVal, feedsClean,                   '📋','🔴', feedsClean ? 'Clean' : 'Listed!');

  // Threat signals
  if (r.signals && r.signals.length > 0) {
    E.signalsCount.textContent = r.signals.length;
    E.signalsList.innerHTML = r.signals
      .slice(0, 7)
      .map(s => `<li class="pg-signal">${s.replace(/^\[.*?\]\s*/,'')}</li>`)
      .join('');
    E.signalsSection.classList.remove('hidden');
  } else {
    E.signalsSection.classList.add('hidden');
  }

  // Attack vector badges
  if (r.attackVectors && r.attackVectors.length > 0) {
    E.vectorsList.innerHTML = r.attackVectors
      .map(v => `<span class="pg-vector-badge">${v}</span>`)
      .join('');
    E.vectorsSection.classList.remove('hidden');
  } else {
    E.vectorsSection.classList.add('hidden');
  }

  // Positive signals (shown for safe sites)
  if (level === 'safe' && r.positiveSignals && r.positiveSignals.length > 0) {
    E.posList.innerHTML = r.positiveSignals
      .slice(0, 5)
      .map(s => `<li class="pg-pos-item">✓ ${s}</li>`)
      .join('');
    E.posSection.classList.remove('hidden');
  } else {
    E.posSection.classList.add('hidden');
  }

  // AI verdict
  const verdicts = {
    phishing:   'HIGH RISK — This URL shows strong phishing indicators. Do NOT enter credentials or personal data.',
    suspicious: 'CAUTION — Suspicious URL detected. Verify the site independently before proceeding.',
    suspicion:  'LOW SUSPICION — Some unusual signals detected. Exercise caution; do not share sensitive data.',
    safe:       'LEGITIMATE — No threats detected. This appears to be an authentic, well-established domain.',
  };
  E.verdictText.textContent = verdicts[level] || verdicts.safe;
  E.verdictText.className   = `pg-verdict ${level}`;
  E.verdictSection.classList.remove('hidden');
}

// ── Scan history ──────────────────────────────────────────────
function timeAgo(ts) {
  const d = Date.now() - new Date(ts).getTime();
  const m = Math.floor(d / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function renderHistory(items) {
  if (!items || items.length === 0) {
    E.historyList.innerHTML = '<div class="pg-history-empty">No scans yet</div>';
    return;
  }
  E.historyList.innerHTML = items.slice(0, 5).map(item => {
    const lv  = item.threatLevel || 'safe';
    const dot = lv === 'phishing' ? '#ef4444' : lv === 'suspicious' ? '#f59e0b' : '#22c55e';
    const dom = item.domain || (() => { try { return new URL(item.url).hostname; } catch { return item.url; }})();
    return `
      <div class="pg-history-item">
        <div class="pg-hdot" style="background:${dot}"></div>
        <div class="pg-hinfo">
          <div class="pg-hdomain">${dom}</div>
          <div class="pg-htime">${timeAgo(item.timestamp)}</div>
        </div>
        <div class="pg-hscore" style="color:${dot}">${item.riskScore}</div>
      </div>`;
  }).join('');
}

// ── Polling helper (waits for background scan to complete) ─────
function pollForResult(tabId, url) {
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(async () => {
    const data = await chrome.storage.local.get(`tab_${tabId}`);
    const res  = data[`tab_${tabId}`];
    if (res && res.url === url) {
      clearInterval(_pollTimer);
      _pollTimer = null;
      stopScanning();
      renderResult(res);
      refreshHistory();
    }
  }, 400);
  // Auto-cancel after 15s
  setTimeout(() => { if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; } }, 15000);
}

async function refreshHistory() {
  const { history = [] } = await chrome.storage.local.get('history');
  renderHistory(history);
}

// ── Main init ──────────────────────────────────────────────────
async function init() {
  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    E.urlText.textContent = 'No active tab';
    stopScanning();
    return;
  }

  const url = tab.url;
  let domain;
  try { domain = new URL(url).hostname.replace(/^www\./, ''); } catch { domain = url; }
  E.urlText.textContent = domain.length > 44 ? domain.slice(0, 44) + '…' : domain;

  // Load history first
  await refreshHistory();

  // Check if the background is currently scanning this tab
  const scanData = await chrome.storage.local.get(`scanning_${tab.id}`);
  if (scanData[`scanning_${tab.id}`]) {
    showScanning();
    pollForResult(tab.id, url);
    return;
  }

  // Check for a cached result for this exact URL
  const tabData = await chrome.storage.local.get(`tab_${tab.id}`);
  const cached  = tabData[`tab_${tab.id}`];
  if (cached && cached.url === url) {
    renderResult(cached);
    return;
  }

  // No cache — request a fresh scan from the background worker
  showScanning();
  chrome.runtime.sendMessage({ action: 'scanURL', url }, result => {
    stopScanning();
    if (result) {
      // Cache the result locally for this tab
      chrome.storage.local.set({ [`tab_${tab.id}`]: result });
      renderResult(result);
      refreshHistory();
    }
  });
}

// ── Event listeners ────────────────────────────────────────────

// Manual "Scan Page" button
E.scanBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  showScanning();
  chrome.runtime.sendMessage({ action: 'scanURL', url: tab.url }, result => {
    stopScanning();
    if (result) {
      chrome.storage.local.set({ [`tab_${tab.id}`]: result });
      renderResult(result);
      refreshHistory();
    }
  });
});

// Open dashboard
E.dashBtn.addEventListener('click', () => {
  chrome.tabs.create({ url: 'http://localhost:5173' }); // Change to your dashboard URL
});

// Clear history
E.clearBtn.addEventListener('click', async () => {
  await chrome.storage.local.set({ history: [] });
  renderHistory([]);
});

// Settings (placeholder)
$('pg-settings').addEventListener('click', () => {
  alert('PhishGuard Settings\n\nAPI Endpoint: http://localhost:8000\nNotifications: Enabled\nAuto-scan: Enabled\n\n(Settings panel coming soon)');
});

// Boot
init().catch(console.error);
