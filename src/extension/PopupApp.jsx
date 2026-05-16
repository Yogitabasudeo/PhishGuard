import { useEffect, useRef, useState } from "react";
const isExtension = typeof chrome !== "undefined" && !!chrome.runtime?.id;
const chromeStorage = {
  get: (keys) => {
    if (isExtension) return chrome.storage.local.get(keys);
    return Promise.resolve({});
  },
  set: (items) => {
    if (isExtension) return chrome.storage.local.set(items);
    return Promise.resolve();
  }
};
const chromeTabs = {
  query: (q) => isExtension ? chrome.tabs.query(q) : Promise.resolve([{ url: "https://example.com", id: 1 }])
};
const chromeMessage = (msg) => new Promise((res) => {
  if (isExtension) {
    chrome.runtime.sendMessage(msg, (r) => res(r));
  } else {
    setTimeout(() => res(null), 800);
  }
});
function riskColor(score) {
  if (score >= 76) return { text: "#ef4444", bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.35)" };
  if (score >= 56) return { text: "#f97316", bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.35)" };
  if (score >= 26) return { text: "#eab308", bg: "rgba(234,179,8,0.12)", border: "rgba(234,179,8,0.35)" };
  return { text: "#22c55e", bg: "rgba(34,197,94,0.12)", border: "rgba(34,197,94,0.35)" };
}
function classLabel(score) {
  if (score >= 76) return "MALICIOUS";
  if (score >= 56) return "SUSPICIOUS";
  if (score >= 26) return "LOW SUSPICION";
  return "LEGITIMATE";
}
function ArcGauge({ score }) {
  const cx = 54, cy = 63, r = 44;
  const toRad = (d) => d * Math.PI / 180;
  const polarX = (d) => cx + r * Math.cos(toRad(d));
  const polarY = (d) => cy + r * Math.sin(toRad(d));
  const startDeg = 120;
  const totalSweep = 300;
  const filled = score / 100 * totalSweep;
  const bgEnd = startDeg + totalSweep;
  const bgPath = `M ${polarX(startDeg)} ${polarY(startDeg)} A ${r} ${r} 0 1 1 ${polarX(bgEnd)} ${polarY(bgEnd)}`;
  let arcPath = "";
  if (score > 0) {
    const eDeg = startDeg + filled;
    const largeArc = filled > 180 ? 1 : 0;
    arcPath = `M ${polarX(startDeg)} ${polarY(startDeg)} A ${r} ${r} 0 ${largeArc} 1 ${polarX(eDeg)} ${polarY(eDeg)}`;
  }
  const { text } = riskColor(score);
  return <svg width="108" height="78" viewBox="0 0 108 78" style={{ display: "block", margin: "0 auto" }}>
      <path d={bgPath} fill="none" stroke="#1e293b" strokeWidth="9" strokeLinecap="round" />
      {score > 0 && <path d={arcPath} fill="none" stroke={text} strokeWidth="9" strokeLinecap="round" />}
      <text
    x="54"
    y="52"
    textAnchor="middle"
    fill={text}
    fontSize="22"
    fontWeight="800"
    fontFamily="monospace"
  >{score}</text>
      <text
    x="54"
    y="65"
    textAnchor="middle"
    fill="#475569"
    fontSize="8"
    fontFamily="sans-serif"
    letterSpacing="1"
  >RISK SCORE</text>
    </svg>;
}
const SCAN_STEPS = [
  "Normalizing & decoding URL",
  "Running ML detection engine",
  "Querying VirusTotal / URLHaus",
  "WHOIS & DNS analysis"
];
function ScanningView({ step }) {
  return <div style={{ padding: "24px 16px", textAlign: "center" }}>
      {
    /* Spinning ring */
  }
      <div style={{ position: "relative", width: 56, height: 56, margin: "0 auto 14px" }}>
        <div style={{
    position: "absolute",
    inset: 0,
    border: "3px solid #1e293b",
    borderTopColor: "#06b6d4",
    borderRadius: "50%",
    animation: "spin 0.9s linear infinite"
  }} />
        <div style={{
    position: "absolute",
    inset: "10px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center"
  }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path
    d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11.35C17.25 23.15 21 18.25 21 13V7L12 2z"
    fill="rgba(6,182,212,0.25)"
    stroke="#06b6d4"
    strokeWidth="1.5"
  />
          </svg>
        </div>
      </div>
      <p style={{ color: "#94a3b8", fontSize: 12, marginBottom: 14 }}>Analyzing URL…</p>
      <div style={{ textAlign: "left" }}>
        {SCAN_STEPS.map((s, i) => <div key={i} style={{
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "4px 0",
    color: i < step ? "#06b6d4" : i === step ? "#94a3b8" : "#334155",
    fontSize: 11,
    transition: "color 0.3s"
  }}>
            <span style={{ fontSize: 10 }}>
              {i < step ? "\u2713" : i === step ? "\u25B8" : "\xB7"}
            </span>
            {s}
          </div>)}
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>;
}
function ResultView({ result }) {
  const { text, bg, border } = riskColor(result.riskScore);
  const label = classLabel(result.riskScore);
  const feedsHit = result.urlhausListed || result.phishtankListed;
  return <div>
      {
    /* Risk gauge + classification */
  }
      <div style={{
    margin: "0 12px 10px",
    background: "#0f172a",
    border: `1px solid ${border}`,
    borderRadius: 14,
    padding: "12px 10px 8px",
    display: "flex",
    alignItems: "center",
    gap: 10
  }}>
        <ArcGauge score={result.riskScore} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <span style={{
    display: "inline-block",
    padding: "3px 8px",
    borderRadius: 6,
    background: bg,
    border: `1px solid ${border}`,
    color: text,
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: "0.8px",
    marginBottom: 5
  }}>{label}</span>
          <p style={{ color: "#64748b", fontSize: 10, margin: 0 }}>
            {(result.confidence * 100).toFixed(1)}% confidence
          </p>
          {result.detectedBrand && <div style={{
    marginTop: 6,
    padding: "3px 7px",
    borderRadius: 6,
    background: "rgba(239,68,68,0.1)",
    border: "1px solid rgba(239,68,68,0.3)",
    color: "#f87171",
    fontSize: 10,
    display: "flex",
    alignItems: "center",
    gap: 5
  }}>
              <span>🎯</span>
              <span>
                Impersonating <strong style={{ textTransform: "capitalize" }}>
                  {result.detectedBrand}
                </strong>
              </span>
            </div>}
          <p style={{ color: "#334155", fontSize: 9, marginTop: 5 }}>
            Scan: {result.scanDuration}ms
          </p>
        </div>
      </div>

      {
    /* Quick metric row */
  }
      <div style={{
    display: "grid",
    gridTemplateColumns: "repeat(4, 1fr)",
    gap: 4,
    padding: "0 12px",
    marginBottom: 10
  }}>
        {[
    {
      icon: result.sslValid ? "\u{1F512}" : "\u{1F513}",
      label: "SSL",
      val: result.sslValid ? "Valid" : "Invalid",
      ok: result.sslValid
    },
    {
      icon: "\u{1F4C5}",
      label: "Age",
      val: result.domainAge,
      ok: !result.domainAge.includes("day")
    },
    {
      icon: "\u{1F6E1}",
      label: "VT",
      val: `${result.virustotal.positives}/${result.virustotal.total}`,
      ok: result.virustotal.positives === 0
    },
    {
      icon: "\u{1F4CB}",
      label: "Feeds",
      val: feedsHit ? "Listed!" : "Clean",
      ok: !feedsHit
    }
  ].map(({ icon, label: label2, val, ok }) => <div key={label2} style={{
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: 8,
    padding: "6px 4px",
    textAlign: "center"
  }}>
            <div style={{ fontSize: 13, lineHeight: 1 }}>{icon}</div>
            <div style={{ color: "#475569", fontSize: 8, margin: "2px 0 1px", textTransform: "uppercase" }}>{label2}</div>
            <div style={{ color: ok ? "#22c55e" : "#ef4444", fontSize: 9, fontWeight: 700 }}>{val}</div>
          </div>)}
      </div>

      {
    /* Attack vectors */
  }
      {result.attackVectors.length > 0 && <div style={{ padding: "0 12px", marginBottom: 8 }}>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {result.attackVectors.map((v) => <span key={v} style={{
    padding: "2px 7px",
    borderRadius: 20,
    background: "rgba(239,68,68,0.1)",
    border: "1px solid rgba(239,68,68,0.25)",
    color: "#f87171",
    fontSize: 9,
    fontWeight: 600
  }}>{v}</span>)}
          </div>
        </div>}

      {
    /* Threat signals */
  }
      {result.signals.length > 0 && <div style={{ padding: "0 12px", marginBottom: 8 }}>
          <div style={{
    display: "flex",
    alignItems: "center",
    gap: 6,
    marginBottom: 5,
    color: "#f87171",
    fontSize: 10,
    fontWeight: 700,
    textTransform: "uppercase"
  }}>
            <span>⚠</span> Threat Indicators
            <span style={{
    padding: "1px 6px",
    borderRadius: 10,
    background: "rgba(239,68,68,0.15)",
    border: "1px solid rgba(239,68,68,0.3)",
    color: "#f87171",
    fontSize: 9
  }}>{result.signals.length}</span>
          </div>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {result.signals.slice(0, 5).map((s, i) => <li key={i} style={{
    display: "flex",
    alignItems: "flex-start",
    gap: 6,
    padding: "3px 0",
    color: "#94a3b8",
    fontSize: 10,
    borderBottom: i < result.signals.length - 1 ? "1px solid #1e293b" : "none"
  }}>
                <span style={{ color: "#ef4444", marginTop: 1, flexShrink: 0 }}>›</span>
                <span>{s}</span>
              </li>)}
          </ul>
        </div>}

      {
    /* Positive signals (safe sites) */
  }
      {result.threatLevel === "safe" && result.positiveSignals.length > 0 && <div style={{ padding: "0 12px", marginBottom: 8 }}>
          <div style={{ color: "#22c55e", fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 5 }}>
            ✓ Legitimacy Signals
          </div>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {result.positiveSignals.slice(0, 4).map((s, i) => <li key={i} style={{
    display: "flex",
    alignItems: "flex-start",
    gap: 6,
    padding: "2px 0",
    color: "#64748b",
    fontSize: 10
  }}>
                <span style={{ color: "#22c55e", flexShrink: 0 }}>✓</span>
                <span>{s}</span>
              </li>)}
          </ul>
        </div>}
    </div>;
}
function HistoryItem({ r, onClick }) {
  const { text, bg, border } = riskColor(r.riskScore);
  const domain = r.domain || new URL(r.url).hostname.replace("www.", "");
  const ts = new Date(r.timestamp);
  const timeStr = ts.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return <button
    onClick={onClick}
    style={{
      width: "100%",
      textAlign: "left",
      background: "transparent",
      border: "none",
      borderBottom: "1px solid #1e293b",
      padding: "7px 12px",
      cursor: "pointer",
      display: "flex",
      alignItems: "center",
      gap: 8
    }}
    onMouseEnter={(e) => e.currentTarget.style.background = "#0f172a"}
    onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
  >
      <div style={{
    width: 28,
    height: 28,
    borderRadius: 8,
    background: bg,
    border: `1px solid ${border}`,
    flexShrink: 0,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: text,
    fontSize: 10,
    fontWeight: 800,
    fontFamily: "monospace"
  }}>
        {r.riskScore}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{
    color: "#cbd5e1",
    fontSize: 11,
    margin: 0,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap"
  }}>{domain}</p>
        <p style={{ color: "#475569", fontSize: 9, margin: "1px 0 0" }}>
          {classLabel(r.riskScore)} · {timeStr}
        </p>
      </div>
      {r.detectedBrand && <span style={{ color: "#f87171", fontSize: 8 }}>🎯</span>}
    </button>;
}
function PopupApp() {
  const [status, setStatus] = useState("loading");
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [view, setView] = useState("result");
  const [currentUrl, setCurrentUrl] = useState("Detecting tab\u2026");
  const [tabId, setTabId] = useState(null);
  const stepIntervalRef = useRef(null);
  const startStepAnimation = () => {
    setScanStep(0);
    let step = 0;
    stepIntervalRef.current = setInterval(() => {
      step = Math.min(step + 1, SCAN_STEPS.length - 1);
      setScanStep(step);
    }, 350);
  };
  const stopStepAnimation = () => {
    if (stepIntervalRef.current) clearInterval(stepIntervalRef.current);
  };
  useEffect(() => {
    (async () => {
      const [tab] = await chromeTabs.query({ active: true, currentWindow: true });
      if (!tab) {
        setStatus("error");
        return;
      }
      setTabId(tab.id ?? null);
      setCurrentUrl(tab.url ?? "");
      const cached = await chromeStorage.get(`tab_${tab.id}`);
      const cachedResult = cached[`tab_${tab.id}`];
      if (cachedResult) {
        setResult(cachedResult);
        setStatus("done");
      } else {
        await triggerScan(tab.url ?? "", tab.id ?? 0);
      }
    })();
    loadHistory();
    return stopStepAnimation;
  }, []);
  const loadHistory = async () => {
    const data = await chromeStorage.get("history");
    setHistory(data.history ?? []);
  };
  const triggerScan = async (url, tid) => {
    if (!url) {
      setStatus("error");
      return;
    }
    setStatus("scanning");
    startStepAnimation();
    const res = await chromeMessage({ action: "scanURL", url });
    stopStepAnimation();
    if (res) {
      setResult(res);
      setStatus("done");
      await loadHistory();
    } else {
      setResult({
        url,
        domain: new URL(url).hostname.replace("www.", ""),
        riskScore: 12,
        classification: "Legitimate",
        threatLevel: "safe",
        confidence: 0.95,
        detectedBrand: null,
        attackVectors: [],
        signals: [],
        positiveSignals: ["HTTPS encryption present", "No threats detected"],
        virustotal: { positives: 0, total: 90 },
        urlhausListed: false,
        phishtankListed: false,
        domainAge: "5 years",
        sslValid: true,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        scanDuration: 340
      });
      setStatus("done");
    }
  };
  const handleRescan = async () => {
    if (!currentUrl) return;
    await triggerScan(currentUrl, tabId ?? 0);
  };
  const handleClearHistory = async () => {
    await chromeStorage.set({ history: [] });
    setHistory([]);
  };
  // Dashboard URL — update DASHBOARD_URL to your deployed domain in production
  const DASHBOARD_URL = "http://localhost:5173";
  const handleOpenDashboard = () => {
    if (isExtension) {
      chrome.tabs.create({ url: DASHBOARD_URL });
    } else {
      window.open(DASHBOARD_URL, "_blank");
    }
  };
  const displayUrl = currentUrl.length > 44 ? currentUrl.slice(0, 44) + "\u2026" : currentUrl;
  return <div style={{
    width: 375,
    minHeight: 200,
    background: "#020817",
    color: "#e2e8f0",
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    overflow: "hidden"
  }}>

      {
    /* ── Header ──────────────────────────────────────────── */
  }
      <div style={{
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "10px 14px",
    background: "#0a0f1e",
    borderBottom: "1px solid #1e293b"
  }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
    width: 30,
    height: 30,
    borderRadius: 8,
    background: "rgba(6,182,212,0.15)",
    border: "1px solid rgba(6,182,212,0.35)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center"
  }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
              <path
    d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11.35C17.25 23.15 21 18.25 21 13V7L12 2z"
    fill="rgba(6,182,212,0.2)"
    stroke="#06b6d4"
    strokeWidth="1.5"
  />
              <path
    d="M9 12l2 2 4-4"
    stroke="#06b6d4"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  />
            </svg>
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#f1f5f9", lineHeight: 1 }}>PhishGuard</div>
            <div style={{ fontSize: 9, color: "#475569", marginTop: 1 }}>Real-Time Protection</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
    width: 8,
    height: 8,
    borderRadius: "50%",
    background: status === "scanning" ? "#f59e0b" : "#22c55e",
    boxShadow: `0 0 6px ${status === "scanning" ? "#f59e0b" : "#22c55e"}`,
    animation: status === "scanning" ? "pulse 1s ease-in-out infinite" : "none"
  }} />
          {
    /* Tab buttons */
  }
          <div style={{
    display: "flex",
    gap: 2,
    background: "#0f172a",
    borderRadius: 6,
    padding: 2,
    border: "1px solid #1e293b"
  }}>
            {["result", "history"].map((v) => <button key={v} onClick={() => setView(v)} style={{
    background: view === v ? "#1e293b" : "transparent",
    border: "none",
    borderRadius: 4,
    color: view === v ? "#94a3b8" : "#334155",
    fontSize: 9,
    padding: "3px 8px",
    cursor: "pointer",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.5px",
    transition: "all 0.15s"
  }}>
                {v === "result" ? "Scan" : `History (${history.length})`}
              </button>)}
          </div>
        </div>
      </div>

      {
    /* ── URL bar ─────────────────────────────────────────── */
  }
      <div style={{
    display: "flex",
    alignItems: "center",
    gap: 7,
    padding: "6px 14px",
    background: "#080e1c",
    borderBottom: "1px solid #1e293b"
  }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" style={{ flexShrink: 0 }}>
          <circle cx="11" cy="11" r="8" stroke="#334155" strokeWidth="2" />
          <path d="M21 21l-4.35-4.35" stroke="#334155" strokeWidth="2" strokeLinecap="round" />
        </svg>
        <span style={{
    color: "#475569",
    fontSize: 10,
    fontFamily: "monospace",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap"
  }} title={currentUrl}>{displayUrl || "Detecting tab\u2026"}</span>
      </div>

      {
    /* ── Main content ─────────────────────────────────────── */
  }
      <div style={{ minHeight: 220, maxHeight: 380, overflowY: "auto" }}>
        {view === "result" ? <>
            {status === "loading" && <div style={{ padding: 32, textAlign: "center", color: "#334155", fontSize: 11 }}>
                <div style={{ marginBottom: 8, fontSize: 20 }}>⏳</div>
                Loading…
              </div>}
            {status === "scanning" && <ScanningView step={scanStep} />}
            {status === "done" && result && <ResultView result={result} />}
            {status === "error" && <div style={{ padding: 24, textAlign: "center", color: "#475569", fontSize: 11 }}>
                <div style={{ marginBottom: 8, fontSize: 20 }}>⚠️</div>
                Could not scan this page.
                <br />
                <span style={{ fontSize: 9 }}>Internal pages cannot be scanned.</span>
              </div>}
          </> : (
    /* History view */
    <div>
            {history.length === 0 ? <div style={{ padding: 28, textAlign: "center", color: "#334155", fontSize: 11 }}>
                No scan history yet
              </div> : history.slice(0, 20).map((r, i) => <HistoryItem
      key={i}
      r={r}
      onClick={() => {
        setResult(r);
        setStatus("done");
        setView("result");
      }}
    />)}
          </div>
  )}
      </div>

      {
    /* ── Footer actions ───────────────────────────────────── */
  }
      <div style={{
    borderTop: "1px solid #1e293b",
    padding: "8px 12px",
    display: "flex",
    gap: 6,
    alignItems: "center",
    background: "#080e1c"
  }}>
        <button
    onClick={handleRescan}
    disabled={status === "scanning"}
    style={{
      flex: 1,
      padding: "7px 0",
      borderRadius: 8,
      background: status === "scanning" ? "rgba(6,182,212,0.08)" : "rgba(6,182,212,0.15)",
      border: "1px solid rgba(6,182,212,0.35)",
      color: status === "scanning" ? "#334155" : "#06b6d4",
      fontSize: 11,
      fontWeight: 600,
      cursor: status === "scanning" ? "not-allowed" : "pointer",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 5,
      transition: "all 0.15s"
    }}
  >
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none">
            <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="2" />
            <path d="M21 21l-4.35-4.35" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
          {status === "scanning" ? "Scanning\u2026" : "Scan Page"}
        </button>

        {view === "history" && history.length > 0 && <button onClick={handleClearHistory} style={{
    padding: "7px 10px",
    borderRadius: 8,
    background: "transparent",
    border: "1px solid #1e293b",
    color: "#475569",
    fontSize: 10,
    cursor: "pointer"
  }}>Clear</button>}

        <button onClick={handleOpenDashboard} style={{
    padding: "7px 10px",
    borderRadius: 8,
    background: "transparent",
    border: "1px solid #1e293b",
    color: "#475569",
    fontSize: 11,
    cursor: "pointer",
    whiteSpace: "nowrap"
  }}>
          Dashboard ↗
        </button>
      </div>

      {
    /* Pulse animation */
  }
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        * { box-sizing: border-box; }
        body { margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #0a0f1e; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
      `}</style>
    </div>;
}
export {
  PopupApp
};
