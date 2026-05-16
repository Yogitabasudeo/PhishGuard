import {
  Chrome,
  Shield,
  Download,
  Code2,
  BookOpen,
  Play,
  Search,
  Loader2,
  Target,
  Lock,
  Globe,
  Cpu,
  Bell,
  Zap,
  Copy,
  Check,
  Info
} from "lucide-react";
import { useState, useRef, useCallback } from "react";
import { DownloadExtensionButton, InstallModal } from "../components/DownloadExtensionButton";
import { simulateScan, SCAN_STAGES } from "../utils/scanSimulator";
const FEATURES = [
  { icon: Zap, label: "Auto-Scan on Tab Change", desc: "Every new URL is scanned the moment the page loads" },
  { icon: Bell, label: "Real-Time Alerts", desc: "Browser notifications for suspicious & malicious URLs" },
  { icon: Target, label: "Brand Impersonation", desc: "Detects PayPal, Google, Amazon & 40+ brand spoofs" },
  { icon: Cpu, label: "ML Detection Engine", desc: "Weighted risk scoring with 10+ detection modules" },
  { icon: Globe, label: "Threat Intel Feeds", desc: "VirusTotal, URLHaus, PhishTank, WHOIS, DNS" },
  { icon: Lock, label: "SSL / HTTPS Analysis", desc: "Certificate validity checked on every scan" }
];
const RISK_LEVELS = [
  { range: "0 \u2013 25", label: "Legitimate", color: "text-green-400", bg: "bg-green-500/10  border-green-500/25" },
  { range: "26 \u2013 55", label: "Low Suspicion", color: "text-yellow-300", bg: "bg-yellow-500/10 border-yellow-500/25" },
  { range: "56 \u2013 75", label: "Suspicious", color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/25" },
  { range: "76 \u2013 100", label: "Malicious", color: "text-red-400", bg: "bg-red-500/10    border-red-500/25" }
];
const SAMPLE_URLS = [
  { url: "https://www.github.com", label: "Safe", color: "text-green-400" },
  { url: "http://paypal-verify.xyz/login", label: "Phishing", color: "text-red-400" },
  { url: "https://goooogle.com", label: "Typosquat", color: "text-red-400" },
  { url: "http://amaz0n-payments.org", label: "L33t", color: "text-red-400" },
  { url: "https://bit.ly/win-prize-2026", label: "Suspicious", color: "text-yellow-400" },
  { url: "https://ajio.com", label: "Safe", color: "text-green-400" }
];
function PopupGauge({ score }) {
  const toRad = (d) => d * Math.PI / 180;
  const cx = 54, cy = 63, r = 45;
  const startDeg = 120, totalSweep = 300;
  const filled = score / 100 * totalSweep;
  const eDeg = startDeg + filled;
  const sx = cx + r * Math.cos(toRad(startDeg));
  const sy = cy + r * Math.sin(toRad(startDeg));
  const ex = cx + r * Math.cos(toRad(eDeg));
  const ey = cy + r * Math.sin(toRad(eDeg));
  const large = filled > 180 ? 1 : 0;
  const fillPath = score <= 0 ? "" : `M ${sx.toFixed(1)} ${sy.toFixed(1)} A ${r} ${r} 0 ${large} 1 ${ex.toFixed(1)} ${ey.toFixed(1)}`;
  const bsx = cx + r * Math.cos(toRad(startDeg));
  const bsy = cy + r * Math.sin(toRad(startDeg));
  const bex = cx + r * Math.cos(toRad(startDeg + totalSweep - 0.5));
  const bey = cy + r * Math.sin(toRad(startDeg + totalSweep - 0.5));
  const color = score >= 76 ? "#ef4444" : score >= 56 ? "#f97316" : score >= 26 ? "#f59e0b" : "#22c55e";
  return <svg width="108" height="72" viewBox="0 0 108 72">
      <path
    d={`M ${bsx.toFixed(1)} ${bsy.toFixed(1)} A ${r} ${r} 0 1 1 ${bex.toFixed(1)} ${bey.toFixed(1)}`}
    fill="none"
    stroke="#1e293b"
    strokeWidth="9"
    strokeLinecap="round"
  />
      {fillPath && <path d={fillPath} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" />}
      <text
    x="54"
    y="50"
    textAnchor="middle"
    fill={color}
    fontSize="20"
    fontWeight="bold"
    fontFamily="monospace"
  >{score}</text>
      <text x="54" y="63" textAnchor="middle" fill="#64748b" fontSize="7.5" fontFamily="sans-serif">RISK SCORE</text>
    </svg>;
}
function ExtensionPopupPreview() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [stage, setStage] = useState("");
  const [result, setResult] = useState(null);
  const inputRef = useRef(null);
  const runScan = useCallback(async (targetUrl) => {
    if (!targetUrl.trim()) return;
    setScanning(true);
    setResult(null);
    for (const s of SCAN_STAGES) {
      setStage(s.label);
      await new Promise((r) => setTimeout(r, s.duration * 0.35));
    }
    const res = await simulateScan(targetUrl);
    setResult(res);
    setScanning(false);
    setStage("");
  }, []);
  const level = result?.prediction === "phishing" ? "phishing" : result?.prediction === "suspicious" ? "suspicious" : result ? "safe" : null;
  const classLabel = result ? result.risk_score >= 76 ? "Malicious" : result.risk_score >= 56 ? "Suspicious" : result.risk_score >= 26 ? "Low Suspicion" : "Legitimate" : "";
  const verdicts = {
    phishing: "HIGH RISK \u2014 Strong phishing indicators. Do NOT enter credentials.",
    suspicious: "CAUTION \u2014 Suspicious URL. Verify the site before proceeding.",
    safe: "LEGITIMATE \u2014 No threats detected. Authentic domain."
  };
  return <div className="flex flex-col gap-4">
      {
    /* URL input */
  }
      <div className="flex gap-2">
        <input
    ref={inputRef}
    value={url}
    onChange={(e) => setUrl(e.target.value)}
    onKeyDown={(e) => e.key === "Enter" && runScan(url)}
    placeholder="Enter a URL to test the extension…"
    className="flex-1 bg-slate-800 border border-slate-700 rounded-xl px-4 py-2.5 text-slate-200 placeholder-slate-500 outline-none focus:border-cyan-500 font-mono"
    style={{ fontSize: "0.8rem" }}
  />
        <button
    onClick={() => runScan(url)}
    disabled={scanning || !url.trim()}
    className="px-4 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 rounded-xl transition-colors"
    style={{ fontSize: "0.8rem", fontWeight: 700 }}
  >
          {scanning ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
        </button>
      </div>

      {
    /* Quick-test buttons */
  }
      <div className="flex flex-wrap gap-2">
        {SAMPLE_URLS.map((s) => <button
    key={s.url}
    onClick={() => {
      setUrl(s.url);
      runScan(s.url);
    }}
    className="px-2.5 py-1 rounded-lg bg-slate-800 border border-slate-700 hover:border-slate-600 transition-colors"
    style={{ fontSize: "0.68rem" }}
  >
            <span className={s.color}>{s.label}</span>
            <span className="text-slate-500 ml-1 font-mono">
              {new URL(s.url.startsWith("http") ? s.url : "https://" + s.url).hostname.replace(/^www\./, "").slice(0, 20)}
            </span>
          </button>)}
      </div>

      {
    /* Popup preview */
  }
      <div className="relative mx-auto" style={{ width: 380 }}>
        {
    /* Browser chrome mock */
  }
        <div className="bg-slate-700 rounded-t-xl px-3 py-2 flex items-center gap-2 border-b border-slate-600">
          <div className="flex gap-1.5">
            {["#ef4444", "#f59e0b", "#22c55e"].map((c) => <div key={c} className="w-3 h-3 rounded-full" style={{ background: c }} />)}
          </div>
          <div className="flex-1 bg-slate-900 rounded-lg px-3 py-1 text-center">
            <span className="text-slate-400 font-mono" style={{ fontSize: "0.65rem" }}>
              {url ? url.startsWith("http") ? new URL(url).hostname : url : "chrome://newtab"}
            </span>
          </div>
          <div className="flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-800 border border-cyan-500/40">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none">
              <path
    d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11.35C17.25 23.15 21 18.25 21 13V7L12 2z"
    fill="rgba(6,182,212,0.4)"
    stroke="#06b6d4"
    strokeWidth="2"
  />
            </svg>
            <span className="text-cyan-400" style={{ fontSize: "0.6rem", fontWeight: 700 }}>PG</span>
          </div>
        </div>

        {
    /* The popup itself */
  }
        <div
    className="bg-slate-950 border border-slate-700 rounded-b-xl overflow-hidden shadow-2xl"
    style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' }}
  >

          {
    /* Popup header */
  }
          <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-slate-800 bg-slate-950">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
                <Shield size={14} className="text-cyan-400" />
              </div>
              <div>
                <div className="text-slate-100" style={{ fontSize: "12.5px", fontWeight: 700 }}>PhishGuard</div>
                <div className="text-slate-500" style={{ fontSize: "8px" }}>Real-Time Protection v1.0</div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-400 shadow-[0_0_5px_#4ade80]" style={{ animation: "pulse 2s infinite" }} />
              <span className="text-slate-500" style={{ fontSize: "13px" }}>⚙</span>
            </div>
          </div>

          {
    /* URL bar */
  }
          <div className="flex items-center gap-1.5 px-3.5 py-1.5 bg-slate-800/70 border-b border-slate-900">
            <span style={{ fontSize: "10px" }}>🔍</span>
            <span className="text-slate-400 font-mono truncate" style={{ fontSize: "10px" }}>
              {url ? url.startsWith("http") ? new URL(url).hostname.replace(/^www\./, "") : url : "Detecting current tab\u2026"}
            </span>
          </div>

          {
    /* Scanning view */
  }
          {scanning && <div className="flex flex-col items-center py-5 gap-3 px-4">
              <div className="relative w-12 h-12 flex items-center justify-center">
                <div className="absolute inset-0 rounded-full border-2 border-t-cyan-400 border-r-cyan-400/20 border-b-transparent border-l-transparent animate-spin" />
                <Shield size={18} className="text-cyan-400/60" />
              </div>
              <div className="text-cyan-400" style={{ fontSize: "11px", fontWeight: 600 }}>Analyzing URL…</div>
              <div className="w-full text-left" style={{ fontSize: "9.5px", color: "#64748b" }}>
                {stage && <div className="text-cyan-400" style={{ fontSize: "9.5px" }}>▸ {stage}</div>}
              </div>
            </div>}

          {
    /* Result view */
  }
          {!scanning && result && <div className="px-3 py-2.5 flex flex-col gap-2">
              {
    /* Gauge + badge */
  }
              <div className="flex items-center gap-3 bg-slate-800/60 border border-slate-700/60 rounded-xl p-2.5">
                <PopupGauge score={result.risk_score} />
                <div className="flex flex-col gap-1.5">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md border text-xs font-bold tracking-wide w-fit ${level === "phishing" ? "bg-red-500/15 text-red-400 border-red-500/30" : level === "suspicious" ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" : "bg-green-500/15 text-green-400 border-green-500/30"}`}>{classLabel}</span>
                  <span className="text-slate-500" style={{ fontSize: "9px" }}>
                    {(result.confidence * 100).toFixed(1)}% confidence
                  </span>
                  {result.detected_brand && level !== "safe" && <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 w-fit">
                      <span style={{ fontSize: "9px" }}>🎯</span>
                      <span className="text-red-300" style={{ fontSize: "9px", fontWeight: 600 }}>
                        Impersonating {result.detected_brand.charAt(0).toUpperCase() + result.detected_brand.slice(1)}
                      </span>
                    </div>}
                </div>
              </div>

              {
    /* Metrics */
  }
              <div className="grid grid-cols-4 gap-1">
                {[
    { label: "SSL", val: result.features.has_https ? "Valid" : "Invalid", ok: result.features.has_https, icon: result.features.has_https ? "\u{1F512}" : "\u{1F513}" },
    { label: "Age", val: result.domain_age, ok: result.domain_age.includes("year"), icon: "\u{1F4C5}" },
    { label: "VT", val: result.virustotal_detections, ok: result.virustotal.positives === 0, icon: "\u{1F6E1}" },
    { label: "Feeds", val: !result.urlhaus_listed && !result.phishtank_listed ? "Clean" : "Listed!", ok: !result.urlhaus_listed && !result.phishtank_listed, icon: !result.urlhaus_listed && !result.phishtank_listed ? "\u{1F4CB}" : "\u{1F534}" }
  ].map((m) => <div key={m.label} className="bg-slate-800/60 border border-slate-700/50 rounded-lg p-1.5 text-center">
                    <div style={{ fontSize: "11px" }}>{m.icon}</div>
                    <div className="text-slate-500" style={{ fontSize: "7.5px", textTransform: "uppercase" }}>{m.label}</div>
                    <div className={`font-mono ${m.ok ? "text-green-400" : "text-red-400"}`} style={{ fontSize: "9px", fontWeight: 700 }}>{m.val}</div>
                  </div>)}
              </div>

              {
    /* Threat signals */
  }
              {result.threat_indicators.length > 0 && <div>
                  <div className="text-red-400 mb-1" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.8px" }}>
                    ⚠ Threat Indicators ({result.threat_indicators.length})
                  </div>
                  <div className="flex flex-col gap-0.5">
                    {result.threat_indicators.slice(0, 4).map((s, i) => <div
    key={i}
    className="text-slate-300 py-0.5 px-2 rounded-r bg-red-500/7 border-l-2 border-red-500/40"
    style={{ fontSize: "9.5px", lineHeight: 1.4 }}
  >
                        {s.replace(/^\[.*?\]\s*/, "")}
                      </div>)}
                  </div>
                </div>}

              {
    /* Attack vectors */
  }
              {result.features.attack_vectors && result.features.attack_vectors.length > 0 && <div className="flex flex-wrap gap-1">
                  {result.features.attack_vectors.map((v, i) => <span
    key={i}
    className="px-2 py-0.5 rounded text-orange-400 bg-orange-500/10 border border-orange-500/25"
    style={{ fontSize: "8.5px", fontWeight: 600 }}
  >{v}</span>)}
                </div>}

              {
    /* Positive signals for safe sites */
  }
              {level === "safe" && result.positive_legitimacy_signals && result.positive_legitimacy_signals.length > 0 && <div>
                  <div className="text-green-400 mb-1" style={{ fontSize: "9px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.8px" }}>
                    ✓ Legitimacy Signals
                  </div>
                  <div className="flex flex-col gap-0.5">
                    {result.positive_legitimacy_signals.slice(0, 4).map((s, i) => <div
    key={i}
    className="text-green-300/80 py-0.5 px-2 rounded-r bg-green-500/7 border-l-2 border-green-500/30"
    style={{ fontSize: "9.5px", lineHeight: 1.4 }}
  >
                        {s}
                      </div>)}
                  </div>
                </div>}

              {
    /* Verdict */
  }
              <div className={`p-2 rounded-lg text-center ${level === "phishing" ? "bg-red-500/7 border border-red-500/20 text-red-300" : level === "suspicious" ? "bg-yellow-500/7 border border-yellow-500/20 text-yellow-200" : "bg-green-500/7 border border-green-500/20 text-green-300"}`} style={{ fontSize: "9.5px", lineHeight: 1.5 }}>
                {verdicts[level || "safe"]}
              </div>
            </div>}

          {
    /* Empty state */
  }
          {!scanning && !result && <div className="flex flex-col items-center py-6 gap-2">
              <Shield size={24} className="text-slate-600" />
              <p className="text-slate-500" style={{ fontSize: "11px" }}>Enter a URL above to scan it</p>
            </div>}

          {
    /* Popup footer */
  }
          <div className="flex gap-2 px-3 py-2 border-t border-slate-800 bg-slate-950">
            <div
    className="flex-1 flex items-center justify-center gap-1.5 py-1.5 bg-cyan-500 text-slate-950 rounded-lg cursor-pointer"
    style={{ fontSize: "11px", fontWeight: 700 }}
  >
              <Search size={11} /> Scan Page
            </div>
            <div
    className="px-3 py-1.5 bg-slate-800 text-slate-400 border border-slate-700 rounded-lg cursor-pointer"
    style={{ fontSize: "10px" }}
  >
              Dashboard ↗
            </div>
          </div>
        </div>
      </div>
    </div>;
}
const CODE_FILES = {
  manifest: { name: "manifest.json", lang: "json", path: "/extension/manifest.json" },
  background: { name: "background.js", lang: "javascript", path: "/extension/background.js" },
  popup_html: { name: "popup.html", lang: "html", path: "/extension/popup.html" },
  popup_js: { name: "popup.js", lang: "javascript", path: "/extension/popup.js" },
  styles: { name: "styles.css", lang: "css", path: "/extension/styles.css" }
};
function CodeViewer() {
  const [active, setActive] = useState("manifest");
  const [code, setCode] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const loadFile = async (key) => {
    setActive(key);
    setLoading(true);
    try {
      const res = await fetch(CODE_FILES[key].path);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const txt = await res.text();
      setCode(txt);
    } catch {
      setCode(`# Could not load file.\n# Path: ${CODE_FILES[key].path}`);
    }
    setLoading(false);
  };
  const copy = async () => {
    if (!code) return;
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return <div className="flex flex-col gap-4">
      {
    /* File tabs */
  }
      <div className="flex flex-wrap gap-2">
        {Object.keys(CODE_FILES).map((k) => <button
    key={k}
    onClick={() => loadFile(k)}
    className={`px-3 py-1.5 rounded-lg border transition-all ${active === k ? "bg-cyan-500/15 border-cyan-500/30 text-cyan-400" : "bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200"}`}
    style={{ fontSize: "0.78rem", fontWeight: active === k ? 600 : 400 }}
  >
            {CODE_FILES[k].name}
          </button>)}
        {code && <button
    onClick={copy}
    className="ml-auto px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 flex items-center gap-1.5 transition-colors"
    style={{ fontSize: "0.75rem" }}
  >
            {copied ? <><Check size={12} className="text-green-400" /> Copied</> : <><Copy size={12} /> Copy</>}
          </button>}
      </div>

      {
    /* Info note */
  }
      <div className="flex items-start gap-2 px-3 py-2.5 rounded-xl bg-cyan-500/5 border border-cyan-500/15">
        <Info size={13} className="text-cyan-400 shrink-0 mt-0.5" />
        <p className="text-slate-400" style={{ fontSize: "0.75rem" }}>
          All extension files are located at <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">/public/extension/</code> in your project.
          Click a file tab to preview its source, then use the copy button or open it directly.
        </p>
      </div>

      {
    /* Code display */
  }
      <div className="relative bg-slate-900 border border-slate-700 rounded-2xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-800/70 border-b border-slate-700">
          <div className="flex items-center gap-2">
            <Code2 size={13} className="text-cyan-400" />
            <span className="text-slate-300 font-mono" style={{ fontSize: "0.78rem" }}>
              {code ? CODE_FILES[active].name : "Select a file to view"}
            </span>
          </div>
          <span className="text-slate-600 font-mono" style={{ fontSize: "0.68rem" }}>
            {code ? `${CODE_FILES[active].lang}` : ""}
          </span>
        </div>
        {loading && <div className="flex items-center justify-center py-12">
            <Loader2 size={20} className="text-cyan-400 animate-spin" />
          </div>}
        {!loading && !code && <div className="flex flex-col items-center justify-center py-12 gap-2 text-slate-600">
            <Code2 size={24} />
            <p style={{ fontSize: "0.8rem" }}>Click a file tab above to view source code</p>
          </div>}
        {!loading && code && <pre className="overflow-auto p-4 text-slate-300 font-mono" style={{ fontSize: "0.72rem", lineHeight: 1.65, maxHeight: 480 }}>
            <code>{code}</code>
          </pre>}
      </div>
    </div>;
}
const INSTALL_STEPS = [
  {
    n: 1,
    title: "Install dependencies",
    desc: "Make sure all npm packages are installed. This only needs to be done once.",
    code: "npm install",
    note: "Requires Node.js 18+. All dependencies are already in package.json."
  },
  {
    n: 2,
    title: "Build the Chrome Extension",
    desc: "Run the dedicated extension build command. This generates PNG icons, bundles the React popup with Vite, and copies background.js + manifest.json into dist-extension/.",
    code: "npm run build:ext",
    note: "Output: dist-extension/ \u2014 this is the folder you will load into Chrome."
  },
  {
    n: 3,
    title: "Verify the dist-extension/ output",
    desc: "After a successful build, your dist-extension/ folder should contain exactly these files:",
    code: "dist-extension/\n  manifest.json\n  popup.html\n  popup.js          \u2190 React popup bundle\n  popup.css         \u2190 Tailwind styles\n  background.js     \u2190 Service worker\n  icons/\n    icon16.png\n    icon32.png\n    icon48.png\n    icon128.png",
    note: "If any file is missing, re-run npm run build:ext and check the console for errors."
  },
  {
    n: 4,
    title: "Open Chrome Extensions",
    desc: "In Chrome, navigate to the Extensions management page and enable Developer Mode.",
    code: "chrome://extensions/",
    note: 'Toggle "Developer mode" ON using the switch in the top-right corner of the page.'
  },
  {
    n: 5,
    title: "Load Unpacked Extension",
    desc: 'Click "Load unpacked" and select the dist-extension/ folder (not its parent).',
    code: null,
    note: "Select the dist-extension/ folder that contains manifest.json directly inside it."
  },
  {
    n: 6,
    title: "Pin the Extension & Test",
    desc: "Click the puzzle piece icon in Chrome's toolbar, then pin PhishGuard for quick access. Navigate to any URL to trigger an auto-scan.",
    code: null,
    note: "The badge shows: \u2713 green (safe) \xB7 ? amber (suspicious) \xB7 !! red (malicious)."
  },
  {
    n: 7,
    title: "After Code Changes \u2014 Rebuild",
    desc: "Whenever you update the popup UI or scanner logic, rebuild and reload the extension:",
    code: "npm run build:ext\n# Then in chrome://extensions \u2192 click \u21BA refresh on the PhishGuard card",
    note: 'background.js changes also require a service worker restart \u2014 click "Service Worker" link in the extension card.'
  }
];
function InstallGuide() {
  const [copied, setCopied] = useState(null);
  return <div className="space-y-4">
      <div className="flex items-start gap-3 px-4 py-3 rounded-xl bg-cyan-500/5 border border-cyan-500/15">
        <Info size={14} className="text-cyan-400 shrink-0 mt-0.5" />
        <p className="text-slate-400" style={{ fontSize: "0.78rem", lineHeight: 1.6 }}>
          PhishGuard uses <strong className="text-slate-300">Chrome Manifest V3</strong> with a background Service Worker.
          Run <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">npm run build:ext</code> to generate
          the <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">dist-extension/</code> folder,
          then load that folder into Chrome as an unpacked extension.
          To share the extension, run <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">npm run package:ext</code> to
          create a distributable <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">phishguard-extension.zip</code>.
        </p>
      </div>
      {INSTALL_STEPS.map((step) => <div key={step.n} className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-4 flex gap-4">
          <div className="shrink-0 w-7 h-7 rounded-full bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
            <span className="text-cyan-400 font-mono" style={{ fontSize: "0.78rem", fontWeight: 700 }}>{step.n}</span>
          </div>
          <div className="flex-1 min-w-0">
            <h4 className="text-slate-200" style={{ fontSize: "0.875rem", fontWeight: 600 }}>{step.title}</h4>
            <p className="text-slate-400 mt-1" style={{ fontSize: "0.78rem", lineHeight: 1.55 }}>{step.desc}</p>
            {step.code && <div className="relative mt-2">
                <pre
    className="bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-slate-300 font-mono overflow-x-auto"
    style={{ fontSize: "0.72rem", lineHeight: 1.6 }}
  >{step.code}</pre>
                <button
    onClick={async () => {
      await navigator.clipboard.writeText(step.code);
      setCopied(step.n);
      setTimeout(() => setCopied(null), 1500);
    }}
    className="absolute top-2 right-2 p-1.5 rounded-lg bg-slate-800 text-slate-500 hover:text-slate-300 transition-colors"
  >
                  {copied === step.n ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                </button>
              </div>}
            {step.note && <p className="mt-2 text-slate-500" style={{ fontSize: "0.72rem", lineHeight: 1.5 }}>
                ℹ️ {step.note}
              </p>}
          </div>
        </div>)}
    </div>;
}
function ExtensionPage() {
  const [tab, setTab] = useState("demo");
  const [showInstallModal, setShowInstallModal] = useState(false);
  const TABS = [
    { id: "demo", label: "Live Demo", icon: Play },
    { id: "code", label: "Source Code", icon: Code2 },
    { id: "install", label: "Dev Setup", icon: BookOpen }
  ];
  return <div className="p-6 max-w-5xl mx-auto space-y-6">

      {
    /* Hero header */
  }
      <div className="bg-gradient-to-r from-slate-800/50 to-cyan-900/20 border border-slate-700/50 rounded-2xl p-5">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-cyan-500/15 border border-cyan-500/25">
            <Chrome size={22} className="text-cyan-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-slate-100" style={{ fontSize: "1.05rem", fontWeight: 700 }}>
                PhishGuard Chrome Extension
              </h2>
              <span
    className="px-2 py-0.5 rounded-full bg-green-500/15 border border-green-500/25 text-green-400"
    style={{ fontSize: "0.65rem", fontWeight: 600 }}
  >Manifest V3</span>
              <span
    className="px-2 py-0.5 rounded-full bg-cyan-500/15 border border-cyan-500/25 text-cyan-400"
    style={{ fontSize: "0.65rem", fontWeight: 600 }}
  >v1.0.0</span>
            </div>
            <p className="text-slate-400 mt-1.5" style={{ fontSize: "0.82rem", lineHeight: 1.6 }}>
              A real-time browser protection extension that automatically scans every tab URL for phishing, typosquatting,
              homoglyph attacks, and brand impersonation — similar to Microsoft Defender SmartScreen or Google Safe Browsing.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              {["Auto Tab Scanning", "Browser Notifications", "Risk Score Gauge", "Scan History", "10+ Detection Modules"].map((f) => <span key={f} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/60 border border-slate-700/40">
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  <span className="text-slate-400" style={{ fontSize: "0.7rem" }}>{f}</span>
                </span>)}
            </div>
          </div>
          <div className="shrink-0 flex flex-col gap-2 items-end">
            <DownloadExtensionButton
              variant="full"
              onShowGuide={() => setShowInstallModal(true)}
            />
            <p className="text-slate-500" style={{ fontSize: "0.65rem" }}>
              v1.0.0 · ~25 KB · Manifest V3 · Chrome / Edge / Brave
            </p>
          </div>
        </div>
      </div>

      {
    /* Feature grid */
  }
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {FEATURES.map(({ icon: Icon, label, desc }) => <div key={label} className="bg-slate-800/30 border border-slate-700/40 rounded-xl p-3.5 flex gap-3">
            <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 h-fit shrink-0">
              <Icon size={14} className="text-cyan-400" />
            </div>
            <div>
              <p className="text-slate-200" style={{ fontSize: "0.78rem", fontWeight: 600 }}>{label}</p>
              <p className="text-slate-500 mt-0.5" style={{ fontSize: "0.7rem", lineHeight: 1.4 }}>{desc}</p>
            </div>
          </div>)}
      </div>

      {
    /* Classification guide */
  }
      <div className="bg-slate-800/30 border border-slate-700/40 rounded-2xl p-4">
        <p className="text-slate-400 mb-3 uppercase tracking-wider" style={{ fontSize: "0.65rem", fontWeight: 600 }}>
          Risk Score Classification
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {RISK_LEVELS.map((r) => <div key={r.label} className={`px-3 py-2.5 rounded-xl border text-center ${r.bg}`}>
              <p className={`font-mono ${r.color}`} style={{ fontSize: "0.9rem", fontWeight: 700 }}>{r.range}</p>
              <p className={`mt-0.5 ${r.color}`} style={{ fontSize: "0.72rem", opacity: 0.85 }}>{r.label}</p>
            </div>)}
        </div>
      </div>

      {
    /* Tab navigation */
  }
      <div className="flex gap-2 border-b border-slate-800 pb-0">
        {TABS.map(({ id, label, icon: Icon }) => <button
    key={id}
    onClick={() => setTab(id)}
    className={`flex items-center gap-2 px-4 py-2.5 rounded-t-xl border-b-2 transition-all ${tab === id ? "text-cyan-400 border-cyan-400 bg-cyan-500/5" : "text-slate-500 border-transparent hover:text-slate-300 hover:bg-slate-800/40"}`}
    style={{ fontSize: "0.825rem", fontWeight: tab === id ? 600 : 400 }}
  >
            <Icon size={14} />
            {label}
          </button>)}
      </div>

      {
    /* Tab content */
  }
      <div className="mt-2">
        {tab === "demo" && <ExtensionPopupPreview />}
        {tab === "code" && <CodeViewer />}
        {tab === "install" && <InstallGuide />}
      </div>

      {/* Install guide modal */}
      {showInstallModal && (
        <InstallModal onClose={() => setShowInstallModal(false)} />
      )}
    </div>;
}
export {
  ExtensionPage
};
