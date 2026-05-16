import {
  Server,
  Code2,
  Play,
  Loader2,
  Copy,
  Check,
  Database,
  GitBranch,
  Terminal,
  Info,
  BarChart3,
  ArrowRight,
  CheckCircle,
  TrendingUp,
  Shield,
  Activity
} from "lucide-react";
import { useState, useCallback, useRef } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  Legend,
  Cell
} from "recharts";
import { simulateScan } from "../utils/scanSimulator";
const METRICS = {
  accuracy: 96.82,
  precision: 97.14,
  recall: 96.51,
  f1: 96.82,
  auc_roc: 99.07,
  tp: 2895,
  fp: 84,
  fn: 101,
  tn: 2920
};
const FEATURE_IMPORTANCES = [
  { feature: "urlhaus_listed", importance: 0.1821 },
  { feature: "phishtank_listed", importance: 0.1654 },
  { feature: "vt_positives", importance: 0.1402 },
  { feature: "brand_similarity_score", importance: 0.1188 },
  { feature: "domain_age_days", importance: 0.0941 },
  { feature: "has_brand_not_in_tld", importance: 0.0724 },
  { feature: "ssl_valid", importance: 0.0618 },
  { feature: "url_entropy", importance: 0.0512 },
  { feature: "has_suspicious_keywords", importance: 0.0421 },
  { feature: "suspicious_tld", importance: 0.0365 },
  { feature: "num_hyphens", importance: 0.0198 },
  { feature: "url_length", importance: 0.0156 }
];
const TRAINING_HISTORY = [
  { epoch: 50, train_acc: 88.4, val_acc: 87.9, train_loss: 0.421, val_loss: 0.438 },
  { epoch: 100, train_acc: 92.1, val_acc: 91.5, train_loss: 0.281, val_loss: 0.309 },
  { epoch: 150, train_acc: 94.2, val_acc: 93.8, train_loss: 0.198, val_loss: 0.219 },
  { epoch: 200, train_acc: 95.6, val_acc: 95.1, train_loss: 0.148, val_loss: 0.162 },
  { epoch: 250, train_acc: 96.4, val_acc: 95.9, train_loss: 0.118, val_loss: 0.131 },
  { epoch: 300, train_acc: 96.8, val_acc: 96.5, train_loss: 0.098, val_loss: 0.112 }
];
const SAMPLE_PAYLOADS = [
  { label: "Phishing", color: "text-red-400", url: "http://paypal-verify-account.xyz/login?user=victim" },
  { label: "Typosquat", color: "text-red-400", url: "https://goooogle-login.com/secure/verify" },
  { label: "L33t Speak", color: "text-orange-400", url: "https://amaz0n-payments.org/checkout" },
  { label: "Safe", color: "text-green-400", url: "https://www.github.com/torvalds/linux" },
  { label: "Subdomain", color: "text-red-400", url: "http://paypal.secure-login-verify.tk/auth" },
  { label: "Brand Abuse", color: "text-orange-400", url: "https://microsoft-office365-login.online/signin" }
];
const CODE_FILES = {
  train: { name: "train_model.py", path: "/backend/train_model.py", lang: "python" },
  feature: { name: "feature_extractor.py", path: "/backend/feature_extractor.py", lang: "python" },
  main: { name: "main.py", path: "/backend/main.py", lang: "python" },
  schemas: { name: "schemas.py", path: "/backend/schemas.py", lang: "python" },
  model_svc: { name: "model_service.py", path: "/backend/services/model_service.py", lang: "python" },
  vt_svc: { name: "virustotal_service.py", path: "/backend/services/virustotal_service.py", lang: "python" },
  urlhaus: { name: "urlhaus_service.py", path: "/backend/services/urlhaus_service.py", lang: "python" },
  whois: { name: "whois_service.py", path: "/backend/services/whois_service.py", lang: "python" },
  dns: { name: "dns_service.py", path: "/backend/services/dns_service.py", lang: "python" },
  ssl: { name: "ssl_service.py", path: "/backend/services/ssl_service.py", lang: "python" }
};
function buildApiResponse(result) {
  const level = result.prediction;
  const classification = result.risk_score >= 76 ? "Malicious" : result.risk_score >= 56 ? "Suspicious" : result.risk_score >= 26 ? "Low Suspicion" : "Legitimate";
  const attackType = result.features.attack_vectors?.[0] || (result.detected_brand ? "Brand Impersonation" : null) || (result.features.has_suspicious_keywords ? "Credential Phishing" : null);
  return {
    scan_id: result.id,
    url: result.url,
    timestamp: result.timestamp,
    classification,
    risk_score: result.risk_score,
    confidence: parseFloat((result.confidence * 100).toFixed(1)),
    attack_type: attackType,
    attack_vectors: result.features.attack_vectors || [],
    impersonated_brand: result.detected_brand || null,
    ioc: {
      domain: result.domain,
      ip_address: result.ip_address,
      domain_age: result.domain_age,
      ssl: result.features.has_https ? "valid" : "invalid",
      vt_detections: result.virustotal.positives,
      vt_total: result.virustotal.total,
      urlhaus_listed: result.urlhaus_listed,
      phishtank_listed: result.phishtank_listed,
      whois_registrar: result.whois.registrar,
      whois_country: result.whois.country,
      dns_a_records: result.dns_records.A.slice(0, 3)
    },
    threat_indicators: result.threat_indicators,
    positive_signals: result.positive_legitimacy_signals || [],
    final_verdict: result.final_verdict_explanation || "",
    features: {
      url_length: result.features.url_length,
      num_subdomains: result.features.subdomain_count,
      has_https: result.features.has_https,
      url_entropy: result.features.entropy,
      brand_similarity_score: result.features.typosquatting_similarity,
      domain_age_days: parseInt(result.domain_age) || -1,
      ssl_valid: result.features.has_https,
      vt_positives: result.virustotal.positives
    },
    scan_duration_ms: result.scan_duration_ms,
    model_version: "1.0.0"
  };
}
function JsonViewer({ data, indent = 0 }) {
  if (data === null) return <span className="text-slate-500">null</span>;
  if (typeof data === "boolean") return <span className="text-purple-400">{String(data)}</span>;
  if (typeof data === "number") return <span className="text-yellow-400">{data}</span>;
  if (typeof data === "string") return <span className="text-green-400">"{data}"</span>;
  if (Array.isArray(data)) {
    if (data.length === 0) return <span className="text-slate-500">[]</span>;
    return <span>
        {"[\n"}
        {data.map((v, i) => <span key={i}>
            {"  ".repeat(indent + 1)}
            <JsonViewer data={v} indent={indent + 1} />
            {i < data.length - 1 ? "," : ""}{"\n"}
          </span>)}
        {"  ".repeat(indent)}
        {"]"}
      </span>;
  }
  if (typeof data === "object") {
    const entries = Object.entries(data);
    if (entries.length === 0) return <span className="text-slate-500">{"{}"}</span>;
    return <span>
        {"{\n"}
        {entries.map(([k, v], i) => <span key={k}>
            {"  ".repeat(indent + 1)}
            <span className="text-cyan-300">"{k}"</span>
            <span className="text-slate-400">: </span>
            <JsonViewer data={v} indent={indent + 1} />
            {i < entries.length - 1 ? "," : ""}{"\n"}
          </span>)}
        {"  ".repeat(indent)}
        {"}"}
      </span>;
  }
  return <span className="text-slate-300">{String(data)}</span>;
}
function ApiExplorer() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [response, setResponse] = useState(null);
  const [reqTime, setReqTime] = useState(null);
  const [copied, setCopied] = useState(false);
  const timerRef = useRef(0);
  const runScan = useCallback(async (target) => {
    if (!target.trim()) return;
    setScanning(true);
    setResponse(null);
    timerRef.current = Date.now();
    const res = await simulateScan(target);
    const apiResp = buildApiResponse(res);
    setResponse(apiResp);
    setReqTime(Date.now() - timerRef.current);
    setScanning(false);
  }, []);
  const curlCmd = url ? `curl -X POST http://localhost:8000/scan \\
  -H "Content-Type: application/json" \\
  -d '{"url": "${url}"}'` : "";
  const classification = response?.classification;
  const statusColor = classification === "Malicious" || classification === "Suspicious" ? "text-red-400" : classification === "Low Suspicion" ? "text-yellow-400" : "text-green-400";
  return <div className="space-y-4">
      {
    /* Endpoint badges */
  }
      <div className="flex flex-wrap gap-2">
        {[
    { method: "POST", path: "/scan", desc: "Analyze a URL" },
    { method: "GET", path: "/scan/{id}", desc: "Get scan by ID" },
    { method: "GET", path: "/history", desc: "Scan history" },
    { method: "GET", path: "/health", desc: "Service health" },
    { method: "GET", path: "/stats", desc: "Aggregate stats" }
  ].map((e) => <div key={e.path} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700">
            <span className={`font-mono text-xs font-bold ${e.method === "POST" ? "text-cyan-400" : e.method === "DELETE" ? "text-red-400" : "text-green-400"}`}>
              {e.method}
            </span>
            <span className="font-mono text-slate-300" style={{ fontSize: "0.72rem" }}>{e.path}</span>
            <span className="text-slate-500" style={{ fontSize: "0.65rem" }}>— {e.desc}</span>
          </div>)}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {
    /* LEFT: Request panel */
  }
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-4 space-y-3">
          <div className="flex items-center gap-2 text-slate-400" style={{ fontSize: "0.75rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.8px" }}>
            <Terminal size={12} /> Request
          </div>

          {
    /* URL Input */
  }
          <div className="flex gap-2">
            <div className="flex items-center gap-2 px-3 py-2 rounded-l-xl bg-slate-900 border border-r-0 border-slate-600">
              <span className="text-cyan-400 font-mono font-bold" style={{ fontSize: "0.75rem" }}>POST</span>
              <span className="text-slate-500 font-mono" style={{ fontSize: "0.72rem" }}>/scan</span>
            </div>
            <input
    value={url}
    onChange={(e) => setUrl(e.target.value)}
    onKeyDown={(e) => e.key === "Enter" && runScan(url)}
    placeholder="https://example.com"
    className="flex-1 bg-slate-900 border border-slate-600 rounded-r-xl px-3 py-2 text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500/70 font-mono"
    style={{ fontSize: "0.78rem" }}
  />
            <button
    onClick={() => runScan(url)}
    disabled={scanning || !url.trim()}
    className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-slate-950 rounded-xl font-bold transition-colors flex items-center gap-1.5"
    style={{ fontSize: "0.8rem" }}
  >
              {scanning ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
              Send
            </button>
          </div>

          {
    /* Sample requests */
  }
          <div>
            <p className="text-slate-500 mb-2" style={{ fontSize: "0.7rem" }}>Quick examples:</p>
            <div className="flex flex-wrap gap-1.5">
              {SAMPLE_PAYLOADS.map((s) => <button
    key={s.url}
    onClick={() => {
      setUrl(s.url);
      runScan(s.url);
    }}
    className="px-2 py-1 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-600 transition-colors"
    style={{ fontSize: "0.68rem" }}
  >
                  <span className={s.color}>{s.label}</span>
                </button>)}
            </div>
          </div>

          {
    /* Request body */
  }
          <div className="bg-slate-900 rounded-xl border border-slate-700/50 p-3">
            <p className="text-slate-500 mb-2" style={{ fontSize: "0.68rem", fontWeight: 600 }}>REQUEST BODY</p>
            <pre className="font-mono text-slate-300 whitespace-pre-wrap" style={{ fontSize: "0.75rem" }}>
              {`{
  `}<span className="text-cyan-300">"url"</span>{`: `}<span className="text-green-400">"{url || "https://example.com"}"</span>{`
}`}
            </pre>
          </div>

          {
    /* cURL */
  }
          {curlCmd && <div className="relative bg-slate-900 rounded-xl border border-slate-700/50 p-3">
              <p className="text-slate-500 mb-2" style={{ fontSize: "0.68rem", fontWeight: 600 }}>CURL COMMAND</p>
              <pre className="font-mono text-slate-400 whitespace-pre-wrap overflow-x-auto" style={{ fontSize: "0.68rem" }}>{curlCmd}</pre>
              <button
    onClick={async () => {
      await navigator.clipboard.writeText(curlCmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }}
    className="absolute top-2 right-2 p-1.5 rounded-lg bg-slate-800 text-slate-500 hover:text-slate-300"
  >
                {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
              </button>
            </div>}
        </div>

        {
    /* RIGHT: Response panel */
  }
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-slate-400" style={{ fontSize: "0.75rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.8px" }}>
              <Server size={12} /> Response
            </div>
            {response && <div className="flex items-center gap-3">
                <span className={`font-mono font-bold ${statusColor}`} style={{ fontSize: "0.75rem" }}>
                  {response.classification}
                </span>
                <span className="px-2 py-0.5 rounded-full bg-green-500/15 border border-green-500/25 text-green-400 font-mono" style={{ fontSize: "0.7rem" }}>200 OK</span>
                {reqTime && <span className="text-slate-500 font-mono" style={{ fontSize: "0.68rem" }}>{reqTime}ms</span>}
              </div>}
          </div>

          <div className="bg-slate-900 rounded-xl border border-slate-700/50 overflow-auto" style={{ maxHeight: 420, minHeight: 180 }}>
            {scanning && <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Loader2 size={20} className="text-cyan-400 animate-spin" />
                <p className="text-slate-500" style={{ fontSize: "0.8rem" }}>Running detection pipeline…</p>
              </div>}
            {!scanning && !response && <div className="flex flex-col items-center justify-center py-12 gap-2 text-slate-600">
                <Server size={24} />
                <p style={{ fontSize: "0.8rem" }}>Send a request to see the response</p>
              </div>}
            {!scanning && response && <pre className="p-4 font-mono whitespace-pre-wrap" style={{ fontSize: "0.72rem", lineHeight: 1.7 }}>
                <JsonViewer data={response} />
              </pre>}
          </div>
        </div>
      </div>
    </div>;
}
const CYAN = "#06b6d4";
const GREEN = "#22c55e";
const RED = "#ef4444";
const AMBER = "#f59e0b";
function MetricCard({ label, value, unit = "%", color, icon: Icon }) {
  return <div className="bg-slate-800/40 border border-slate-700/40 rounded-2xl p-4 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-slate-400" style={{ fontSize: "0.72rem", textTransform: "uppercase", letterSpacing: "0.8px" }}>{label}</span>
        <div className="p-1.5 rounded-lg" style={{ background: `${color}18` }}>
          <Icon size={13} style={{ color }} />
        </div>
      </div>
      <div className="flex items-end gap-1">
        <span style={{ fontSize: "1.6rem", fontWeight: 800, fontFamily: "monospace", color }}>{value.toFixed(2)}</span>
        <span className="text-slate-500 pb-1" style={{ fontSize: "0.8rem" }}>{unit}</span>
      </div>
      {
    /* Mini bar */
  }
      <div className="h-1 bg-slate-700 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: color }} />
      </div>
    </div>;
}
function ConfusionMatrix() {
  const { tp, fp, fn, tn } = METRICS;
  const total = tp + fp + fn + tn;
  const cells = [
    { label: "True Negative", val: tn, pct: (tn / total * 100).toFixed(1), color: "bg-green-500/20 border-green-500/40 text-green-400" },
    { label: "False Positive", val: fp, pct: (fp / total * 100).toFixed(1), color: "bg-red-500/10   border-red-500/30   text-red-400" },
    { label: "False Negative", val: fn, pct: (fn / total * 100).toFixed(1), color: "bg-orange-500/10 border-orange-500/30 text-orange-400" },
    { label: "True Positive", val: tp, pct: (tp / total * 100).toFixed(1), color: "bg-green-500/20 border-green-500/40 text-green-400" }
  ];
  return <div className="bg-slate-800/40 border border-slate-700/40 rounded-2xl p-4">
      <p className="text-slate-400 mb-3 uppercase tracking-wider" style={{ fontSize: "0.7rem", fontWeight: 600 }}>Confusion Matrix (Test Set — 6,000 samples)</p>
      <div className="flex gap-2 mb-2">
        <div className="w-24" />
        <div className="flex-1 text-center text-slate-500" style={{ fontSize: "0.68rem" }}>Predicted: Legit</div>
        <div className="flex-1 text-center text-slate-500" style={{ fontSize: "0.68rem" }}>Predicted: Phish</div>
      </div>
      <div className="flex gap-2">
        <div className="flex flex-col gap-2 justify-around">
          <div className="text-slate-500 text-right" style={{ fontSize: "0.65rem", lineHeight: 1.4 }}>Actual<br />Legit</div>
          <div className="text-slate-500 text-right" style={{ fontSize: "0.65rem", lineHeight: 1.4 }}>Actual<br />Phish</div>
        </div>
        <div className="flex-1 grid grid-cols-2 gap-2">
          {cells.map((c, i) => <div key={i} className={`rounded-xl border p-3 text-center ${c.color}`}>
              <div style={{ fontSize: "1.2rem", fontWeight: 800, fontFamily: "monospace" }}>{c.val.toLocaleString()}</div>
              <div style={{ fontSize: "0.68rem", opacity: 0.8 }}>{c.pct}%</div>
              <div style={{ fontSize: "0.65rem", opacity: 0.65, marginTop: 2 }}>{c.label}</div>
            </div>)}
        </div>
      </div>
    </div>;
}
function MLMetrics() {
  return <div className="space-y-5">
      {
    /* Metric cards */
  }
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <MetricCard label="Accuracy" value={METRICS.accuracy} color={GREEN} icon={CheckCircle} />
        <MetricCard label="Precision" value={METRICS.precision} color={CYAN} icon={TrendingUp} />
        <MetricCard label="Recall" value={METRICS.recall} color={CYAN} icon={Activity} />
        <MetricCard label="F1 Score" value={METRICS.f1} color={CYAN} icon={BarChart3} />
        <MetricCard label="AUC-ROC" value={METRICS.auc_roc} color={AMBER} icon={Shield} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {
    /* Feature importance */
  }
        <div className="bg-slate-800/40 border border-slate-700/40 rounded-2xl p-4">
          <p className="text-slate-400 mb-4 uppercase tracking-wider" style={{ fontSize: "0.7rem", fontWeight: 600 }}>Feature Importance (XGBoost gain)</p>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={FEATURE_IMPORTANCES} layout="vertical" margin={{ left: 10, right: 30 }}>
              <CartesianGrid key="fi-grid" strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis key="fi-xaxis" type="number" tick={{ fill: "#64748b", fontSize: 10 }} tickFormatter={(v) => v.toFixed(2)} />
              <YAxis key="fi-yaxis" type="category" dataKey="feature" tick={{ fill: "#94a3b8", fontSize: 10 }} width={155} />
              <Tooltip
    contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, fontSize: 11 }}
    labelStyle={{ color: "#94a3b8" }}
    key="fi-tooltip" formatter={(v) => [v.toFixed(4), "Importance"]}
  />
              <Bar key="fi-bar" dataKey="importance" name="importance" radius={[0, 4, 4, 0]} maxBarSize={14}>
                {FEATURE_IMPORTANCES.map((item, i) => <Cell key={item.feature} fill={i < 3 ? "#06b6d4" : i < 6 ? "#22d3ee" : "#0e7490"} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {
    /* Confusion matrix + training curves */
  }
        <div className="space-y-4">
          <ConfusionMatrix />
          <div className="bg-slate-800/40 border border-slate-700/40 rounded-2xl p-4">
            <p className="text-slate-400 mb-3 uppercase tracking-wider" style={{ fontSize: "0.7rem", fontWeight: 600 }}>Training History (Accuracy %)</p>
            <ResponsiveContainer width="100%" height={130}>
              <LineChart data={TRAINING_HISTORY} margin={{ left: -10, right: 10 }}>
                <CartesianGrid key="th-grid" strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis key="th-xaxis" dataKey="epoch" tick={{ fill: "#64748b", fontSize: 9 }} label={{ value: "Estimators", position: "insideBottom", offset: -2, fill: "#475569", fontSize: 9 }} />
                <YAxis key="th-yaxis" tick={{ fill: "#64748b", fontSize: 9 }} domain={[85, 100]} />
                <Tooltip key="th-tooltip" contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, fontSize: 10 }} />
                <Line key="train-acc" type="monotone" dataKey="train_acc" stroke={CYAN} dot={false} strokeWidth={2} name="Train Acc" />
                <Line key="val-acc" type="monotone" dataKey="val_acc" stroke={GREEN} dot={false} strokeWidth={2} name="Val Acc" strokeDasharray="4 2" />
                <Legend key="th-legend" wrapperStyle={{ fontSize: 10, paddingTop: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {
    /* Dataset stats */
  }
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
    { label: "Training Samples", val: "24,000", icon: Database },
    { label: "Test Samples", val: "6,000", icon: BarChart3 },
    { label: "Features", val: "26", icon: GitBranch },
    { label: "CV Folds", val: "5", icon: TrendingUp }
  ].map(({ label, val, icon: Icon }) => <div key={label} className="bg-slate-800/30 border border-slate-700/40 rounded-xl p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              <Icon size={13} className="text-cyan-400" />
            </div>
            <div>
              <p className="text-slate-200 font-mono" style={{ fontSize: "1rem", fontWeight: 700 }}>{val}</p>
              <p className="text-slate-500" style={{ fontSize: "0.68rem" }}>{label}</p>
            </div>
          </div>)}
      </div>
    </div>;
}
function ArchitectureView() {
  const nodes = [
    { id: "chrome", label: "Chrome Extension", sub: "Manifest V3 / popup.js", color: "border-cyan-500/40 bg-cyan-500/8", dot: "bg-cyan-400", x: 0 },
    { id: "react", label: "React Dashboard", sub: "SOC Analyst UI / Recharts", color: "border-blue-500/40 bg-blue-500/8", dot: "bg-blue-400", x: 0 },
    { id: "api", label: "FastAPI Backend", sub: "POST /scan  \u2014 uvicorn", color: "border-purple-500/40 bg-purple-500/8", dot: "bg-purple-400", x: 1 },
    { id: "feature", label: "Feature Extractor", sub: "26-dim vector from URL", color: "border-indigo-500/40 bg-indigo-500/8", dot: "bg-indigo-400", x: 1 },
    { id: "ml", label: "XGBoost Model", sub: "phishing_model.pkl / 96.8% acc", color: "border-yellow-500/40 bg-yellow-500/8", dot: "bg-yellow-400", x: 2 },
    { id: "vt", label: "VirusTotal API", sub: "90 AV engines", color: "border-red-500/40 bg-red-500/8", dot: "bg-red-400", x: 2 },
    { id: "urlhaus", label: "URLHaus", sub: "Abuse.ch malware feed", color: "border-orange-500/40 bg-orange-500/8", dot: "bg-orange-400", x: 2 },
    { id: "whois", label: "WHOIS / DNS", sub: "Domain age + records", color: "border-green-500/40 bg-green-500/8", dot: "bg-green-400", x: 2 },
    { id: "ssl", label: "SSL Checker", sub: "Certificate validation", color: "border-teal-500/40 bg-teal-500/8", dot: "bg-teal-400", x: 2 }
  ];
  const cols = [
    { title: "Clients", items: nodes.filter((n) => n.x === 0) },
    { title: "Backend Core", items: nodes.filter((n) => n.x === 1) },
    { title: "Services / Signals", items: nodes.filter((n) => n.x === 2) }
  ];
  const steps = [
    { n: 1, text: "URL submitted via Chrome Extension or React dashboard" },
    { n: 2, text: "FastAPI receives POST /scan, generates scan_id" },
    { n: 3, text: "Concurrent async lookups: VT + URLHaus + WHOIS + DNS + SSL" },
    { n: 4, text: "Feature extractor builds 26-dim vector from all signals" },
    { n: 5, text: "XGBoost model predicts phishing probability [0\u20131]" },
    { n: 6, text: "Risk score mapped \u2192 classification + attack vectors + IoCs" },
    { n: 7, text: "Structured JSON response returned in < 600ms" }
  ];
  return <div className="space-y-5">
      {
    /* Pipeline diagram */
  }
      <div className="grid grid-cols-3 gap-3">
        {cols.map((col, ci) => <div key={col.title} className="space-y-2">
            <p className="text-slate-500 uppercase tracking-wider text-center" style={{ fontSize: "0.65rem", fontWeight: 600 }}>{col.title}</p>
            {col.items.map((node) => <div key={node.id} className={`rounded-xl border p-3 ${node.color}`}>
                <div className="flex items-center gap-2 mb-0.5">
                  <div className={`w-2 h-2 rounded-full ${node.dot}`} />
                  <span className="text-slate-200" style={{ fontSize: "0.78rem", fontWeight: 600 }}>{node.label}</span>
                </div>
                <p className="text-slate-500" style={{ fontSize: "0.68rem" }}>{node.sub}</p>
              </div>)}
            {ci < 2 && <div className="flex justify-center pt-1">
                <ArrowRight size={16} className="text-slate-600" />
              </div>}
          </div>)}
      </div>

      {
    /* Request pipeline steps */
  }
      <div className="bg-slate-800/40 border border-slate-700/40 rounded-2xl p-4">
        <p className="text-slate-400 mb-4 uppercase tracking-wider" style={{ fontSize: "0.7rem", fontWeight: 600 }}>Detection Pipeline — Step by Step</p>
        <div className="space-y-2">
          {steps.map((s) => <div key={s.n} className="flex items-start gap-3">
              <div className="shrink-0 w-5 h-5 rounded-full bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
                <span className="text-cyan-400 font-mono" style={{ fontSize: "0.68rem", fontWeight: 700 }}>{s.n}</span>
              </div>
              <p className="text-slate-400" style={{ fontSize: "0.78rem", lineHeight: 1.55, paddingTop: 2 }}>{s.text}</p>
            </div>)}
        </div>
      </div>

      {
    /* Tech stack grid */
  }
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {[
    { cat: "Web Framework", items: ["FastAPI 0.104", "uvicorn[standard]", "Pydantic v2"] },
    { cat: "ML Stack", items: ["XGBoost 2.0", "scikit-learn 1.3", "joblib + SMOTE"] },
    { cat: "CTI Services", items: ["VirusTotal v3 API", "URLHaus REST API", "PhishTank API"] },
    { cat: "Domain Intel", items: ["python-whois", "dnspython", "tldextract"] },
    { cat: "Similarity", items: ["rapidfuzz (Levenshtein)", "Unicode normalisation", "L33t-speak decoder"] },
    { cat: "SSL / Certs", items: ["pyOpenSSL", "Python ssl module", "socket / TLS handshake"] }
  ].map(({ cat, items }) => <div key={cat} className="bg-slate-800/30 border border-slate-700/40 rounded-xl p-3">
            <p className="text-cyan-400 mb-2" style={{ fontSize: "0.7rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.7px" }}>{cat}</p>
            {items.map((item) => <div key={item} className="flex items-center gap-1.5 py-0.5">
                <div className="w-1 h-1 rounded-full bg-slate-600" />
                <span className="text-slate-400" style={{ fontSize: "0.72rem" }}>{item}</span>
              </div>)}
          </div>)}
      </div>
    </div>;
}
function SourceCodeViewer() {
  const [activeKey, setActiveKey] = useState("");
  const [code, setCode] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const loadFile = async (key) => {
    setActiveKey(key);
    setLoading(true);
    try {
      const res = await fetch(CODE_FILES[key].path);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setCode(await res.text());
    } catch {
      setCode(`# Could not load file.\n# Path: ${CODE_FILES[key].path}\n# Run: uvicorn main:app --reload`);
    }
    setLoading(false);
  };
  return <div className="space-y-4">
      <div className="flex items-start gap-2 px-3 py-2.5 rounded-xl bg-cyan-500/5 border border-cyan-500/15">
        <Info size={13} className="text-cyan-400 shrink-0 mt-0.5" />
        <p className="text-slate-400" style={{ fontSize: "0.75rem", lineHeight: 1.6 }}>
          All Python source files live in <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">/backend/</code>.
          Run <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">pip install -r requirements.txt</code> then
          <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded"> python train_model.py</code> to generate the model,
          then <code className="text-cyan-300 font-mono bg-slate-800 px-1 rounded">uvicorn main:app --reload</code> to start the API.
        </p>
      </div>

      {
    /* File tabs */
  }
      <div className="flex flex-wrap gap-2">
        {Object.entries(CODE_FILES).map(([key, f]) => <button
    key={key}
    onClick={() => loadFile(key)}
    className={`px-3 py-1.5 rounded-lg border transition-all ${activeKey === key ? "bg-cyan-500/15 border-cyan-500/30 text-cyan-400" : "bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200"}`}
    style={{ fontSize: "0.75rem", fontWeight: activeKey === key ? 600 : 400 }}
  >
            {f.name}
          </button>)}
        {code && <button
    onClick={async () => {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(null), 1500);
    }}
    className="ml-auto px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 flex items-center gap-1.5"
    style={{ fontSize: "0.73rem" }}
  >
            {copied ? <><Check size={11} className="text-green-400" /> Copied</> : <><Copy size={11} /> Copy</>}
          </button>}
      </div>

      {
    /* Code display */
  }
      <div className="bg-slate-900 border border-slate-700 rounded-2xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-800/70 border-b border-slate-700">
          <div className="flex items-center gap-2">
            <Code2 size={12} className="text-cyan-400" />
            <span className="text-slate-300 font-mono" style={{ fontSize: "0.75rem" }}>
              {code ? CODE_FILES[activeKey]?.name : "Select a file to view source"}
            </span>
          </div>
          {code && <span className="text-slate-600 font-mono" style={{ fontSize: "0.68rem" }}>
              Python · {code.split("\n").length} lines
            </span>}
        </div>
        {loading && <div className="flex justify-center py-10"><Loader2 size={18} className="text-cyan-400 animate-spin" /></div>}
        {!loading && !code && <div className="flex flex-col items-center justify-center py-14 gap-2 text-slate-600">
            <Code2 size={24} />
            <p style={{ fontSize: "0.8rem" }}>Click a file tab above to view source code</p>
          </div>}
        {!loading && code && <pre className="overflow-auto p-4 text-slate-300 font-mono" style={{ fontSize: "0.72rem", lineHeight: 1.7, maxHeight: 520 }}>
            <code>{code}</code>
          </pre>}
      </div>
    </div>;
}
function BackendPage() {
  const [tab, setTab] = useState("explorer");
  const TABS = [
    { id: "explorer", label: "API Explorer", icon: Terminal },
    { id: "metrics", label: "ML Performance", icon: BarChart3 },
    { id: "architecture", label: "Architecture", icon: GitBranch },
    { id: "code", label: "Source Code", icon: Code2 }
  ];
  return <div className="p-6 max-w-6xl mx-auto space-y-6">

      {
    /* Hero */
  }
      <div className="bg-gradient-to-r from-slate-800/50 to-purple-900/15 border border-slate-700/50 rounded-2xl p-5">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-purple-500/15 border border-purple-500/25">
            <Server size={22} className="text-purple-400" />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-slate-100" style={{ fontSize: "1.05rem", fontWeight: 700 }}>
                ML Model + FastAPI Backend
              </h2>
              <span className="px-2 py-0.5 rounded-full bg-purple-500/15 border border-purple-500/25 text-purple-400" style={{ fontSize: "0.65rem", fontWeight: 600 }}>XGBoost</span>
              <span className="px-2 py-0.5 rounded-full bg-cyan-500/15 border border-cyan-500/25 text-cyan-400" style={{ fontSize: "0.65rem", fontWeight: 600 }}>FastAPI</span>
              <span className="px-2 py-0.5 rounded-full bg-green-500/15 border border-green-500/25 text-green-400" style={{ fontSize: "0.65rem", fontWeight: 600 }}>96.8% Acc</span>
            </div>
            <p className="text-slate-400 mt-1.5" style={{ fontSize: "0.82rem", lineHeight: 1.6 }}>
              A production-ready phishing detection system with a serialised XGBoost classifier (30,000 training samples, 26 features),
              concurrent CTI lookups (VirusTotal, URLHaus, PhishTank), and a REST API serving sub-600ms responses.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              {["26 ML Features", "XGBoost + SMOTE", "POST /scan endpoint", "Async CTI Lookups", "WHOIS + DNS + SSL", "Heuristic Fallback"].map((f) => <span key={f} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/60 border border-slate-700/40">
                  <div className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                  <span className="text-slate-400" style={{ fontSize: "0.7rem" }}>{f}</span>
                </span>)}
            </div>
          </div>
        </div>
      </div>

      {
    /* Quick-start commands */
  }
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {[
    { step: "1", label: "Install dependencies", cmd: "pip install -r requirements.txt", color: "border-cyan-500/25 bg-cyan-500/5" },
    { step: "2", label: "Train the model", cmd: "python train_model.py", color: "border-yellow-500/25 bg-yellow-500/5" },
    { step: "3", label: "Start the API", cmd: "uvicorn main:app --reload", color: "border-green-500/25 bg-green-500/5" }
  ].map(({ step, label, cmd, color }) => <div key={step} className={`rounded-xl border p-3 ${color}`}>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="w-5 h-5 rounded-full bg-slate-800 border border-slate-600 flex items-center justify-center text-slate-400 font-mono shrink-0" style={{ fontSize: "0.65rem" }}>{step}</span>
              <span className="text-slate-300" style={{ fontSize: "0.75rem", fontWeight: 600 }}>{label}</span>
            </div>
            <code className="block font-mono text-cyan-300 bg-slate-900/70 rounded-lg px-3 py-1.5" style={{ fontSize: "0.72rem" }}>
              {cmd}
            </code>
          </div>)}
      </div>

      {
    /* Tabs */
  }
      <div className="flex gap-2 border-b border-slate-800 pb-0">
        {TABS.map(({ id, label, icon: Icon }) => <button
    key={id}
    onClick={() => setTab(id)}
    className={`flex items-center gap-2 px-4 py-2.5 rounded-t-xl border-b-2 transition-all ${tab === id ? "text-purple-400 border-purple-400 bg-purple-500/5" : "text-slate-500 border-transparent hover:text-slate-300 hover:bg-slate-800/40"}`}
    style={{ fontSize: "0.825rem", fontWeight: tab === id ? 600 : 400 }}
  >
            <Icon size={14} />
            {label}
          </button>)}
      </div>

      <div className="mt-2">
        {tab === "explorer" && <ApiExplorer />}
        {tab === "metrics" && <MLMetrics />}
        {tab === "architecture" && <ArchitectureView />}
        {tab === "code" && <SourceCodeViewer />}
      </div>
    </div>;
}
export {
  BackendPage
};
