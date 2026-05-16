import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  Zap,
  Activity,
  Clock,
  ExternalLink,
  ArrowRight,
  Radio,
  RefreshCw,
  Cpu,
  Database,
  Wifi,
  WifiOff,
  TrendingDown,
  Eye
} from "lucide-react";
import { Link } from "react-router";
import { useMemo, useState, useEffect } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  BarChart,
  Bar,
  LabelList
} from "recharts";
import { useId } from "react";
import { useScanContext } from "../context/ScanContext";
import { ThreatBadge } from "../components/ThreatBadge";
const TooltipBox = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return <div className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 shadow-xl">
      {label && <p className="text-slate-400 mb-1" style={{ fontSize: "0.72rem" }}>{label}</p>}
      {payload.map((p, i) => <p key={`tip-item-${i}`} style={{ color: p.color || p.fill, fontSize: "0.78rem" }}>
          {p.name}: <span style={{ fontWeight: 600 }}>{p.value}</span>
        </p>)}
    </div>;
};
function computeStats(scans) {
  if (!scans.length) return {
    total: 0,
    phishing: 0,
    suspicious: 0,
    safe: 0,
    avgRisk: 0,
    avgConf: 0,
    avgDuration: 0,
    urlhausHits: 0,
    phishtankHits: 0,
    phishingPct: "0.0",
    vtAvgPositives: 0
  };
  const phishing = scans.filter((s) => s.prediction === "phishing").length;
  const suspicious = scans.filter((s) => s.prediction === "suspicious").length;
  const safe = scans.filter((s) => s.prediction === "safe").length;
  const avgRisk = scans.reduce((a, s) => a + s.risk_score, 0) / scans.length;
  const avgConf = scans.reduce((a, s) => a + s.confidence, 0) / scans.length;
  const avgDuration = Math.round(scans.reduce((a, s) => a + s.scan_duration_ms, 0) / scans.length);
  const urlhausHits = scans.filter((s) => s.urlhaus_listed).length;
  const phishtankHits = scans.filter((s) => s.phishtank_listed).length;
  const vtAvgPositives = parseFloat(
    (scans.reduce((a, s) => a + s.virustotal.positives, 0) / scans.length).toFixed(1)
  );
  return {
    total: scans.length,
    phishing,
    suspicious,
    safe,
    avgRisk: parseFloat(avgRisk.toFixed(1)),
    avgConf: parseFloat((avgConf * 100).toFixed(1)),
    avgDuration,
    urlhausHits,
    phishtankHits,
    vtAvgPositives,
    phishingPct: scans.length ? (phishing / scans.length * 100).toFixed(1) : "0.0"
  };
}
function buildTimeSeries(scans) {
  const days = {};
  const today = /* @__PURE__ */ new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().split("T")[0];
    const label = d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
    days[key] = { date: label, phishing: 0, suspicious: 0, safe: 0, scans: 0 };
  }
  for (const s of scans) {
    const key = s.timestamp.split("T")[0];
    if (days[key]) {
      days[key][s.prediction]++;
      days[key].scans++;
    }
  }
  return Object.values(days);
}
function buildRiskBuckets(scans) {
  const buckets = [
    { range: "0-10", count: 0, fill: "#22c55e" },
    { range: "11-30", count: 0, fill: "#84cc16" },
    { range: "31-50", count: 0, fill: "#f59e0b" },
    { range: "51-70", count: 0, fill: "#f97316" },
    { range: "71-90", count: 0, fill: "#ef4444" },
    { range: "91-100", count: 0, fill: "#dc2626" }
  ];
  for (const s of scans) {
    const r = s.risk_score;
    if (r <= 10) buckets[0].count++;
    else if (r <= 30) buckets[1].count++;
    else if (r <= 50) buckets[2].count++;
    else if (r <= 70) buckets[3].count++;
    else if (r <= 90) buckets[4].count++;
    else buckets[5].count++;
  }
  return buckets;
}
function topIndicators(scans) {
  const freq = {};
  for (const s of scans) {
    for (const ind of s.threat_indicators) {
      const key = ind.includes("BRAND") || ind.includes("impersonation") ? "Brand Impersonation" : ind.includes("TYPO") || ind.includes("Levenshtein") ? "Typosquatting" : ind.includes("HTTP only") ? "No HTTPS" : ind.includes("URLHaus") ? "URLHaus Listed" : ind.includes("PhishTank") ? "PhishTank Listed" : ind.includes("IP-based") ? "IP-based URL" : ind.includes("keyword") || ind.includes("Keywords") ? "Suspicious Keywords" : ind.includes("HOMOGLYPH") || ind.includes("Unicode") ? "Homoglyph Attack" : ind.includes("L33T") || ind.includes("Digit") ? "L33t Substitution" : ind.includes("SUBDOMAIN") ? "Subdomain Abuse" : ind.includes("HYPHEN") ? "Hyphen Abuse" : ind.includes("DGA") ? "DGA Domain" : ind.includes("TLD") ? "Suspicious TLD" : ind.includes("New domain") ? "New Domain" : null;
      if (key) freq[key] = (freq[key] || 0) + 1;
    }
  }
  return Object.entries(freq).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 8);
}
function StatCard({ label, value, sub, icon: Icon, iconColor, iconBg, trend, live = false }) {
  return <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
      <div className="flex items-start justify-between mb-4">
        <div className={`p-2.5 rounded-xl ${iconBg} relative`}>
          <Icon size={18} className={iconColor} />
          {live && <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-green-400 border border-slate-900 animate-pulse" />}
        </div>
        {trend && <div className={`flex items-center gap-1 px-2 py-1 rounded-lg ${trend.value >= 0 ? "bg-red-500/10 text-red-400" : "bg-green-500/10 text-green-400"}`}>
            {trend.value >= 0 ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
            <span style={{ fontSize: "0.68rem", fontWeight: 600 }}>
              {trend.value >= 0 ? "+" : ""}{trend.value}%
            </span>
          </div>}
      </div>
      <p className="text-slate-200" style={{ fontSize: "1.6rem", fontWeight: 700, lineHeight: 1 }}>{value}</p>
      <p className="text-slate-400 mt-1" style={{ fontSize: "0.8rem" }}>{label}</p>
      {sub && <p className="text-slate-600 mt-0.5" style={{ fontSize: "0.72rem" }}>{sub}</p>}
    </div>;
}
function RecentScanRow({ scan, isNew }) {
  return <div className={`flex items-center gap-3 py-3 border-b border-slate-800/60 last:border-0 group transition-colors ${isNew ? "bg-cyan-500/5 -mx-5 px-5" : ""}`}>
      <div className={`w-2 h-2 rounded-full shrink-0 ${scan.prediction === "phishing" ? "bg-red-400 shadow-[0_0_6px_#f87171]" : scan.prediction === "suspicious" ? "bg-yellow-400" : "bg-green-400"}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <p className="text-slate-300 truncate font-mono" style={{ fontSize: "0.78rem" }}>{scan.domain}</p>
          {isNew && <span className="shrink-0 px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400" style={{ fontSize: "0.6rem" }}>NEW</span>}
        </div>
        <p className="text-slate-600 font-mono" style={{ fontSize: "0.65rem" }}>
          {new Date(scan.timestamp).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}
          {" \xB7 "}Risk {scan.risk_score}
          {scan.urlhaus_listed ? " \xB7 \u26A0 URLHaus" : ""}
        </p>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <ThreatBadge level={scan.prediction} size="sm" showDot={false} />
        <span className={`font-mono ${scan.risk_score >= 70 ? "text-red-400" : scan.risk_score >= 40 ? "text-yellow-400" : "text-green-400"}`} style={{ fontSize: "0.78rem" }}>{scan.risk_score}</span>
        <a
    href={scan.url}
    target="_blank"
    rel="noopener noreferrer"
    className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-600 hover:text-cyan-400"
  >
          <ExternalLink size={12} />
        </a>
      </div>
    </div>;
}
function LiveThreatFeed({ scans }) {
  const threats = scans.filter((s) => s.prediction !== "safe").slice(0, 6);
  return <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5 h-full">
      <div className="flex items-center gap-2 mb-4">
        <Radio size={14} className="text-red-400 animate-pulse" />
        <h3 className="text-slate-200" style={{ fontSize: "0.9rem", fontWeight: 600 }}>Live Threat Feed</h3>
        <span className="ml-auto px-2 py-0.5 rounded-full bg-red-500/15 border border-red-500/25 text-red-400 font-mono" style={{ fontSize: "0.6rem" }}>
          LIVE
        </span>
      </div>
      <div className="space-y-2">
        {threats.length === 0 && <p className="text-slate-600 text-center py-4" style={{ fontSize: "0.78rem" }}>No active threats</p>}
        {threats.map((s) => <div key={s.id} className="flex items-start gap-3 px-3 py-2 rounded-xl bg-slate-900/50 border border-slate-700/30">
            <div className={`mt-0.5 w-1.5 h-1.5 rounded-full shrink-0 ${s.prediction === "phishing" ? "bg-red-400 animate-pulse" : "bg-yellow-400"}`} />
            <div className="flex-1 min-w-0">
              <p className="text-slate-300 font-mono truncate" style={{ fontSize: "0.72rem" }}>{s.domain}</p>
              <p className="text-slate-500 mt-0.5 truncate" style={{ fontSize: "0.65rem" }}>
                {s.threat_indicators[0]?.replace(/\[.*?\] /, "").slice(0, 60)}...
              </p>
            </div>
            <div className="text-right shrink-0">
              <p
    className={`font-mono ${s.risk_score >= 70 ? "text-red-400" : "text-yellow-400"}`}
    style={{ fontSize: "0.8rem", fontWeight: 700 }}
  >{s.risk_score}</p>
              <p className="text-slate-600" style={{ fontSize: "0.6rem" }}>
                {new Date(s.timestamp).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}
              </p>
            </div>
          </div>)}
      </div>
    </div>;
}
const SYSTEM_SERVICES = [
  { label: "XGBoost ML Model", ok: true, latency: "12ms" },
  { label: "FastAPI Backend", ok: true, latency: "8ms" },
  { label: "VirusTotal API", ok: true, latency: "340ms" },
  { label: "URLHaus Feed", ok: true, latency: "120ms" },
  { label: "PhishTank DB", ok: true, latency: "95ms" },
  { label: "WHOIS Service", ok: false, latency: "\u2014" },
  { label: "PostgreSQL DB", ok: true, latency: "4ms" },
  { label: "DNS Resolver", ok: true, latency: "28ms" }
];
function DashboardPage() {
  const { allScans, userScans } = useScanContext();
  const uid = useId().replace(/:/g, "");
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 1e4);
    return () => clearInterval(t);
  }, []);
  const stats = useMemo(() => computeStats(allScans), [allScans]);
  const timeSeries = useMemo(() => buildTimeSeries(allScans), [allScans]);
  const riskBuckets = useMemo(() => buildRiskBuckets(allScans), [allScans]);
  const indicators = useMemo(() => topIndicators(allScans), [allScans]);
  const recentScans = useMemo(() => allScans.slice(0, 8), [allScans]);
  const newScanIds = new Set(userScans.slice(0, 3).map((s) => s.id));
  const donutData = [
    { name: "Phishing", value: stats.phishing, color: "#ef4444" },
    { name: "Suspicious", value: stats.suspicious, color: "#f59e0b" },
    { name: "Safe", value: stats.safe, color: "#22c55e" }
  ].filter((d) => d.value > 0);
  const gP = `dash-gP-${uid}`;
  const gS = `dash-gS-${uid}`;
  const gSus = `dash-gSus-${uid}`;
  const phishingTrend = stats.total > 0 ? Math.round(stats.phishing / Math.max(stats.total, 1) * 100 - 35) : 0;
  return <div className="p-6 space-y-6 max-w-7xl mx-auto">

      {
    /* Live badge + New Scan */
  }
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/20">
          <Radio size={12} className="text-green-400 animate-pulse" />
          <span className="text-green-400" style={{ fontSize: "0.72rem", fontWeight: 600 }}>
            LIVE — {stats.total} scans loaded · updates on every new scan
          </span>
        </div>
        <Link
    to="/scanner"
    className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors"
    style={{ fontSize: "0.85rem", fontWeight: 700 }}
  >
          <Search size={15} /> New Scan
        </Link>
      </div>

      {
    /* Primary stat cards */
  }
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
    label="Total Scans"
    value={stats.total.toLocaleString()}
    sub="All-time (mock + live)"
    icon={Search}
    iconColor="text-cyan-400"
    iconBg="bg-cyan-500/15"
    live
    trend={{ value: userScans.length > 0 ? userScans.length : 0, label: "new" }}
  />
        <StatCard
    label="Phishing Detected"
    value={stats.phishing}
    sub={`${stats.phishingPct}% of all scans`}
    icon={AlertTriangle}
    iconColor="text-red-400"
    iconBg="bg-red-500/15"
    live
    trend={{ value: phishingTrend, label: "threat rate" }}
  />
        <StatCard
    label="Safe URLs"
    value={stats.safe}
    sub="Confirmed clean"
    icon={CheckCircle}
    iconColor="text-green-400"
    iconBg="bg-green-500/15"
  />
        <StatCard
    label="Avg Risk Score"
    value={stats.avgRisk}
    sub="/100 across all scans"
    icon={Activity}
    iconColor="text-yellow-400"
    iconBg="bg-yellow-500/15"
  />
      </div>

      {
    /* Secondary metrics */
  }
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
    { icon: Clock, color: "text-cyan-400", label: "Avg Scan Time", val: `${stats.avgDuration}ms` },
    { icon: Shield, color: "text-red-400", label: "PhishTank Hits", val: stats.phishtankHits },
    { icon: Zap, color: "text-orange-400", label: "URLHaus Hits", val: stats.urlhausHits },
    { icon: Activity, color: "text-purple-400", label: "Suspicious URLs", val: stats.suspicious }
  ].map(({ icon: Icon, color, label, val }) => <div key={label} className="bg-slate-800/30 border border-slate-700/30 rounded-xl px-4 py-3 flex items-center gap-3">
            <Icon size={15} className={`${color} shrink-0`} />
            <div>
              <p className="text-slate-200 font-mono" style={{ fontSize: "0.9rem", fontWeight: 600 }}>{val}</p>
              <p className="text-slate-500" style={{ fontSize: "0.7rem" }}>{label}</p>
            </div>
          </div>)}
      </div>

      {
    /* Charts row — Donut + Area trend */
  }
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
          <h3 className="text-slate-200 mb-1" style={{ fontSize: "0.9rem", fontWeight: 600 }}>Threat Distribution</h3>
          <p className="text-slate-500 mb-4" style={{ fontSize: "0.72rem" }}>Live classification breakdown</p>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
    key={`donut-pie-${uid}`}
    data={donutData}
    cx="50%"
    cy="50%"
    innerRadius={60}
    outerRadius={90}
    paddingAngle={3}
    dataKey="value"
    labelLine={false}
    label={({ percent }) => percent > 0.06 ? `${(percent * 100).toFixed(0)}%` : ""}
  >
                {donutData.map((entry) => <Cell key={`donut-cell-${uid}-${entry.name}`} fill={entry.color} />)}
              </Pie>
              <Tooltip key={`donut-tooltip-${uid}`} content={<TooltipBox />} />
              <Legend key={`donut-legend-${uid}`} formatter={(v) => <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="lg:col-span-2 bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
          <h3 className="text-slate-200 mb-1" style={{ fontSize: "0.9rem", fontWeight: 600 }}>14-Day Scan Activity</h3>
          <p className="text-slate-500 mb-4" style={{ fontSize: "0.72rem" }}>Daily breakdown — updates after each scan</p>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timeSeries} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id={gP} x1="0" y1="0" x2="0" y2="1">
                  <stop key={`${gP}-s1`} offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
                  <stop key={`${gP}-s2`} offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id={gS} x1="0" y1="0" x2="0" y2="1">
                  <stop key={`${gS}-s1`} offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                  <stop key={`${gS}-s2`} offset="95%" stopColor="#22c55e" stopOpacity={0} />
                </linearGradient>
                <linearGradient id={gSus} x1="0" y1="0" x2="0" y2="1">
                  <stop key={`${gSus}-s1`} offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                  <stop key={`${gSus}-s2`} offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid key={`area-grid-${uid}`} strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis key={`area-xaxis-${uid}`} dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis key={`area-yaxis-${uid}`} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip key={`area-tooltip-${uid}`} content={<TooltipBox />} />
              <Legend key={`area-legend-${uid}`} formatter={(v) => <span style={{ color: "#94a3b8", fontSize: "0.75rem" }}>{v}</span>} />
              <Area key={`area-phishing-${uid}`} type="monotone" dataKey="phishing" name="Phishing" stroke="#ef4444" strokeWidth={2} fill={`url(#${gP})`} dot={false} />
              <Area key={`area-safe-${uid}`} type="monotone" dataKey="safe" name="Safe" stroke="#22c55e" strokeWidth={2} fill={`url(#${gS})`} dot={false} />
              <Area key={`area-suspicious-${uid}`} type="monotone" dataKey="suspicious" name="Suspicious" stroke="#f59e0b" strokeWidth={2} fill={`url(#${gSus})`} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {
    /* Risk histogram + Top IOCs */
  }
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
          <h3 className="text-slate-200 mb-1" style={{ fontSize: "0.9rem", fontWeight: 600 }}>Risk Score Distribution</h3>
          <p className="text-slate-500 mb-4" style={{ fontSize: "0.72rem" }}>Live scan count per risk bucket</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={riskBuckets} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
              <CartesianGrid key={`bar-grid-${uid}`} strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis key={`bar-xaxis-${uid}`} dataKey="range" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis key={`bar-yaxis-${uid}`} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip key={`bar-tooltip-${uid}`} content={<TooltipBox />} />
              <Bar key={`bar-bars-${uid}`} dataKey="count" name="Scans" radius={[4, 4, 0, 0]}>
                {riskBuckets.map((bucket) => <Cell key={`risk-cell-${uid}-${bucket.range}`} fill={bucket.fill} />)}
                <LabelList key={`bar-labels-${uid}`} dataKey="count" position="top" style={{ fill: "#94a3b8", fontSize: 10 }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
          <h3 className="text-slate-200 mb-1" style={{ fontSize: "0.9rem", fontWeight: 600 }}>Top Threat Indicators</h3>
          <p className="text-slate-500 mb-4" style={{ fontSize: "0.72rem" }}>Most frequent IOC signals across all scans</p>
          {indicators.length === 0 ? <div className="flex items-center justify-center h-32 text-slate-600" style={{ fontSize: "0.78rem" }}>
              No threat data yet — run some scans
            </div> : <div className="space-y-2">
              {indicators.slice(0, 7).map(({ name, count }) => {
    const pct = Math.round(count / Math.max(...indicators.map((ind) => ind.count)) * 100);
    return <div key={name} className="flex items-center gap-3">
                    <span className="text-slate-400 w-36 shrink-0 truncate" style={{ fontSize: "0.72rem" }}>{name}</span>
                    <div className="flex-1 bg-slate-700/40 rounded-full h-2">
                      <div className="h-2 rounded-full bg-cyan-500/70 transition-all" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-slate-400 w-8 text-right font-mono" style={{ fontSize: "0.7rem" }}>{count}</span>
                  </div>;
  })}
            </div>}
        </div>
      </div>

      {
    /* Bottom row — Recent scans, Threat feed, System status */
  }
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Eye size={14} className="text-cyan-400" />
              <h3 className="text-slate-200" style={{ fontSize: "0.9rem", fontWeight: 600 }}>Recent Scans</h3>
            </div>
            <Link
    to="/history"
    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
    style={{ fontSize: "0.75rem" }}
  >
              All <ArrowRight size={12} />
            </Link>
          </div>
          {recentScans.map((scan) => <RecentScanRow key={scan.id} scan={scan} isNew={newScanIds.has(scan.id)} />)}
        </div>

        <LiveThreatFeed scans={allScans} />

        <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-slate-200" style={{ fontSize: "0.9rem", fontWeight: 600 }}>System Status</h3>
            <button
    onClick={() => setTick((t) => t + 1)}
    className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-700 transition-colors"
    title="Refresh status"
  >
              <RefreshCw size={13} />
            </button>
          </div>
          <div className="space-y-3">
            {SYSTEM_SERVICES.map(({ label, ok, latency }) => <div key={label} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-green-400 animate-pulse" : "bg-yellow-400"}`} />
                  <span className="text-slate-400" style={{ fontSize: "0.775rem" }}>{label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-600 font-mono" style={{ fontSize: "0.65rem" }}>{latency}</span>
                  {ok ? <Wifi size={11} className="text-green-400" /> : <WifiOff size={11} className="text-yellow-400" />}
                </div>
              </div>)}
          </div>
          <div className="mt-5 pt-4 border-t border-slate-700/50 grid grid-cols-2 gap-2">
            <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-slate-700/30">
              <Cpu size={11} className="text-cyan-400" />
              <div>
                <p className="text-slate-300 font-mono" style={{ fontSize: "0.72rem" }}>XGBoost</p>
                <p className="text-slate-600" style={{ fontSize: "0.6rem" }}>24 features</p>
              </div>
            </div>
            <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-slate-700/30">
              <Database size={11} className="text-cyan-400" />
              <div>
                <p className="text-slate-300 font-mono" style={{ fontSize: "0.72rem" }}>{stats.total} records</p>
                <p className="text-slate-600" style={{ fontSize: "0.6rem" }}>in DB</p>
              </div>
            </div>
          </div>
        </div>
      </div>

    </div>;
}
export {
  DashboardPage
};
