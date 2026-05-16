import { useState } from "react";
import {
  FileText,
  Download,
  Printer,
  Shield,
  Globe,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Database,
  ChevronDown,
  ChevronUp,
  Copy,
  Star
} from "lucide-react";
import { useScanContext } from "../context/ScanContext";
import { ThreatBadge } from "./ThreatBadge";
function SectionCard({
  title,
  icon: Icon,
  badge,
  children
}) {
  const [open, setOpen] = useState(true);
  return <div className="border border-slate-700/50 rounded-xl overflow-hidden">
      <button
    onClick={() => setOpen((o) => !o)}
    className="w-full flex items-center gap-2.5 px-5 py-3.5 bg-slate-800/70 hover:bg-slate-800 transition-colors"
  >
        <Icon size={15} className="text-cyan-400 shrink-0" />
        <span className="text-slate-200" style={{ fontSize: "0.875rem", fontWeight: 600 }}>{title}</span>
        {badge && <span className="ml-2">{badge}</span>}
        <span className="ml-auto text-slate-500">{open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</span>
      </button>
      {open && <div className="px-5 py-4 bg-slate-900/50">{children}</div>}
    </div>;
}
function Row({ label, value, mono = false, highlight }) {
  const textColor = highlight === "danger" ? "text-red-400" : highlight === "warning" ? "text-yellow-400" : highlight === "success" ? "text-green-400" : "text-slate-300";
  return <div className="flex flex-col sm:flex-row sm:items-center gap-1 py-2.5 border-b border-slate-800/60 last:border-0">
      <span className="text-slate-500 shrink-0 sm:w-40" style={{ fontSize: "0.775rem" }}>{label}</span>
      <span className={`${textColor} ${mono ? "font-mono break-all" : ""}`} style={{ fontSize: "0.775rem" }}>
        {value}
      </span>
    </div>;
}
function IOCTag({ text, type }) {
  const styles = {
    ioc: "bg-red-500/15 border-red-500/30 text-red-400",
    keyword: "bg-yellow-500/15 border-yellow-500/30 text-yellow-400",
    domain: "bg-blue-500/15 border-blue-500/30 text-blue-400",
    ip: "bg-purple-500/15 border-purple-500/30 text-purple-400"
  };
  return <span className={`inline-block px-2 py-0.5 rounded-lg border font-mono ${styles[type]}`} style={{ fontSize: "0.68rem" }}>
      {text}
    </span>;
}
function generateHTMLReport(result) {
  const threatColor = result.prediction === "phishing" ? "#ef4444" : result.prediction === "suspicious" ? "#f59e0b" : "#22c55e";
  const threatBg = result.prediction === "phishing" ? "#ef444418" : result.prediction === "suspicious" ? "#f59e0b18" : "#22c55e18";
  const now = (/* @__PURE__ */ new Date()).toUTCString();
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhishGuard IOC Report \u2014 ${result.id}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f8fafc; color: #1e293b; padding: 0; }
  .cover { background: #0f172a; color: #f1f5f9; padding: 48px 56px 36px; }
  .cover-logo { display: flex; align-items: center; gap: 12px; margin-bottom: 40px; }
  .cover-logo .shield { width: 44px; height: 44px; background: #06b6d420; border: 1px solid #06b6d440; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 22px; }
  .cover-logo h1 { font-size: 24px; font-weight: 800; color: #06b6d4; letter-spacing: -0.5px; }
  .cover-logo span { font-size: 12px; color: #64748b; display: block; }
  .verdict-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; margin-top: 8px; }
  .verdict-left h2 { font-size: 15px; color: #94a3b8; font-weight: 400; margin-bottom: 8px; }
  .verdict-left .url { font-family: monospace; font-size: 13px; color: #e2e8f0; background: #1e293b; padding: 10px 14px; border-radius: 8px; word-break: break-all; max-width: 600px; border: 1px solid #334155; }
  .verdict-badge { display: inline-block; padding: 6px 18px; border-radius: 20px; font-size: 14px; font-weight: 700; background: ${threatBg}; color: ${threatColor}; border: 1px solid ${threatColor}44; margin-top: 12px; }
  .risk-score { text-align: right; }
  .risk-score .num { font-size: 64px; font-weight: 800; color: ${threatColor}; line-height: 1; }
  .risk-score .lbl { font-size: 11px; color: #64748b; margin-top: 4px; }
  .meta-row { display: flex; gap: 28px; margin-top: 24px; padding-top: 20px; border-top: 1px solid #1e293b; }
  .meta-item .label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 4px; }
  .meta-item .value { font-size: 14px; color: #e2e8f0; font-weight: 600; }
  .body { padding: 36px 56px; }
  .section { margin-bottom: 32px; }
  .section-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #06b6d4; font-weight: 700; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; display: flex; align-items: center; gap-8px; }
  .section-title::before { content: ''; display: inline-block; width: 3px; height: 14px; background: #06b6d4; border-radius: 2px; margin-right: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td { padding: 9px 0; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  td:first-child { color: #64748b; width: 200px; font-weight: 500; }
  td.danger { color: #ef4444; font-weight: 600; }
  td.warning { color: #f59e0b; font-weight: 600; }
  td.success { color: #22c55e; font-weight: 600; }
  td code { font-family: monospace; font-size: 12px; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; color: #334155; }
  .ioc-grid { display: flex; flex-wrap: wrap; gap: 8px; }
  .ioc-tag { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-family: monospace; }
  .kw-tag  { background: #fffbeb; border: 1px solid #fde68a; color: #b45309; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-family: monospace; }
  .feed-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .feed-card { border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px; text-align: center; }
  .feed-card .name { font-size: 11px; color: #64748b; margin-bottom: 6px; }
  .feed-card .status { font-size: 13px; font-weight: 700; }
  .feed-card.danger  { border-color: #fecaca; background: #fef2f2; }
  .feed-card.safe    { border-color: #bbf7d0; background: #f0fdf4; }
  .footer { background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 18px 56px; display: flex; justify-content: space-between; align-items: center; font-size: 10px; color: #94a3b8; }
  @media print {
    body { background: white; }
    .cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>
<!-- COVER -->
<div class="cover">
  <div class="cover-logo">
    <div class="shield">\u{1F6E1}</div>
    <div>
      <h1>PhishGuard</h1>
      <span>ML-Powered Phishing Detection Platform</span>
    </div>
  </div>
  <div class="verdict-row">
    <div class="verdict-left">
      <h2>Indicator of Compromise Report</h2>
      <div class="url">${result.url}</div>
      <div class="verdict-badge">${result.prediction.toUpperCase()}</div>
    </div>
    <div class="risk-score">
      <div class="num">${result.risk_score}</div>
      <div class="lbl">Risk Score / 100</div>
    </div>
  </div>
  <div class="meta-row">
    <div class="meta-item"><div class="label">Report ID</div><div class="value">${result.id}</div></div>
    <div class="meta-item"><div class="label">Generated</div><div class="value">${now}</div></div>
    <div class="meta-item"><div class="label">ML Confidence</div><div class="value">${(result.confidence * 100).toFixed(2)}%</div></div>
    <div class="meta-item"><div class="label">Scan Duration</div><div class="value">${result.scan_duration_ms}ms</div></div>
    <div class="meta-item"><div class="label">Domain Age</div><div class="value">${result.domain_age}</div></div>
  </div>
</div>

<!-- BODY -->
<div class="body">

  <!-- Threat Intelligence Feeds -->
  <div class="section">
    <div class="section-title">Threat Intelligence Feeds</div>
    <div class="feed-grid">
      <div class="feed-card ${result.virustotal.positives > 0 ? "danger" : "safe"}">
        <div class="name">VirusTotal</div>
        <div class="status" style="color:${result.virustotal.positives > 0 ? "#dc2626" : "#16a34a"}">${result.virustotal_detections} detections</div>
      </div>
      <div class="feed-card ${result.urlhaus_listed ? "danger" : "safe"}">
        <div class="name">URLHaus</div>
        <div class="status" style="color:${result.urlhaus_listed ? "#dc2626" : "#16a34a"}">${result.urlhaus_listed ? "\u26A0 LISTED" : "\u2713 Clean"}</div>
      </div>
      <div class="feed-card ${result.phishtank_listed ? "danger" : "safe"}">
        <div class="name">PhishTank</div>
        <div class="status" style="color:${result.phishtank_listed ? "#dc2626" : "#16a34a"}">${result.phishtank_listed ? "\u26A0 LISTED" : "\u2713 Clean"}</div>
      </div>
    </div>
  </div>

  <!-- IOCs -->
  ${result.threat_indicators.length > 0 ? `
  <div class="section">
    <div class="section-title">Indicators of Compromise (${result.threat_indicators.length})</div>
    <div class="ioc-grid">
      ${result.threat_indicators.map((i) => `<span class="ioc-tag">${i}</span>`).join("\n      ")}
    </div>
  </div>` : ""}

  <!-- Domain Intelligence -->
  <div class="section">
    <div class="section-title">Domain Intelligence</div>
    <table>
      <tr><td>Domain</td><td><code>${result.domain}</code></td></tr>
      <tr><td>IP Address</td><td><code>${result.ip_address}</code></td></tr>
      <tr><td>Domain Age</td><td class="${!result.domain_age.includes("year") ? "danger" : "success"}">${result.domain_age}</td></tr>
      <tr><td>Country</td><td>${result.country}</td></tr>
      <tr><td>ASN</td><td>${result.asn}</td></tr>
      <tr><td>ISP / Hosting</td><td>${result.isp}</td></tr>
    </table>
  </div>

  <!-- WHOIS -->
  <div class="section">
    <div class="section-title">WHOIS Forensics</div>
    <table>
      <tr><td>Registrant</td><td class="${result.whois.registrant.includes("REDACTED") ? "warning" : ""}">${result.whois.registrant}</td></tr>
      <tr><td>Registrar</td><td>${result.whois.registrar}</td></tr>
      <tr><td>Creation Date</td><td>${result.whois.creation_date}</td></tr>
      <tr><td>Expiry Date</td><td>${result.whois.expiry_date}</td></tr>
      <tr><td>Contact Email</td><td><code>${result.whois.email}</code></td></tr>
    </table>
  </div>

  <!-- DNS -->
  <div class="section">
    <div class="section-title">DNS Records</div>
    <table>
      <tr><td>A Records</td><td><code>${result.dns_records.A.join(", ") || "None"}</code></td></tr>
      <tr><td>MX Records</td><td><code>${result.dns_records.MX.join(", ") || "None"}</code></td></tr>
      <tr><td>NS Records</td><td><code>${result.dns_records.NS.join(", ") || "None"}</code></td></tr>
      <tr><td>TXT Records</td><td><code>${result.dns_records.TXT[0] || "None"}</code></td></tr>
    </table>
  </div>

  <!-- ML Features -->
  <div class="section">
    <div class="section-title">ML Feature Extraction (${result.ml_features_used} features)</div>
    <table>
      <tr><td>URL Length</td><td>${result.features.url_length} chars</td></tr>
      <tr><td>HTTPS</td><td class="${result.features.has_https ? "success" : "danger"}">${result.features.has_https ? "Yes" : "No"}</td></tr>
      <tr><td>IP-based URL</td><td class="${result.features.has_ip ? "danger" : "success"}">${result.features.has_ip ? "Yes (suspicious)" : "No"}</td></tr>
      <tr><td>Entropy</td><td>${result.features.entropy}</td></tr>
      <tr><td>Hyphen Count</td><td>${result.features.hyphen_count}</td></tr>
      <tr><td>Subdomain Count</td><td>${result.features.subdomain_count}</td></tr>
      <tr><td>Dot Count</td><td>${result.features.num_dots}</td></tr>
      ${result.features.suspicious_keywords.length > 0 ? `<tr><td>Suspicious Keywords</td><td class="danger">${result.features.suspicious_keywords.join(", ")}</td></tr>` : ""}
      ${result.features.typosquatting_target ? `<tr><td>Typosquatting Target</td><td class="danger">${result.features.typosquatting_target} (${((result.features.typosquatting_similarity || 0) * 100).toFixed(0)}% similar)</td></tr>` : ""}
    </table>
  </div>

  ${result.features.suspicious_keywords.length > 0 ? `
  <div class="section">
    <div class="section-title">Suspicious Keywords</div>
    <div class="ioc-grid">
      ${result.features.suspicious_keywords.map((k) => `<span class="kw-tag">${k}</span>`).join("\n      ")}
    </div>
  </div>` : ""}

</div>

<!-- FOOTER -->
<div class="footer">
  <span>PhishGuard v1.0 \u2014 ML-Powered Phishing Detection | XGBoost + VirusTotal + URLHaus + PhishTank</span>
  <span>Report ID: ${result.id}</span>
</div>
</body>
</html>`;
}
function IOCReportViewer() {
  const { allScans } = useScanContext();
  const [selectedId, setSelectedId] = useState(() => allScans[0]?.id ?? "");
  const result = allScans.find((r) => r.id === selectedId) ?? allScans[0];
  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phishguard_ioc_${result.id}.json`;
    a.click();
  };
  const handleExportPDF = () => {
    const html = generateHTMLReport(result);
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const win = window.open(url, "_blank");
    if (win) {
      win.onload = () => {
        setTimeout(() => win.print(), 500);
      };
    }
  };
  const handleCopyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
  };
  const iconMap = {
    phishing: <XCircle size={18} className="text-red-400" />,
    suspicious: <AlertTriangle size={18} className="text-yellow-400" />,
    safe: <CheckCircle size={18} className="text-green-400" />
  };
  return <div className="space-y-5">
      {
    /* Report selector */
  }
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        <div>
          <h2 className="text-slate-200" style={{ fontSize: "1rem", fontWeight: 600 }}>IOC Report Viewer</h2>
          <p className="text-slate-500 mt-0.5" style={{ fontSize: "0.78rem" }}>
            Select a scan to view its full Indicators of Compromise report
          </p>
        </div>
        <div className="flex gap-2">
          <button
    onClick={handleCopyJSON}
    className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
    style={{ fontSize: "0.8rem" }}
  >
            <Copy size={13} /> Copy JSON
          </button>
          <button
    onClick={handleExportJSON}
    className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
    style={{ fontSize: "0.8rem" }}
  >
            <Download size={13} /> JSON
          </button>
          <button
    onClick={handleExportPDF}
    className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/25 transition-colors"
    style={{ fontSize: "0.8rem" }}
  >
            <Printer size={13} /> PDF Report
          </button>
        </div>
      </div>

      {
    /* Scan selector list */
  }
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {
    /* Left: scan list */
  }
        <div className="lg:col-span-1 space-y-2 max-h-[600px] overflow-y-auto pr-1">
          <p className="text-slate-500 uppercase tracking-wider mb-2" style={{ fontSize: "0.65rem" }}>
            Select Scan
          </p>
          {allScans.map((scan) => <button
    key={scan.id}
    onClick={() => setSelectedId(scan.id)}
    className={`w-full text-left px-3 py-3 rounded-xl border transition-all ${selectedId === scan.id ? "bg-cyan-500/10 border-cyan-500/30" : "bg-slate-800/30 border-slate-700/30 hover:bg-slate-800/60"}`}
  >
              <div className="flex items-center gap-2 mb-1">
                {iconMap[scan.prediction]}
                <ThreatBadge level={scan.prediction} size="sm" showDot={false} />
                {!scan.id.startsWith("scan_0") && <span className="ml-auto flex items-center gap-0.5 text-cyan-400" style={{ fontSize: "0.6rem" }}>
                    <Star size={9} className="fill-cyan-400" /> Live
                  </span>}
                <span className={`ml-auto font-mono ${scan.risk_score >= 70 ? "text-red-400" : scan.risk_score >= 40 ? "text-yellow-400" : "text-green-400"}`} style={{ fontSize: "0.78rem" }}>
                  {scan.risk_score}
                </span>
              </div>
              <p className="text-slate-400 truncate font-mono" style={{ fontSize: "0.7rem" }}>{scan.domain}</p>
              <div className="flex items-center gap-1 mt-1">
                <Clock size={9} className="text-slate-600" />
                <p className="text-slate-600" style={{ fontSize: "0.65rem" }}>
                  {new Date(scan.timestamp).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                </p>
              </div>
            </button>)}
        </div>

        {
    /* Right: full report */
  }
        <div className="lg:col-span-2 space-y-3">
          {
    /* Header */
  }
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-2xl p-5">
            <div className="flex items-start gap-3 mb-4">
              <div className={`p-2.5 rounded-xl ${result.prediction === "phishing" ? "bg-red-500/20" : result.prediction === "suspicious" ? "bg-yellow-500/20" : "bg-green-500/20"}`}>
                <FileText size={20} className={result.prediction === "phishing" ? "text-red-400" : result.prediction === "suspicious" ? "text-yellow-400" : "text-green-400"} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-slate-200" style={{ fontWeight: 600, fontSize: "0.95rem" }}>IOC Report</span>
                  <ThreatBadge level={result.prediction} size="md" />
                </div>
                <p className="text-slate-500 font-mono truncate mt-1" style={{ fontSize: "0.72rem" }}>{result.url}</p>
              </div>
              <div className="text-right shrink-0">
                <p className={`font-mono ${result.risk_score >= 70 ? "text-red-400" : result.risk_score >= 40 ? "text-yellow-400" : "text-green-400"}`} style={{ fontSize: "1.8rem", fontWeight: 700 }}>
                  {result.risk_score}
                </p>
                <p className="text-slate-600" style={{ fontSize: "0.65rem" }}>Risk Score</p>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4 pt-3 border-t border-slate-700/50">
              <div>
                <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>ML Confidence</p>
                <p className="text-slate-200 font-mono mt-0.5" style={{ fontSize: "0.875rem" }}>{(result.confidence * 100).toFixed(1)}%</p>
              </div>
              <div>
                <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>Scan Duration</p>
                <p className="text-slate-200 font-mono mt-0.5" style={{ fontSize: "0.875rem" }}>{result.scan_duration_ms}ms</p>
              </div>
              <div>
                <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>Report ID</p>
                <p className="text-slate-200 font-mono mt-0.5" style={{ fontSize: "0.78rem" }}>{result.id}</p>
              </div>
            </div>
          </div>

          {
    /* IOC Tags */
  }
          {result.threat_indicators.length > 0 && <SectionCard
    title="Indicators of Compromise (IOCs)"
    icon={AlertTriangle}
    badge={<span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400" style={{ fontSize: "0.65rem" }}>{result.threat_indicators.length}</span>}
  >
              <div className="flex flex-wrap gap-2">
                {result.threat_indicators.map((ind, i) => <IOCTag key={i} text={ind} type="ioc" />)}
              </div>
            </SectionCard>}

          {
    /* Domain Intelligence */
  }
          <SectionCard title="Domain Intelligence" icon={Globe}>
            <Row label="Domain" value={result.domain} mono />
            <Row label="IP Address" value={result.ip_address} mono />
            <Row label="Domain Age" value={result.domain_age} highlight={!result.domain_age.includes("year") ? "danger" : "success"} />
            <Row label="Country" value={result.country} highlight={["RU", "CN", "UA", "RO", "NG"].includes(result.country) ? "warning" : void 0} />
            <Row label="ASN" value={result.asn} mono />
            <Row label="ISP / Hosting" value={result.isp} />
          </SectionCard>

          {
    /* WHOIS */
  }
          <SectionCard title="WHOIS Forensics" icon={Database}>
            <Row label="Registrant" value={result.whois.registrant} highlight={result.whois.registrant.includes("REDACTED") ? "warning" : void 0} />
            <Row label="Registrar" value={result.whois.registrar} />
            <Row label="Creation Date" value={result.whois.creation_date} />
            <Row label="Expiry Date" value={result.whois.expiry_date} />
            <Row label="Country" value={result.whois.country} />
            <Row label="Contact Email" value={result.whois.email} mono />
          </SectionCard>

          {
    /* DNS */
  }
          <SectionCard title="DNS Records" icon={Server}>
            <Row label="A Records" value={result.dns_records.A.join(", ") || "None"} mono />
            <Row label="MX Records" value={result.dns_records.MX.join(", ") || "None"} mono />
            <Row label="NS Records" value={result.dns_records.NS.join(", ") || "None"} mono />
            <Row label="TXT Records" value={result.dns_records.TXT.length > 0 ? result.dns_records.TXT[0] : "None"} mono />
          </SectionCard>

          {
    /* Threat Intel */
  }
          <SectionCard title="Threat Intelligence Feeds" icon={Shield}>
            <Row label="VirusTotal" value={`${result.virustotal_detections} detections`} highlight={result.virustotal.positives > 0 ? "danger" : "success"} />
            {result.virustotal.detected_by.length > 0 && <Row label="Detected By" value={result.virustotal.detected_by.join(", ")} />}
            <Row label="URLHaus" value={result.urlhaus_listed ? "\u26A0 LISTED \u2014 Malicious URL" : "\u2713 Not listed"} highlight={result.urlhaus_listed ? "danger" : "success"} />
            <Row label="PhishTank" value={result.phishtank_listed ? "\u26A0 LISTED \u2014 Known Phishing" : "\u2713 Not listed"} highlight={result.phishtank_listed ? "danger" : "success"} />
          </SectionCard>

          {
    /* Suspicious keywords */
  }
          {result.features.suspicious_keywords.length > 0 && <SectionCard title="Suspicious Keywords Detected" icon={AlertTriangle}>
              <div className="flex flex-wrap gap-2">
                {result.features.suspicious_keywords.map((kw, i) => <IOCTag key={i} text={kw} type="keyword" />)}
              </div>
              {result.features.typosquatting_target && <div className="mt-3 p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                  <p className="text-orange-400" style={{ fontSize: "0.8rem" }}>
                    ⚠ Typosquatting detected — <strong>{result.features.typosquatting_target}</strong> ({((result.features.typosquatting_similarity || 0) * 100).toFixed(0)}% similarity)
                  </p>
                </div>}
            </SectionCard>}
        </div>
      </div>
    </div>;
}
export {
  IOCReportViewer
};
