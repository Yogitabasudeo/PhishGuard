import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  ExternalLink,
  Clock,
  Globe,
  Server,
  Shield,
  Eye,
  Database,
  ChevronDown,
  ChevronUp,
  Download,
  Copy,
  Zap,
  Search,
  RotateCcw,
  Hash,
  Layers,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Target,
  Info
} from "lucide-react";
import { useState } from "react";
import { ThreatBadge } from "./ThreatBadge";
function RiskGauge({ score }) {
  const radius = 42;
  const cx = 56;
  const cy = 56;
  const startAngle = 210;
  const endAngle = 330;
  const toRad = (deg) => deg * Math.PI / 180;
  const clampedAngle = startAngle + score / 100 * (360 - (360 - endAngle) - (startAngle - 180) + 30);
  const bgStart = { x: cx + radius * Math.cos(toRad(210)), y: cy + radius * Math.sin(toRad(210)) };
  const bgEnd = { x: cx + radius * Math.cos(toRad(330 - 1)), y: cy + radius * Math.sin(toRad(330 - 1)) };
  const sweepTotal = 300;
  const sweepFilled = score / 100 * sweepTotal;
  const startDeg = 120;
  const endDeg = startDeg + sweepFilled;
  const sx = cx + radius * Math.cos(toRad(startDeg));
  const sy = cy + radius * Math.sin(toRad(startDeg));
  const ex = cx + radius * Math.cos(toRad(endDeg));
  const ey = cy + radius * Math.sin(toRad(endDeg));
  const largeArcFlag = sweepFilled > 180 ? 1 : 0;
  const bsx = cx + radius * Math.cos(toRad(120));
  const bsy = cy + radius * Math.sin(toRad(120));
  const bex = cx + radius * Math.cos(toRad(60));
  const bey = cy + radius * Math.sin(toRad(60));
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#22c55e";
  return <div className="flex flex-col items-center">
      <svg width="112" height="112" viewBox="0 0 112 112">
        {
    /* Background arc */
  }
        <path
    d={`M ${bsx} ${bsy} A ${radius} ${radius} 0 1 1 ${bex} ${bey}`}
    fill="none"
    stroke="#1e293b"
    strokeWidth="10"
    strokeLinecap="round"
  />
        {
    /* Filled arc */
  }
        {sweepFilled > 0 && <path
    d={`M ${sx} ${sy} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${ex} ${ey}`}
    fill="none"
    stroke={color}
    strokeWidth="10"
    strokeLinecap="round"
  />}
        {
    /* Score text */
  }
        <text x={cx} y={cy - 4} textAnchor="middle" fill={color} fontSize="22" fontWeight="bold" fontFamily="monospace">
          {score}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="sans-serif">
          RISK SCORE
        </text>
      </svg>
    </div>;
}
function Section({
  title,
  icon: Icon,
  children,
  defaultOpen = false
}) {
  const [open, setOpen] = useState(defaultOpen);
  return <div className="border border-slate-700/50 rounded-xl overflow-hidden">
      <button
    onClick={() => setOpen(!open)}
    className="w-full flex items-center gap-2 px-4 py-3 bg-slate-800/60 hover:bg-slate-800 transition-colors text-left"
  >
        <Icon size={15} className="text-cyan-400" />
        <span className="text-slate-300" style={{ fontSize: "0.825rem", fontWeight: 600 }}>{title}</span>
        <span className="ml-auto text-slate-500">{open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</span>
      </button>
      {open && <div className="px-4 py-3 bg-slate-900/40">{children}</div>}
    </div>;
}
function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return <button onClick={handleCopy} className="text-slate-500 hover:text-cyan-400 transition-colors ml-1" title="Copy">
      <Copy size={12} />
    </button>;
}
function KV({ label, value, mono = false }) {
  const str = String(value);
  return <div className="flex items-start justify-between gap-4 py-1.5 border-b border-slate-800/60 last:border-0">
      <span className="text-slate-500 shrink-0" style={{ fontSize: "0.75rem" }}>{label}</span>
      <span className={`text-slate-300 text-right break-all ${mono ? "font-mono" : ""}`} style={{ fontSize: "0.75rem" }}>
        {str}
        {mono && <CopyBtn text={str} />}
      </span>
    </div>;
}
const ATTACK_STYLES = {
  "Unicode Homoglyph Attack": { bg: "bg-purple-500/15", border: "border-purple-500/30", text: "text-purple-400", icon: <Hash size={11} /> },
  "Unicode Abuse": { bg: "bg-purple-500/10", border: "border-purple-500/20", text: "text-purple-400", icon: <Hash size={11} /> },
  "Character Repetition Attack": { bg: "bg-orange-500/15", border: "border-orange-500/30", text: "text-orange-400", icon: <RotateCcw size={11} /> },
  "L33t Speak Substitution": { bg: "bg-yellow-500/15", border: "border-yellow-500/30", text: "text-yellow-400", icon: <Hash size={11} /> },
  "Combined Obfuscation Attack": { bg: "bg-red-500/20", border: "border-red-500/40", text: "text-red-400", icon: <Layers size={11} /> },
  "Subdomain Brand Impersonation": { bg: "bg-red-500/15", border: "border-red-500/30", text: "text-red-400", icon: <Zap size={11} /> },
  "Hyphen Brand Abuse": { bg: "bg-amber-500/15", border: "border-amber-500/30", text: "text-amber-400", icon: <ArrowRight size={11} /> },
  "Direct Brand Impersonation": { bg: "bg-red-500/15", border: "border-red-500/30", text: "text-red-400", icon: <Search size={11} /> },
  "Typosquatting": { bg: "bg-orange-500/15", border: "border-orange-500/30", text: "text-orange-400", icon: <Search size={11} /> },
  "Security Keyword Injection": { bg: "bg-yellow-500/15", border: "border-yellow-500/30", text: "text-yellow-400", icon: <Zap size={11} /> },
  "DGA Domain": { bg: "bg-slate-500/20", border: "border-slate-500/30", text: "text-slate-400", icon: <Hash size={11} /> }
};
function AttackVectorBadge({ label }) {
  const style = ATTACK_STYLES[label] ?? {
    bg: "bg-red-500/10",
    border: "border-red-500/20",
    text: "text-red-400",
    icon: <AlertTriangle size={11} />
  };
  return <span
    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border ${style.bg} ${style.border} ${style.text}`}
    style={{ fontSize: "0.72rem", fontWeight: 600 }}
  >
      {style.icon}
      {label}
    </span>;
}
function NormRow({ label, original, normalized, brand }) {
  return <div className="flex items-center gap-2 py-2 border-b border-slate-800/40 last:border-0 flex-wrap">
      <span className="text-slate-500 w-36 shrink-0" style={{ fontSize: "0.72rem" }}>{label}</span>
      <code className="text-red-400/90 bg-red-500/10 px-1.5 py-0.5 rounded font-mono" style={{ fontSize: "0.7rem" }}>{original}</code>
      <ArrowRight size={11} className="text-slate-600" />
      <code className="text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded font-mono" style={{ fontSize: "0.7rem" }}>{normalized}</code>
      {brand && <>
          <ArrowRight size={11} className="text-slate-600" />
          <span className="text-cyan-400" style={{ fontSize: "0.7rem" }}>targets <strong>{brand}.com</strong></span>
        </>}
    </div>;
}
function ResultCard({ result, onExportJSON }) {
  const {
    url,
    prediction,
    confidence,
    risk_score,
    domain,
    ip_address,
    domain_age,
    virustotal,
    virustotal_detections,
    dns_records,
    whois,
    features,
    threat_indicators,
    scan_duration_ms,
    urlhaus_listed,
    phishtank_listed,
    asn,
    country,
    isp,
    final_verdict_explanation,
    positive_legitimacy_signals,
    negative_signals,
    detected_brand
  } = result;
  const sld = domain.replace(/^www\./, "").split(".")[0].toLowerCase();
  const iconMap = {
    phishing: <XCircle size={22} className="text-red-400" />,
    suspicious: <AlertTriangle size={22} className="text-yellow-400" />,
    safe: <CheckCircle size={22} className="text-green-400" />
  };
  const borderColor = {
    phishing: "border-red-500/30",
    suspicious: "border-yellow-500/30",
    safe: "border-green-500/30"
  }[prediction];
  const headerBg = {
    phishing: "bg-red-500/10",
    suspicious: "bg-yellow-500/10",
    safe: "bg-green-500/10"
  }[prediction];
  return <div className={`rounded-2xl border ${borderColor} overflow-hidden`}>
      {
    /* Header */
  }
      <div className={`${headerBg} border-b ${borderColor} px-5 py-4`}>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            {iconMap[prediction]}
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <ThreatBadge level={prediction} size="lg" />
                <span className="text-slate-400" style={{ fontSize: "0.75rem" }}>
                  {(confidence * 100).toFixed(1)}% confidence
                </span>
              </div>
              <p className="text-slate-400 mt-1 truncate font-mono" style={{ fontSize: "0.72rem" }} title={url}>
                {url.length > 70 ? url.slice(0, 70) + "..." : url}
              </p>
            </div>
          </div>
          <div className="flex gap-2 shrink-0">
            {onExportJSON && <button
    onClick={onExportJSON}
    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
    style={{ fontSize: "0.75rem" }}
  >
                <Download size={13} />
                Export
              </button>}
            <a
    href={url}
    target="_blank"
    rel="noopener noreferrer"
    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
    style={{ fontSize: "0.75rem" }}
  >
              <ExternalLink size={13} />
              Open
            </a>
          </div>
        </div>
      </div>

      {
    /* ── Final Verdict Explanation ─────────────────────── */
  }
      {final_verdict_explanation && <div className={`px-5 py-4 border-b ${borderColor} ${prediction === "phishing" ? "bg-red-500/5" : prediction === "suspicious" ? "bg-yellow-500/5" : "bg-green-500/5"}`}>
          <div className="flex items-start gap-3">
            <div className={`shrink-0 p-1.5 rounded-lg mt-0.5 ${prediction === "phishing" ? "bg-red-500/15" : prediction === "suspicious" ? "bg-yellow-500/15" : "bg-green-500/15"}`}>
              {prediction === "phishing" ? <ShieldAlert size={14} className="text-red-400" /> : prediction === "suspicious" ? <Info size={14} className="text-yellow-400" /> : <ShieldCheck size={14} className="text-green-400" />}
            </div>
            <div>
              <p className={`uppercase tracking-widest mb-1 ${prediction === "phishing" ? "text-red-400" : prediction === "suspicious" ? "text-yellow-400" : "text-green-400"}`} style={{ fontSize: "0.6rem", fontWeight: 700 }}>
                AI Verdict Explanation
              </p>
              <p className="text-slate-300 leading-relaxed" style={{ fontSize: "0.78rem" }}>
                {final_verdict_explanation}
              </p>
            </div>
          </div>
        </div>}

      {
    /* ── Detected Brand Impersonation Banner ───────────── */
  }
      {detected_brand && prediction !== "safe" && <div className="px-5 py-3 border-b border-red-500/20 bg-red-950/30 flex items-center gap-3">
          <Target size={14} className="text-red-400 shrink-0" />
          <p className="text-red-300" style={{ fontSize: "0.78rem" }}>
            <span className="text-red-400" style={{ fontWeight: 700 }}>Target Brand Detected:</span>{" "}
            This URL is attempting to impersonate{" "}
            <span className="text-red-300 font-mono" style={{ fontWeight: 700 }}>
              {detected_brand.charAt(0).toUpperCase() + detected_brand.slice(1)}
            </span>
            {" "}— a well-known brand. Users may be tricked into thinking this is legitimate.
          </p>
        </div>}

      {
    /* Quick stats grid */
  }
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-slate-800/30">
        {
    /* Risk Gauge */
  }
        <div className="bg-slate-900/80 flex flex-col items-center justify-center py-4 col-span-1">
          <RiskGauge score={risk_score} />
        </div>

        {
    /* Domain */
  }
        <div className="bg-slate-900/80 px-4 py-4 space-y-3">
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>Domain</p>
            <p className="text-slate-200 font-mono truncate mt-0.5" style={{ fontSize: "0.78rem" }}>{domain}</p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>IP Address</p>
            <p className="text-slate-200 font-mono mt-0.5" style={{ fontSize: "0.78rem" }}>{ip_address}</p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>Domain Age</p>
            <p className={`font-mono mt-0.5 ${parseInt(domain_age) <= 30 && !domain_age.includes("year") ? "text-red-400" : "text-green-400"}`} style={{ fontSize: "0.78rem" }}>
              {domain_age}
            </p>
          </div>
        </div>

        {
    /* VirusTotal */
  }
        <div className="bg-slate-900/80 px-4 py-4 space-y-3">
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>VirusTotal</p>
            <p className={`font-mono mt-0.5 ${virustotal.positives > 0 ? "text-red-400" : "text-green-400"}`} style={{ fontSize: "0.9rem", fontWeight: 700 }}>
              {virustotal_detections}
            </p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>URLHaus</p>
            <p className={`mt-0.5 ${urlhaus_listed ? "text-red-400" : "text-green-400"}`} style={{ fontSize: "0.78rem" }}>
              {urlhaus_listed ? "\u26A0 Listed" : "\u2713 Clean"}
            </p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>PhishTank</p>
            <p className={`mt-0.5 ${phishtank_listed ? "text-red-400" : "text-green-400"}`} style={{ fontSize: "0.78rem" }}>
              {phishtank_listed ? "\u26A0 Listed" : "\u2713 Clean"}
            </p>
          </div>
        </div>

        {
    /* Scan meta */
  }
        <div className="bg-slate-900/80 px-4 py-4 space-y-3">
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>Country</p>
            <p className="text-slate-200 font-mono mt-0.5" style={{ fontSize: "0.78rem" }}>{country}</p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>ASN</p>
            <p className="text-slate-200 font-mono mt-0.5" style={{ fontSize: "0.78rem" }}>{asn}</p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.6rem" }}>Scan Time</p>
            <div className="flex items-center gap-1 mt-0.5">
              <Clock size={10} className="text-slate-500" />
              <p className="text-slate-300 font-mono" style={{ fontSize: "0.78rem" }}>{scan_duration_ms}ms</p>
            </div>
          </div>
        </div>
      </div>

      {
    /* ── Attack Analysis (new) ──────────────────────────── */
  }
      {features.attack_vectors && features.attack_vectors.length > 0 && <div className="px-5 py-4 border-b border-slate-800 space-y-3">
          <div className="flex items-center gap-2">
            <Zap size={14} className="text-orange-400" />
            <p className="text-orange-400 uppercase tracking-wider" style={{ fontSize: "0.65rem", fontWeight: 700 }}>
              Attack Vectors Detected ({features.attack_vectors.length})
            </p>
          </div>

          {
    /* Badges row */
  }
          <div className="flex flex-wrap gap-2">
            {features.attack_vectors.map((v, i) => <AttackVectorBadge key={i} label={v} />)}
          </div>

          {
    /* Normalization trace */
  }
          <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 px-4 py-3">
            <p className="text-slate-500 uppercase tracking-wider mb-2" style={{ fontSize: "0.6rem" }}>
              Obfuscation Trace
            </p>
            {features.homoglyph_detected && features.homoglyph_normalized && <NormRow
    label="Unicode Homoglyph"
    original={domain}
    normalized={features.homoglyph_normalized}
    brand={features.typosquatting_target?.replace(".com", "") ?? void 0}
  />}
            {features.char_repetition_detected && features.char_repetition_normalized && <NormRow
    label="Char Repetition"
    original={sld}
    normalized={features.char_repetition_normalized}
    brand={features.typosquatting_target?.replace(".com", "") ?? void 0}
  />}
            {features.leet_speak_detected && features.leet_normalized && <NormRow
    label="L33t Speak"
    original={sld}
    normalized={features.leet_normalized}
    brand={features.typosquatting_target?.replace(".com", "") ?? void 0}
  />}
            {features.normalized_domain && features.normalized_domain !== sld && !features.leet_speak_detected && !features.char_repetition_detected && !features.homoglyph_detected && <NormRow
    label="Normalized Form"
    original={sld}
    normalized={features.normalized_domain}
    brand={features.typosquatting_target?.replace(".com", "") ?? void 0}
  />}
            {features.subdomain_brand_abuse && features.subdomain_brand_target && <div className="flex items-center gap-2 py-2 border-b border-slate-800/40 last:border-0">
                <span className="text-slate-500 w-36 shrink-0" style={{ fontSize: "0.72rem" }}>Subdomain Abuse</span>
                <span className="text-slate-300 font-mono" style={{ fontSize: "0.7rem" }}>{domain}</span>
                <span className="text-red-400" style={{ fontSize: "0.7rem" }}>→ sub "<strong>{features.subdomain_brand_target}</strong>" mimics official domain</span>
              </div>}
            {features.hyphen_brand_abuse && features.hyphen_brand_target && <div className="flex items-center gap-2 py-2 border-b border-slate-800/40 last:border-0">
                <span className="text-slate-500 w-36 shrink-0" style={{ fontSize: "0.72rem" }}>Hyphen Abuse</span>
                <span className="text-slate-300 font-mono" style={{ fontSize: "0.7rem" }}>{sld}</span>
                <span className="text-amber-400" style={{ fontSize: "0.7rem" }}>→ "<strong>{features.hyphen_brand_target}</strong>" hidden in hyphens</span>
              </div>}
            {features.keyword_injection_detected && features.injected_keywords && <div className="flex items-center gap-2 py-2 last:border-0 flex-wrap">
                <span className="text-slate-500 w-36 shrink-0" style={{ fontSize: "0.72rem" }}>Injected Keywords</span>
                <div className="flex gap-1 flex-wrap">
                  {features.injected_keywords.map((k, i) => <code key={i} className="text-yellow-400 bg-yellow-500/10 px-1.5 py-0.5 rounded font-mono" style={{ fontSize: "0.7rem" }}>{k}</code>)}
                </div>
              </div>}
          </div>
        </div>}

      {
    /* Threat Indicators */
  }
      {threat_indicators.length > 0 && <div className="px-5 py-4 border-b border-slate-800">
          <p className="text-slate-400 uppercase tracking-wider mb-3" style={{ fontSize: "0.65rem" }}>
            ⚠ Threat Indicators ({threat_indicators.length})
          </p>
          <div className="flex flex-wrap gap-2">
            {threat_indicators.map((ind, i) => <span
    key={i}
    className="px-2.5 py-1 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400"
    style={{ fontSize: "0.72rem" }}
  >
                {ind}
              </span>)}
          </div>
        </div>}

      {
    /* Expandable sections */
  }
      <div className="p-4 space-y-2">

        {
    /* ── Legitimacy Signals ──────────────────────────── */
  }
        {positive_legitimacy_signals && positive_legitimacy_signals.length > 0 && <Section title={`Legitimacy Signals (${positive_legitimacy_signals.length})`} icon={ShieldCheck} defaultOpen={prediction === "safe"}>
            <div className="space-y-1.5">
              {positive_legitimacy_signals.map((sig, i) => <div key={i} className="flex items-start gap-2.5 py-1.5 border-b border-slate-800/40 last:border-0">
                  <CheckCircle size={12} className="text-green-400 shrink-0 mt-0.5" />
                  <span className="text-slate-300" style={{ fontSize: "0.75rem" }}>{sig}</span>
                </div>)}
            </div>
          </Section>}

        {
    /* URL Features */
  }
        <Section title="ML Feature Extraction" icon={Eye} defaultOpen>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8">
            <KV label="URL Length" value={`${features.url_length} chars`} />
            <KV label="HTTPS" value={features.has_https ? "\u2713 Yes" : "\u2717 No"} />
            <KV label="IP-based URL" value={features.has_ip ? "\u26A0 Yes" : "No"} />
            <KV label="Number of Dots" value={features.num_dots} />
            <KV label="Hyphen Count" value={features.hyphen_count} />
            <KV label="Digit Count" value={features.num_digits} />
            <KV label="Special Chars" value={features.special_char_count} />
            <KV label="Entropy" value={features.entropy.toFixed(3)} />
            <KV label="Subdomain Count" value={features.subdomain_count} />
            <KV label="URL Shortened" value={features.is_shortened ? "\u26A0 Yes" : "No"} />
            <KV label="Path Components" value={features.num_path_components} />
            <KV label="Features Used" value={`${result.ml_features_used} features`} />
            {
    /* New v2 fields */
  }
            {features.char_repetition_detected && <KV label="Char Repetition" value={`\u26A0 Detected \u2192 "${features.char_repetition_normalized}"`} />}
            {features.leet_speak_detected && <KV label="L33t Speak" value={`\u26A0 Normalized \u2192 "${features.leet_normalized}"`} />}
            {features.unicode_abuse_detected && <KV label="Unicode Abuse" value={`\u26A0 ${features.unicode_chars?.length ?? 0} non-ASCII char(s)`} />}
            {features.subdomain_brand_abuse && <KV label="Subdomain Abuse" value={`\u26A0 "${features.subdomain_brand_target}" as subdomain`} />}
            {features.hyphen_brand_abuse && <KV label="Hyphen Abuse" value={`\u26A0 "${features.hyphen_brand_target}" in hyphens`} />}
            {features.suspicious_keywords.length > 0 && <div className="col-span-2 pt-1">
                <KV label="Suspicious Keywords" value={features.suspicious_keywords.join(", ")} />
              </div>}
            {features.typosquatting_target && <>
                <KV label="Typosquatting Target" value={features.typosquatting_target} />
                <KV label="Similarity Score" value={`${((features.typosquatting_similarity || 0) * 100).toFixed(0)}%`} />
              </>}
          </div>
        </Section>

        {
    /* WHOIS */
  }
        <Section title="WHOIS Information" icon={Globe}>
          <KV label="Registrant" value={whois.registrant} />
          <KV label="Registrar" value={whois.registrar} />
          <KV label="Creation Date" value={whois.creation_date} />
          <KV label="Expiry Date" value={whois.expiry_date} />
          <KV label="Country" value={whois.country} />
          <KV label="Email" value={whois.email} />
          <KV label="Updated" value={whois.updated_date} />
        </Section>

        {
    /* DNS */
  }
        <Section title="DNS Records" icon={Server}>
          <KV label="A Records" value={dns_records.A.join(", ") || "None"} mono />
          <KV label="MX Records" value={dns_records.MX.join(", ") || "None"} mono />
          <KV label="NS Records" value={dns_records.NS.join(", ") || "None"} mono />
          <KV label="TXT Records" value={dns_records.TXT.length > 0 ? dns_records.TXT[0] : "None"} mono />
          <KV label="ISP / Hosting" value={isp} />
        </Section>

        {
    /* VirusTotal Details */
  }
        <Section title="VirusTotal Details" icon={Shield}>
          <KV label="Positive Detections" value={`${virustotal.positives} / ${virustotal.total} vendors`} />
          <KV label="Scan Date" value={virustotal.scan_date} />
          {virustotal.detected_by.length > 0 && <KV label="Detected By" value={virustotal.detected_by.join(", ")} />}
          {virustotal.permalink && <div className="pt-1">
              <a
    href={virustotal.permalink}
    target="_blank"
    rel="noopener noreferrer"
    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
    style={{ fontSize: "0.75rem" }}
  >
                View full VirusTotal report <ExternalLink size={11} />
              </a>
            </div>}
        </Section>

        {
    /* Threat Intel Feeds */
  }
        <Section title="Threat Intelligence Feeds" icon={Database}>
          <KV label="URLHaus Listed" value={urlhaus_listed ? "\u26A0 YES - Malicious" : "\u2713 Not Listed"} />
          <KV label="PhishTank Listed" value={phishtank_listed ? "\u26A0 YES - Phishing" : "\u2713 Not Listed"} />
          <KV label="ML Prediction" value={prediction.toUpperCase()} />
          <KV label="ML Confidence" value={`${(confidence * 100).toFixed(2)}%`} />
          <KV label="Risk Score" value={`${risk_score} / 100`} />
        </Section>
      </div>
    </div>;
}
export {
  ResultCard
};
