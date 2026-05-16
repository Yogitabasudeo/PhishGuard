const CONFIG = {
  phishing: {
    label: "PHISHING",
    bg: "bg-red-500/15",
    border: "border-red-500/40",
    text: "text-red-400",
    dot: "bg-red-400"
  },
  suspicious: {
    label: "SUSPICIOUS",
    bg: "bg-yellow-500/15",
    border: "border-yellow-500/40",
    text: "text-yellow-400",
    dot: "bg-yellow-400"
  },
  safe: {
    label: "SAFE",
    bg: "bg-green-500/15",
    border: "border-green-500/40",
    text: "text-green-400",
    dot: "bg-green-400"
  }
};
const SIZE_MAP = {
  sm: { text: "0.65rem", px: "px-2 py-0.5", dot: "w-1.5 h-1.5" },
  md: { text: "0.72rem", px: "px-2.5 py-1", dot: "w-2 h-2" },
  lg: { text: "0.8rem", px: "px-3 py-1.5", dot: "w-2.5 h-2.5" }
};
function ThreatBadge({ level, size = "md", showDot = true }) {
  const c = CONFIG[level];
  const s = SIZE_MAP[size];
  return <span
    className={`inline-flex items-center gap-1.5 rounded-full border font-mono tracking-widest ${c.bg} ${c.border} ${c.text} ${s.px}`}
    style={{ fontSize: s.text, fontWeight: 600 }}
  >
      {showDot && <span className={`rounded-full ${c.dot} ${s.dot}`} />}
      {c.label}
    </span>;
}
function RiskScore({ score, size = "md" }) {
  const color = score >= 70 ? "text-red-400" : score >= 40 ? "text-yellow-400" : "text-green-400";
  const sizes = { sm: "0.75rem", md: "0.9rem", lg: "1.1rem" };
  return <span className={`font-mono font-bold ${color}`} style={{ fontSize: sizes[size] }}>
      {score}
    </span>;
}
export {
  RiskScore,
  ThreatBadge
};
