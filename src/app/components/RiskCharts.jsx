import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Area,
  AreaChart,
  BarChart,
  Bar,
  LabelList
} from "recharts";
import { useId } from "react";
import {
  TIME_SERIES_DATA,
  RISK_BUCKETS,
  THREAT_DISTRIBUTION,
  THREAT_INDICATORS
} from "../data/mockData";
const TooltipBox = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return <div className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 shadow-xl">
      {label && <p className="text-slate-400 mb-1" style={{ fontSize: "0.72rem" }}>{label}</p>}
      {payload.map((p, i) => <p key={`tip-${i}-${p.name}`} style={{ color: p.color || p.fill, fontSize: "0.78rem" }}>
          {p.name}: <span style={{ fontWeight: 600 }}>{p.value}</span>
        </p>)}
    </div>;
};
function ChartCard({ title, subtitle, children }) {
  return <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
      <div className="mb-4">
        <h3 className="text-slate-200" style={{ fontSize: "0.9rem", fontWeight: 600 }}>{title}</h3>
        {subtitle && <p className="text-slate-500 mt-0.5" style={{ fontSize: "0.72rem" }}>{subtitle}</p>}
      </div>
      {children}
    </div>;
}
function ThreatDonut() {
  const uid = useId().replace(/:/g, "");
  const RADIAN = Math.PI / 180;
  const renderLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }) => {
    if (percent < 0.08) return null;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);
    return <text
      x={x}
      y={y}
      fill="#fff"
      textAnchor="middle"
      dominantBaseline="central"
      fontSize={11}
      fontWeight={600}
    >
        {`${(percent * 100).toFixed(0)}%`}
      </text>;
  };
  return <ChartCard
    title="Threat Distribution"
    subtitle="All-time scan classification breakdown"
  >
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
    key={`donut-pie-${uid}`}
    data={THREAT_DISTRIBUTION}
    cx="50%"
    cy="50%"
    innerRadius={65}
    outerRadius={95}
    paddingAngle={3}
    dataKey="value"
    labelLine={false}
    label={renderLabel}
  >
            {THREAT_DISTRIBUTION.map((entry, i) => <Cell key={`donut-cell-${uid}-${i}`} fill={entry.color} />)}
          </Pie>
          <Tooltip key={`donut-tooltip-${uid}`} content={<TooltipBox />} />
          <Legend
    key={`donut-legend-${uid}`}
    formatter={(value, entry) => <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>
                {value} ({entry.payload.value})
              </span>}
  />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>;
}
function ScanTrend() {
  const uid = useId().replace(/:/g, "");
  const gPhishing = `gPhishing-${uid}`;
  const gSafe = `gSafe-${uid}`;
  const gSuspicious = `gSuspicious-${uid}`;
  return <ChartCard
    title="Scan Activity — Last 14 Days"
    subtitle="Daily breakdown of URL scans by category"
  >
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={TIME_SERIES_DATA} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <defs>
            <linearGradient key={`grad-phishing-${uid}`} id={gPhishing} x1="0" y1="0" x2="0" y2="1">
              <stop key={`${gPhishing}-s1`} offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
              <stop key={`${gPhishing}-s2`} offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
            <linearGradient key={`grad-safe-${uid}`} id={gSafe} x1="0" y1="0" x2="0" y2="1">
              <stop key={`${gSafe}-s1`} offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
              <stop key={`${gSafe}-s2`} offset="95%" stopColor="#22c55e" stopOpacity={0} />
            </linearGradient>
            <linearGradient key={`grad-sus-${uid}`} id={gSuspicious} x1="0" y1="0" x2="0" y2="1">
              <stop key={`${gSuspicious}-s1`} offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
              <stop key={`${gSuspicious}-s2`} offset="95%" stopColor="#f59e0b" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid key={`trend-grid-${uid}`} strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis key={`trend-xaxis-${uid}`} dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis key={`trend-yaxis-${uid}`} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip key={`trend-tooltip-${uid}`} content={<TooltipBox />} />
          <Legend key={`trend-legend-${uid}`} formatter={(v) => <span style={{ color: "#94a3b8", fontSize: "0.75rem" }}>{v}</span>} />
          <Area key={`trend-area-phishing-${uid}`} type="monotone" dataKey="phishing" name="Phishing" stroke="#ef4444" strokeWidth={2} fill={`url(#${gPhishing})`} dot={false} />
          <Area key={`trend-area-safe-${uid}`} type="monotone" dataKey="safe" name="Safe" stroke="#22c55e" strokeWidth={2} fill={`url(#${gSafe})`} dot={false} />
          <Area key={`trend-area-sus-${uid}`} type="monotone" dataKey="suspicious" name="Suspicious" stroke="#f59e0b" strokeWidth={2} fill={`url(#${gSuspicious})`} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </ChartCard>;
}
function RiskHistogram() {
  const uid = useId().replace(/:/g, "");
  return <ChartCard
    title="Risk Score Distribution"
    subtitle="Number of scans per risk score range"
  >
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={RISK_BUCKETS} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
          <CartesianGrid key={`hist-grid-${uid}`} strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis key={`hist-xaxis-${uid}`} dataKey="range" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis key={`hist-yaxis-${uid}`} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip key={`hist-tooltip-${uid}`} content={<TooltipBox />} />
          <Bar key={`hist-bar-${uid}`} dataKey="count" name="Scans" radius={[4, 4, 0, 0]}>
            {RISK_BUCKETS.map((entry) => <Cell key={`hist-cell-${uid}-${entry.range}`} fill={entry.fill} />)}
            <LabelList key={`hist-labels-${uid}`} dataKey="count" position="top" style={{ fill: "#94a3b8", fontSize: 10 }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>;
}
function ThreatIndicatorsChart() {
  const uid = useId().replace(/:/g, "");
  return <ChartCard
    title="Top Threat Indicators"
    subtitle="Most common IOC signals across all phishing scans"
  >
      <ResponsiveContainer width="100%" height={260}>
        <BarChart
    data={THREAT_INDICATORS}
    layout="vertical"
    margin={{ top: 0, right: 40, bottom: 0, left: 10 }}
  >
          <CartesianGrid key={`ioc-grid-${uid}`} strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
          <XAxis key={`ioc-xaxis-${uid}`} type="number" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis
    key={`ioc-yaxis-${uid}`}
    type="category"
    dataKey="name"
    width={130}
    tick={{ fill: "#94a3b8", fontSize: 10 }}
    axisLine={false}
    tickLine={false}
  />
          <Tooltip key={`ioc-tooltip-${uid}`} content={<TooltipBox />} />
          <Bar key={`ioc-bar-${uid}`} dataKey="count" name="Occurrences" fill="#06b6d4" radius={[0, 4, 4, 0]}>
            <LabelList dataKey="count" position="right" style={{ fill: "#64748b", fontSize: 10 }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>;
}
function DailyScanLine() {
  const uid = useId().replace(/:/g, "");
  return <ChartCard
    title="Total Daily Scans"
    subtitle="Cumulative scan volume over the past two weeks"
  >
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={TIME_SERIES_DATA} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
          <CartesianGrid key={`line-grid-${uid}`} strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis key={`line-xaxis-${uid}`} dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis key={`line-yaxis-${uid}`} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip key={`line-tooltip-${uid}`} content={<TooltipBox />} />
          <Line
    key={`line-series-${uid}`}
    type="monotone"
    dataKey="scans"
    name="Total Scans"
    stroke="#06b6d4"
    strokeWidth={2.5}
    dot={{ fill: "#06b6d4", r: 3 }}
    activeDot={{ r: 5 }}
  />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>;
}
export {
  DailyScanLine,
  RiskHistogram,
  ScanTrend,
  ThreatDonut,
  ThreatIndicatorsChart
};
