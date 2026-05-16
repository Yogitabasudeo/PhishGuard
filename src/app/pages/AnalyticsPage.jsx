import { BarChart3, Target, Zap } from "lucide-react";
import { DASHBOARD_STATS } from "../data/mockData";
import {
  ThreatDonut,
  ScanTrend,
  RiskHistogram,
  ThreatIndicatorsChart,
  DailyScanLine
} from "../components/RiskCharts";
function MetricBadge({ label, value, color }) {
  return <div className={`px-4 py-3 rounded-xl border text-center ${color}`}>
      <p className="font-mono" style={{ fontSize: "1.1rem", fontWeight: 700 }}>{value}</p>
      <p style={{ fontSize: "0.7rem", opacity: 0.7 }}>{label}</p>
    </div>;
}
function AnalyticsPage() {
  const detectionRate = (DASHBOARD_STATS.phishing_detected / DASHBOARD_STATS.total_scans * 100).toFixed(1);
  const falseNegateRate = (100 - parseFloat(detectionRate) - DASHBOARD_STATS.suspicious_detected / DASHBOARD_STATS.total_scans * 100).toFixed(1);
  return <div className="p-6 max-w-7xl mx-auto space-y-6">
      {
    /* Header */
  }
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700">
          <BarChart3 size={18} className="text-cyan-400" />
        </div>
        <div>
          <h2 className="text-slate-100" style={{ fontSize: "1rem", fontWeight: 600 }}>
            Visual Analytics & Threat Intelligence
          </h2>
          <p className="text-slate-500 mt-0.5" style={{ fontSize: "0.775rem" }}>
            Recharts-powered dashboards for SOC analysts and security leadership
          </p>
        </div>
      </div>

      {
    /* KPI bar */
  }
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricBadge
    label="Phishing Detection Rate"
    value={`${detectionRate}%`}
    color="bg-red-500/10 border-red-500/20 text-red-400"
  />
        <MetricBadge
    label="Avg ML Confidence"
    value={`${(DASHBOARD_STATS.avg_confidence * 100).toFixed(1)}%`}
    color="bg-cyan-500/10 border-cyan-500/20 text-cyan-400"
  />
        <MetricBadge
    label="URLHaus Hit Rate"
    value={`${(DASHBOARD_STATS.urlhaus_hits / DASHBOARD_STATS.phishing_detected * 100).toFixed(0)}%`}
    color="bg-orange-500/10 border-orange-500/20 text-orange-400"
  />
        <MetricBadge
    label="Avg Scan Latency"
    value={`${DASHBOARD_STATS.avg_scan_duration_ms}ms`}
    color="bg-green-500/10 border-green-500/20 text-green-400"
  />
      </div>

      {
    /* Row 1 */
  }
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-1">
          <ThreatDonut />
        </div>
        <div className="lg:col-span-2">
          <ScanTrend />
        </div>
      </div>

      {
    /* Row 2 */
  }
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <RiskHistogram />
        <DailyScanLine />
      </div>

      {
    /* Row 3: Full width */
  }
      <ThreatIndicatorsChart />

      {
    /* ML Model Performance section */
  }
      <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Target size={16} className="text-cyan-400" />
          <h3 className="text-slate-200" style={{ fontSize: "0.9rem", fontWeight: 600 }}>
            ML Model Performance Metrics
          </h3>
          <span className="px-2 py-0.5 rounded-full bg-green-500/15 text-green-400 border border-green-500/30" style={{ fontSize: "0.65rem" }}>
            XGBoost v1.7
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700/50">
                {["Metric", "Phishing (Class 1)", "Safe (Class 0)", "Weighted Avg"].map((h) => <th key={h} className="text-left px-4 py-2.5 text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
                    {h}
                  </th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {[
    { metric: "Accuracy", p: "\u2014", s: "\u2014", avg: "96.4%" },
    { metric: "Precision", p: "97.2%", s: "95.8%", avg: "96.5%" },
    { metric: "Recall", p: "95.6%", s: "97.0%", avg: "96.3%" },
    { metric: "F1-Score", p: "96.4%", s: "96.4%", avg: "96.4%" },
    { metric: "ROC-AUC", p: "\u2014", s: "\u2014", avg: "0.9912" }
  ].map((row) => <tr key={row.metric} className="hover:bg-slate-800/20">
                  <td className="px-4 py-2.5 text-slate-400" style={{ fontSize: "0.8rem" }}>{row.metric}</td>
                  <td className="px-4 py-2.5 text-red-400 font-mono" style={{ fontSize: "0.8rem" }}>{row.p}</td>
                  <td className="px-4 py-2.5 text-green-400 font-mono" style={{ fontSize: "0.8rem" }}>{row.s}</td>
                  <td className="px-4 py-2.5 text-cyan-400 font-mono" style={{ fontSize: "0.8rem", fontWeight: 600 }}>{row.avg}</td>
                </tr>)}
            </tbody>
          </table>
        </div>

        {
    /* Confusion matrix mini display */
  }
        <div className="mt-4 pt-4 border-t border-slate-700/50">
          <p className="text-slate-500 mb-3 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
            Confusion Matrix (Test Set — 2,000 samples)
          </p>
          <div className="inline-grid grid-cols-3 gap-1 font-mono" style={{ fontSize: "0.72rem" }}>
            <div />
            <div className="px-3 py-1 text-center text-red-400">Pred. Phishing</div>
            <div className="px-3 py-1 text-center text-green-400">Pred. Safe</div>
            <div className="px-3 py-1 text-right text-red-400">Actual Phishing</div>
            <div className="px-3 py-2 text-center rounded-lg bg-green-500/15 text-green-300 border border-green-500/20">956 TP</div>
            <div className="px-3 py-2 text-center rounded-lg bg-red-500/15 text-red-400 border border-red-500/20">44 FN</div>
            <div className="px-3 py-1 text-right text-green-400">Actual Safe</div>
            <div className="px-3 py-2 text-center rounded-lg bg-red-500/15 text-red-400 border border-red-500/20">29 FP</div>
            <div className="px-3 py-2 text-center rounded-lg bg-green-500/15 text-green-300 border border-green-500/20">971 TN</div>
          </div>
        </div>
      </div>

      {
    /* Feature Importance */
  }
      <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Zap size={16} className="text-yellow-400" />
          <h3 className="text-slate-200" style={{ fontSize: "0.9rem", fontWeight: 600 }}>
            Top ML Feature Importances
          </h3>
        </div>
        <div className="space-y-2">
          {[
    { name: "URL entropy / randomness", score: 0.18, color: "bg-cyan-400" },
    { name: "Suspicious keyword presence", score: 0.16, color: "bg-red-400" },
    { name: "Domain age (days)", score: 0.14, color: "bg-red-400" },
    { name: "URL length", score: 0.11, color: "bg-yellow-400" },
    { name: "IP-based URL", score: 0.1, color: "bg-red-400" },
    { name: "Hyphen count in domain", score: 0.09, color: "bg-yellow-400" },
    { name: "HTTPS presence", score: 0.08, color: "bg-green-400" },
    { name: "Typosquatting similarity", score: 0.07, color: "bg-orange-400" },
    { name: "Subdomain count", score: 0.05, color: "bg-blue-400" },
    { name: "Special character count", score: 0.02, color: "bg-slate-400" }
  ].map(({ name, score, color }) => <div key={name} className="flex items-center gap-3">
              <div className="w-40 shrink-0">
                <span className="text-slate-400" style={{ fontSize: "0.78rem" }}>{name}</span>
              </div>
              <div className="flex-1 h-2 bg-slate-700 rounded-full overflow-hidden">
                <div className={`h-full ${color} rounded-full`} style={{ width: `${score * 100 * 5}%` }} />
              </div>
              <span className="text-slate-400 font-mono w-10 text-right" style={{ fontSize: "0.75rem" }}>
                {(score * 100).toFixed(0)}%
              </span>
            </div>)}
        </div>
      </div>
    </div>;
}
export {
  AnalyticsPage
};
