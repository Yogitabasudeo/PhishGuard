import { History, Database } from "lucide-react";
import { HistoryTable } from "../components/HistoryTable";
import { DASHBOARD_STATS } from "../data/mockData";
function HistoryPage() {
  return <div className="p-6 max-w-7xl mx-auto space-y-5">
      {
    /* Header */
  }
      <div className="flex flex-col sm:flex-row sm:items-center gap-4 justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700">
            <History size={18} className="text-cyan-400" />
          </div>
          <div>
            <h2 className="text-slate-100" style={{ fontSize: "1rem", fontWeight: 600 }}>Scan History</h2>
            <p className="text-slate-500 mt-0.5" style={{ fontSize: "0.775rem" }}>
              Browse, filter, and export historical URL scan results
            </p>
          </div>
        </div>

        <div className="flex gap-3">
          <div className="px-4 py-2 rounded-xl bg-slate-800/50 border border-slate-700/50 text-center">
            <p className="text-slate-200 font-mono" style={{ fontSize: "1rem", fontWeight: 700 }}>
              {DASHBOARD_STATS.total_scans}
            </p>
            <p className="text-slate-500" style={{ fontSize: "0.65rem" }}>Total Scans</p>
          </div>
          <div className="px-4 py-2 rounded-xl bg-red-500/10 border border-red-500/20 text-center">
            <p className="text-red-400 font-mono" style={{ fontSize: "1rem", fontWeight: 700 }}>
              {DASHBOARD_STATS.phishing_detected}
            </p>
            <p className="text-red-500/70" style={{ fontSize: "0.65rem" }}>Phishing</p>
          </div>
          <div className="px-4 py-2 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-center">
            <p className="text-yellow-400 font-mono" style={{ fontSize: "1rem", fontWeight: 700 }}>
              {DASHBOARD_STATS.suspicious_detected}
            </p>
            <p className="text-yellow-500/70" style={{ fontSize: "0.65rem" }}>Suspicious</p>
          </div>
          <div className="px-4 py-2 rounded-xl bg-green-500/10 border border-green-500/20 text-center">
            <p className="text-green-400 font-mono" style={{ fontSize: "1rem", fontWeight: 700 }}>
              {DASHBOARD_STATS.safe_detected}
            </p>
            <p className="text-green-500/70" style={{ fontSize: "0.65rem" }}>Safe</p>
          </div>
        </div>
      </div>

      {
    /* Database info bar */
  }
      <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800/30 border border-slate-700/30">
        <Database size={13} className="text-slate-500" />
        <span className="text-slate-500" style={{ fontSize: "0.75rem" }}>
          PostgreSQL Database · Table: <code className="font-mono text-slate-400">scan_history</code> · 
          Endpoint: <code className="font-mono text-slate-400">GET /history</code>
        </span>
        <div className="ml-auto flex items-center gap-1.5">
          <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          <span className="text-green-400" style={{ fontSize: "0.68rem" }}>Connected</span>
        </div>
      </div>

      {
    /* Table */
  }
      <HistoryTable />
    </div>;
}
export {
  HistoryPage
};
