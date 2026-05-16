import { useState, useMemo } from "react";
import {
  Search,
  Filter,
  Download,
  ChevronUp,
  ChevronDown,
  ExternalLink,
  ChevronLeft,
  ChevronRight as ChevRight,
  Trash2
} from "lucide-react";
import { useScanContext } from "../context/ScanContext";
import { ThreatBadge } from "./ThreatBadge";
const PAGE_SIZES = [10, 20, 50];
function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  });
}
function RiskBar({ score }) {
  const color = score >= 70 ? "bg-red-500" : score >= 40 ? "bg-yellow-500" : "bg-green-500";
  return <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${score}%` }} />
      </div>
      <span className={`font-mono ${score >= 70 ? "text-red-400" : score >= 40 ? "text-yellow-400" : "text-green-400"}`} style={{ fontSize: "0.78rem" }}>
        {score}
      </span>
    </div>;
}
function HistoryTable({ compact = false }) {
  const { allScans, clearUserScans, userScans } = useScanContext();
  const [query, setQuery] = useState("");
  const [filterLevel, setFilterLevel] = useState("all");
  const [sortKey, setSortKey] = useState("timestamp");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(compact ? 5 : 10);
  const [selected, setSelected] = useState([]);
  const handleSort = (key) => {
    if (sortKey === key) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else {
      setSortKey(key);
      setSortDir("desc");
    }
  };
  const filtered = useMemo(() => {
    let data = [...allScans];
    if (filterLevel !== "all") data = data.filter((d) => d.prediction === filterLevel);
    if (query) {
      const q = query.toLowerCase();
      data = data.filter(
        (d) => d.url.toLowerCase().includes(q) || d.domain.toLowerCase().includes(q) || d.prediction.includes(q)
      );
    }
    data.sort((a, b) => {
      let va, vb;
      switch (sortKey) {
        case "timestamp":
          va = a.timestamp;
          vb = b.timestamp;
          break;
        case "risk_score":
          va = a.risk_score;
          vb = b.risk_score;
          break;
        case "confidence":
          va = a.confidence;
          vb = b.confidence;
          break;
        case "domain":
          va = a.domain;
          vb = b.domain;
          break;
        case "prediction":
          va = a.prediction;
          vb = b.prediction;
          break;
        default:
          va = a.timestamp;
          vb = b.timestamp;
      }
      if (va < vb) return sortDir === "asc" ? -1 : 1;
      if (va > vb) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return data;
  }, [allScans, query, filterLevel, sortKey, sortDir]);
  const totalPages = Math.ceil(filtered.length / pageSize);
  const paged = filtered.slice((page - 1) * pageSize, page * pageSize);
  const SortIcon = ({ col }) => sortKey === col ? sortDir === "asc" ? <ChevronUp size={12} /> : <ChevronDown size={12} /> : <ChevronDown size={12} className="opacity-20" />;
  const handleExportCSV = () => {
    const headers = ["ID", "URL", "Prediction", "Risk Score", "Confidence", "Domain", "Timestamp", "VT Detections"];
    const rows = filtered.map((r) => [
      r.id,
      r.url,
      r.prediction,
      r.risk_score,
      r.confidence,
      r.domain,
      r.timestamp,
      r.virustotal_detections
    ]);
    const csv = [headers, ...rows].map((row) => row.map((v) => `"${v}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "phishguard_history.csv";
    a.click();
  };
  return <div className="space-y-4">
      {
    /* Controls */
  }
      {!compact && <div className="flex flex-col sm:flex-row gap-3">
          {
    /* Search */
  }
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
    type="text"
    value={query}
    onChange={(e) => {
      setQuery(e.target.value);
      setPage(1);
    }}
    placeholder="Search URLs, domains..."
    className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20"
    style={{ fontSize: "0.825rem" }}
  />
          </div>

          {
    /* Filter by level */
  }
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-slate-500" />
            {["all", "phishing", "suspicious", "safe"].map((lv) => <button
    key={lv}
    onClick={() => {
      setFilterLevel(lv);
      setPage(1);
    }}
    className={`px-3 py-1.5 rounded-lg transition-colors capitalize ${filterLevel === lv ? lv === "phishing" ? "bg-red-500/20 text-red-400 border border-red-500/30" : lv === "suspicious" ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30" : lv === "safe" ? "bg-green-500/20 text-green-400 border border-green-500/30" : "bg-slate-700 text-slate-200 border border-slate-600" : "bg-slate-800/60 text-slate-500 border border-slate-700/50 hover:text-slate-300"}`}
    style={{ fontSize: "0.75rem" }}
  >
                {lv}
              </button>)}
          </div>

          <button
    onClick={handleExportCSV}
    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
    style={{ fontSize: "0.8rem" }}
  >
            <Download size={13} /> Export CSV
          </button>

          {userScans.length > 0 && <button
    onClick={clearUserScans}
    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:text-red-300 hover:bg-red-500/20 transition-colors"
    style={{ fontSize: "0.8rem" }}
  >
              <Trash2 size={13} /> Clear My Scans ({userScans.length})
            </button>}
        </div>}

      {
    /* Table */
  }
      <div className="rounded-xl border border-slate-700/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-800/80 border-b border-slate-700/50">
                {!compact && <th className="w-8 px-4 py-3">
                    <input
    type="checkbox"
    checked={selected.length === paged.length && paged.length > 0}
    onChange={(e) => setSelected(e.target.checked ? paged.map((r) => r.id) : [])}
    className="w-3.5 h-3.5 accent-cyan-500"
  />
                  </th>}
                <th className="px-4 py-3 text-left">
                  <button onClick={() => handleSort("domain")} className="flex items-center gap-1 text-slate-400 hover:text-slate-200 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
                    URL / Domain <SortIcon col="domain" />
                  </button>
                </th>
                <th className="px-4 py-3 text-left">
                  <button onClick={() => handleSort("prediction")} className="flex items-center gap-1 text-slate-400 hover:text-slate-200 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
                    Result <SortIcon col="prediction" />
                  </button>
                </th>
                <th className="px-4 py-3 text-left">
                  <button onClick={() => handleSort("risk_score")} className="flex items-center gap-1 text-slate-400 hover:text-slate-200 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
                    Risk Score <SortIcon col="risk_score" />
                  </button>
                </th>
                {!compact && <>
                    <th className="px-4 py-3 text-left">
                      <span className="text-slate-400 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>VT Detections</span>
                    </th>
                    <th className="px-4 py-3 text-left">
                      <button onClick={() => handleSort("confidence")} className="flex items-center gap-1 text-slate-400 hover:text-slate-200 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
                        Confidence <SortIcon col="confidence" />
                      </button>
                    </th>
                  </>}
                <th className="px-4 py-3 text-left">
                  <button onClick={() => handleSort("timestamp")} className="flex items-center gap-1 text-slate-400 hover:text-slate-200 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
                    Time <SortIcon col="timestamp" />
                  </button>
                </th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {paged.length === 0 ? <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500" style={{ fontSize: "0.875rem" }}>
                    No scan results found
                  </td>
                </tr> : paged.map((row) => <tr key={row.id} className="hover:bg-slate-800/30 transition-colors group">
                  {!compact && <td className="px-4 py-3">
                      <input
    type="checkbox"
    checked={selected.includes(row.id)}
    onChange={(e) => setSelected((s) => e.target.checked ? [...s, row.id] : s.filter((id) => id !== row.id))}
    className="w-3.5 h-3.5 accent-cyan-500"
  />
                    </td>}
                  <td className="px-4 py-3 max-w-xs">
                    <div>
                      <p className="text-slate-300 font-mono truncate" style={{ fontSize: "0.775rem" }}>{row.domain}</p>
                      <p className="text-slate-600 truncate font-mono" style={{ fontSize: "0.68rem" }}>
                        {row.url.length > 50 ? row.url.slice(0, 50) + "\u2026" : row.url}
                      </p>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <ThreatBadge level={row.prediction} size="sm" />
                  </td>
                  <td className="px-4 py-3">
                    <RiskBar score={row.risk_score} />
                  </td>
                  {!compact && <>
                      <td className="px-4 py-3">
                        <span className={`font-mono ${row.virustotal.positives > 0 ? "text-red-400" : "text-green-400"}`} style={{ fontSize: "0.78rem" }}>
                          {row.virustotal_detections}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-slate-400 font-mono" style={{ fontSize: "0.78rem" }}>
                          {(row.confidence * 100).toFixed(1)}%
                        </span>
                      </td>
                    </>}
                  <td className="px-4 py-3">
                    <span className="text-slate-500" style={{ fontSize: "0.75rem" }}>{formatTime(row.timestamp)}</span>
                  </td>
                  <td className="px-4 py-3">
                    <a
    href={row.url}
    target="_blank"
    rel="noopener noreferrer"
    className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-500 hover:text-cyan-400"
  >
                      <ExternalLink size={13} />
                    </a>
                  </td>
                </tr>)}
            </tbody>
          </table>
        </div>

        {
    /* Pagination */
  }
        <div className="flex items-center justify-between px-4 py-3 bg-slate-800/40 border-t border-slate-700/50">
          <div className="flex items-center gap-3">
            <span className="text-slate-500" style={{ fontSize: "0.75rem" }}>
              {filtered.length} results
            </span>
            {!compact && <select
    value={pageSize}
    onChange={(e) => {
      setPageSize(Number(e.target.value));
      setPage(1);
    }}
    className="bg-slate-800 border border-slate-700 text-slate-400 rounded px-2 py-1"
    style={{ fontSize: "0.75rem" }}
  >
                {PAGE_SIZES.map((s) => <option key={s} value={s}>{s} per page</option>)}
              </select>}
          </div>
          <div className="flex items-center gap-2">
            <button
    onClick={() => setPage((p) => Math.max(1, p - 1))}
    disabled={page === 1}
    className="p-1 rounded text-slate-500 hover:text-slate-200 disabled:opacity-30"
  >
              <ChevronLeft size={15} />
            </button>
            <span className="text-slate-400" style={{ fontSize: "0.78rem" }}>
              {page} / {totalPages || 1}
            </span>
            <button
    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
    disabled={page >= totalPages}
    className="p-1 rounded text-slate-500 hover:text-slate-200 disabled:opacity-30"
  >
              <ChevRight size={15} />
            </button>
          </div>
        </div>
      </div>
    </div>;
}
export {
  HistoryTable
};
