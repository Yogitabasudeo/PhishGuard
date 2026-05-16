import { useState, useRef } from "react";
import { Search, X, Loader2, ChevronRight, AlertCircle } from "lucide-react";
import { simulateScan, SCAN_STAGES } from "../utils/scanSimulator";
import { useScanContext } from "../context/ScanContext";
import { ResultCard } from "./ResultCard";
const EXAMPLE_URLS = [
  "http://paypal-security-center.com/verify-account",
  "https://www.github.com/microsoft/vscode",
  "http://192.168.45.102/banking/login.php",
  "https://amazon-order-confirm.xyz/tracking"
];
function ScanForm() {
  const { addScan } = useScanContext();
  const [url, setUrl] = useState("");
  const [scanState, setScanState] = useState("idle");
  const [currentStage, setCurrentStage] = useState(0);
  const [stageProgress, setStageProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);
  const handleScan = async () => {
    if (!url.trim()) {
      inputRef.current?.focus();
      return;
    }
    const trimmed = url.trim();
    if (!trimmed.includes(".")) {
      setError("Please enter a valid URL (e.g., https://example.com)");
      return;
    }
    setError(null);
    setResult(null);
    setScanState("scanning");
    setCurrentStage(0);
    setStageProgress(0);
    let elapsed = 0;
    for (let i = 0; i < SCAN_STAGES.length; i++) {
      setCurrentStage(i);
      setStageProgress(0);
      const stage = SCAN_STAGES[i];
      const steps = 20;
      const stepDuration = stage.duration / steps;
      for (let s = 0; s <= steps; s++) {
        await new Promise((r) => setTimeout(r, stepDuration));
        setStageProgress(Math.round(s / steps * 100));
      }
      elapsed += stage.duration;
    }
    try {
      const scanResult = await simulateScan(trimmed);
      addScan(scanResult);
      setResult(scanResult);
      setScanState("done");
    } catch (e) {
      setError("Scan failed. Please check the URL and try again.");
      setScanState("error");
    }
  };
  const handleReset = () => {
    setUrl("");
    setResult(null);
    setScanState("idle");
    setError(null);
    setCurrentStage(0);
    inputRef.current?.focus();
  };
  const handleExportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phishguard_scan_${result.id}.json`;
    a.click();
  };
  const overallProgress = scanState === "scanning" ? Math.round(currentStage / SCAN_STAGES.length * 100 + stageProgress / SCAN_STAGES.length) : 0;
  return <div className="space-y-6">
      {
    /* Input area */
  }
      <div className="rounded-2xl bg-slate-800/40 border border-slate-700/50 p-5">
        <label className="block text-slate-300 mb-3" style={{ fontSize: "0.875rem", fontWeight: 600 }}>
          Enter URL to Scan
        </label>

        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
            <input
    ref={inputRef}
    type="text"
    value={url}
    onChange={(e) => setUrl(e.target.value)}
    onKeyDown={(e) => e.key === "Enter" && scanState === "idle" && handleScan()}
    placeholder="https://suspicious-site.com/login"
    disabled={scanState === "scanning"}
    className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all font-mono disabled:opacity-50"
    style={{ fontSize: "0.875rem" }}
  />
            {url && <button
    onClick={() => setUrl("")}
    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
  >
                <X size={14} />
              </button>}
          </div>
          <button
    onClick={scanState === "done" || scanState === "error" ? handleReset : handleScan}
    disabled={scanState === "scanning"}
    className={`px-5 py-3 rounded-xl font-medium transition-all flex items-center gap-2 ${scanState === "done" || scanState === "error" ? "bg-slate-700 hover:bg-slate-600 text-slate-300" : "bg-cyan-500 hover:bg-cyan-400 text-slate-950 disabled:opacity-60 disabled:cursor-not-allowed"}`}
    style={{ fontSize: "0.875rem", minWidth: "100px" }}
  >
            {scanState === "scanning" ? <><Loader2 size={16} className="animate-spin" /> Scanning</> : scanState === "done" || scanState === "error" ? <>New Scan</> : <><Search size={16} /> Scan URL</>}
          </button>
        </div>

        {error && <div className="mt-3 flex items-center gap-2 text-red-400" style={{ fontSize: "0.8rem" }}>
            <AlertCircle size={14} />
            {error}
          </div>}

        {
    /* Example URLs */
  }
        {scanState === "idle" && <div className="mt-4">
            <p className="text-slate-500 mb-2" style={{ fontSize: "0.72rem" }}>Try these example URLs:</p>
            <div className="flex flex-wrap gap-2">
              {EXAMPLE_URLS.map((ex) => <button
    key={ex}
    onClick={() => setUrl(ex)}
    className="px-2.5 py-1 rounded-lg bg-slate-900/60 border border-slate-700/50 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors font-mono truncate max-w-xs"
    style={{ fontSize: "0.68rem" }}
  >
                  {ex.length > 45 ? ex.slice(0, 45) + "..." : ex}
                </button>)}
            </div>
          </div>}
      </div>

      {
    /* Scanning progress */
  }
      {scanState === "scanning" && <div className="rounded-2xl bg-slate-800/40 border border-slate-700/50 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Loader2 size={16} className="text-cyan-400 animate-spin" />
              <span className="text-slate-300" style={{ fontSize: "0.875rem", fontWeight: 600 }}>
                Analyzing URL...
              </span>
            </div>
            <span className="text-cyan-400 font-mono" style={{ fontSize: "0.875rem" }}>
              {overallProgress}%
            </span>
          </div>

          {
    /* Overall progress bar */
  }
          <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
            <div
    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-300"
    style={{ width: `${overallProgress}%` }}
  />
          </div>

          {
    /* Stage list */
  }
          <div className="space-y-1.5">
            {SCAN_STAGES.map((stage, idx) => <div key={idx} className="flex items-center gap-3">
                <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${idx < currentStage ? "bg-green-400" : idx === currentStage ? "bg-cyan-400 animate-pulse" : "bg-slate-700"}`} />
                <span
    className={`${idx < currentStage ? "text-green-400" : idx === currentStage ? "text-cyan-400" : "text-slate-600"}`}
    style={{ fontSize: "0.78rem" }}
  >
                  {stage.label}
                </span>
                {idx < currentStage && <span className="text-green-400 ml-auto" style={{ fontSize: "0.68rem" }}>✓</span>}
                {idx === currentStage && <div className="ml-auto w-16 h-1 bg-slate-700 rounded-full overflow-hidden">
                    <div
    className="h-full bg-cyan-400 transition-all duration-100"
    style={{ width: `${stageProgress}%` }}
  />
                  </div>}
              </div>)}
          </div>

          {
    /* Scanning URL */
  }
          <div className="pt-2 border-t border-slate-700/50">
            <p className="text-slate-600" style={{ fontSize: "0.68rem" }}>Analyzing:</p>
            <p className="text-slate-400 font-mono truncate" style={{ fontSize: "0.72rem" }}>{url}</p>
          </div>
        </div>}

      {
    /* Result */
  }
      {scanState === "done" && result && <div>
          <div className="flex items-center gap-2 mb-4">
            <ChevronRight size={16} className="text-cyan-400" />
            <span className="text-slate-300" style={{ fontSize: "0.875rem", fontWeight: 600 }}>
              Scan Results
            </span>
            <span className="text-slate-500" style={{ fontSize: "0.75rem" }}>
              — completed in {result.scan_duration_ms}ms
            </span>
          </div>
          <ResultCard result={result} onExportJSON={handleExportJSON} />
        </div>}
    </div>;
}
export {
  ScanForm
};
