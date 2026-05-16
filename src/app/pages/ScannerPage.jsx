import { Shield, Info } from "lucide-react";
import { ScanForm } from "../components/ScanForm";
const FEATURE_LIST = [
  { label: "XGBoost ML Model", desc: "24-feature classification pipeline" },
  { label: "VirusTotal API", desc: "90-vendor multi-scanner" },
  { label: "URLHaus Integration", desc: "MalwareBazaar threat feed" },
  { label: "PhishTank Database", desc: "Community phishing DB" },
  { label: "WHOIS Forensics", desc: "Domain registration analysis" },
  { label: "DNS Analysis", desc: "A, MX, NS, TXT record lookup" },
  { label: "Typosquatting Detection", desc: "Levenshtein distance matching" },
  { label: "IP Forensics", desc: "ASN, geolocation, ISP lookup" }
];
function ScannerPage() {
  return <div className="p-6 max-w-4xl mx-auto space-y-6">
      {
    /* Page header */
  }
      <div className="bg-slate-800/40 border border-slate-700/50 rounded-2xl p-5">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-cyan-500/15 border border-cyan-500/20">
            <Shield size={22} className="text-cyan-400" />
          </div>
          <div>
            <h2 className="text-slate-100" style={{ fontSize: "1.05rem", fontWeight: 600 }}>
              ML-Powered URL Scanner
            </h2>
            <p className="text-slate-400 mt-1" style={{ fontSize: "0.825rem" }}>
              Submit any URL for real-time phishing detection using our XGBoost ML model, combined with live threat
              intelligence from VirusTotal, URLHaus, PhishTank, WHOIS, and DNS forensics.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              {FEATURE_LIST.map(({ label, desc }) => <div
    key={label}
    className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/60 border border-slate-700/40 group relative"
    title={desc}
  >
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  <span className="text-slate-400" style={{ fontSize: "0.7rem" }}>{label}</span>
                </div>)}
            </div>
          </div>
        </div>
      </div>

      {
    /* Scan form */
  }
      <ScanForm />

      {
    /* Info note */
  }
      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl bg-slate-800/30 border border-slate-700/30">
        <Info size={14} className="text-slate-500 mt-0.5 shrink-0" />
        <p className="text-slate-500" style={{ fontSize: "0.75rem" }}>
          This is a demo environment using a simulated backend. In production, scan requests are sent to
          <code className="mx-1 px-1 bg-slate-800 rounded text-slate-400 font-mono">POST /scan</code>
          on the FastAPI backend which runs XGBoost inference and queries live threat intelligence APIs.
          Scan results are stored in PostgreSQL and accessible via
          <code className="ml-1 px-1 bg-slate-800 rounded text-slate-400 font-mono">GET /history</code>.
        </p>
      </div>
    </div>;
}
export {
  ScannerPage
};
