import { FileText } from "lucide-react";
import { IOCReportViewer } from "../components/IOCReportViewer";
function ReportsPage() {
  return <div className="p-6 max-w-7xl mx-auto space-y-5">
      {
    /* Header */
  }
      <div className="flex items-center gap-3">
        <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700">
          <FileText size={18} className="text-cyan-400" />
        </div>
        <div>
          <h2 className="text-slate-100" style={{ fontSize: "1rem", fontWeight: 600 }}>
            IOC Report Viewer
          </h2>
          <p className="text-slate-500 mt-0.5" style={{ fontSize: "0.775rem" }}>
            Browse detailed Indicators of Compromise reports. Export as JSON or print as PDF for incident response documentation.
          </p>
        </div>
      </div>

      {
    /* IOC Viewer */
  }
      <IOCReportViewer />
    </div>;
}
export {
  ReportsPage
};
