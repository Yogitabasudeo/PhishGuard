import { createBrowserRouter, Outlet, useLocation } from "react-router";
import { Sidebar } from "./components/layout/Sidebar";
import { Header } from "./components/layout/Header";
import { DashboardPage } from "./pages/DashboardPage";
import { ScannerPage } from "./pages/ScannerPage";
import { HistoryPage } from "./pages/HistoryPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ExtensionPage } from "./pages/ExtensionPage";
import { BackendPage } from "./pages/BackendPage";
const PAGE_META = {
  "/": { title: "PhishGuard Dashboard", subtitle: "SOC Analyst Threat Intelligence Overview" },
  "/scanner": { title: "URL Scanner", subtitle: "Submit URLs for real-time phishing detection" },
  "/history": { title: "Scan History", subtitle: "Browse and filter historical scan results" },
  "/analytics": { title: "Visual Analytics", subtitle: "Threat intelligence charts and model metrics" },
  "/reports": { title: "IOC Reports", subtitle: "Indicators of Compromise \u2014 detailed forensic reports" },
  "/extension": { title: "Chrome Extension", subtitle: "Real-time browser phishing protection \u2014 Manifest V3" },
  "/backend": { title: "ML Model & FastAPI Backend", subtitle: "XGBoost classifier \xB7 REST API \xB7 CTI integration \xB7 26 features" }
};
function RootLayout() {
  const location = useLocation();
  const meta = PAGE_META[location.pathname] || PAGE_META["/"];
  return <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      <Sidebar />
      {
    /* Main content — offset for sidebar on large screens */
  }
      <div className="flex-1 flex flex-col lg:ml-64">
        <Header title={meta.title} subtitle={meta.subtitle} />
        <main className="flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>;
}
function NotFound() {
  return <div className="flex flex-col items-center justify-center h-full py-24 text-center">
      <div className="text-slate-700" style={{ fontSize: "5rem", fontWeight: 800, fontFamily: "monospace" }}>404</div>
      <p className="text-slate-400 mt-2">Page not found</p>
    </div>;
}
const router = createBrowserRouter([
  {
    path: "/",
    Component: RootLayout,
    children: [
      { index: true, Component: DashboardPage },
      { path: "scanner", Component: ScannerPage },
      { path: "history", Component: HistoryPage },
      { path: "analytics", Component: AnalyticsPage },
      { path: "reports", Component: ReportsPage },
      { path: "extension", Component: ExtensionPage },
      { path: "backend", Component: BackendPage },
      { path: "*", Component: NotFound }
    ]
  }
]);
export {
  router
};
