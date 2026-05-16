import { NavLink } from "react-router";
import {
  Shield,
  LayoutDashboard,
  Search,
  History,
  BarChart3,
  FileText,
  ChevronRight,
  Activity,
  Wifi,
  X,
  Menu,
  Chrome,
  Server
} from "lucide-react";
import { useState } from "react";
const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/scanner", label: "URL Scanner", icon: Search },
  { to: "/history", label: "Scan History", icon: History },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/reports", label: "IOC Reports", icon: FileText },
  { to: "/extension", label: "Chrome Extension", icon: Chrome },
  { to: "/backend", label: "ML + API Backend", icon: Server }
];
function Sidebar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  return <>
      {
    /* Mobile toggle button */
  }
      <button
    className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-cyan-400"
    onClick={() => setMobileOpen(!mobileOpen)}
  >
        {mobileOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {
    /* Mobile overlay */
  }
      {mobileOpen && <div
    className="lg:hidden fixed inset-0 z-30 bg-black/60 backdrop-blur-sm"
    onClick={() => setMobileOpen(false)}
  />}

      {
    /* Sidebar */
  }
      <aside
    className={`
          fixed top-0 left-0 h-full z-40 w-64 flex flex-col
          bg-slate-900 border-r border-slate-800
          transition-transform duration-300
          ${mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
        `}
  >
        {
    /* Logo */
  }
        <div className="flex items-center gap-3 px-6 py-5 border-b border-slate-800">
          <div className="relative">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
              <Shield size={20} className="text-cyan-400" />
            </div>
            <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-green-400 border-2 border-slate-900" />
          </div>
          <div>
            <span className="text-white tracking-tight" style={{ fontWeight: 700, fontSize: "1.1rem" }}>
              PhishGuard
            </span>
            <div className="flex items-center gap-1 mt-0.5">
              <Activity size={10} className="text-green-400" />
              <span className="text-green-400" style={{ fontSize: "0.65rem" }}>System Active</span>
            </div>
          </div>
        </div>

        {
    /* Navigation */
  }
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <p className="px-3 mb-3 text-slate-500 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>
            Main Menu
          </p>
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => <NavLink
    key={to}
    to={to}
    end={end}
    onClick={() => setMobileOpen(false)}
    className={({ isActive }) => `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150 group ${isActive ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
  >
              {({ isActive }) => <>
                  <Icon size={17} className={isActive ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300"} />
                  <span style={{ fontSize: "0.875rem" }}>{label}</span>
                  {isActive && <ChevronRight size={14} className="ml-auto text-cyan-400/70" />}
                </>}
            </NavLink>)}
        </nav>

        {
    /* Bottom section — threat feed status */
  }
        <div className="px-4 py-4 border-t border-slate-800 space-y-2">
          <p className="text-slate-500 uppercase tracking-wider mb-3" style={{ fontSize: "0.65rem" }}>
            Threat Intel Feeds
          </p>
          {[
    { name: "VirusTotal API", ok: true },
    { name: "URLHaus Feed", ok: true },
    { name: "PhishTank DB", ok: true },
    { name: "WHOIS Service", ok: false }
  ].map(({ name, ok }) => <div key={name} className="flex items-center gap-2">
              <div className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-green-400" : "bg-yellow-400"}`} />
              <span className="text-slate-500" style={{ fontSize: "0.7rem" }}>{name}</span>
              <span className={`ml-auto ${ok ? "text-green-400" : "text-yellow-400"}`} style={{ fontSize: "0.65rem" }}>
                {ok ? "Online" : "Degraded"}
              </span>
            </div>)}
        </div>

        {
    /* API status indicator */
  }
        <div className="px-4 py-3 border-t border-slate-800">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/70">
            <Wifi size={13} className="text-cyan-400" />
            <span className="text-slate-400" style={{ fontSize: "0.72rem" }}>
              API: localhost:8000
            </span>
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 ml-auto animate-pulse" />
          </div>
        </div>
      </aside>
    </>;
}
export {
  Sidebar
};
