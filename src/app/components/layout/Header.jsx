import {
  Bell,
  Download,
  Settings,
  User,
  Shield,
  Clock,
  X,
  AlertTriangle,
  CheckCircle,
  Info,
  ChevronRight,
  LogOut,
  LogIn,
  Key,
  Moon,
  Sun,
  Monitor,
  Sliders,
  Database,
  Wifi,
  Save,
  UserCircle,
  BadgeCheck,
  Mail,
  Phone,
  Globe
} from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { Link } from "react-router";
import { useAuth } from "../../context/AuthContext";
import { useNotifications } from "../../context/NotificationContext";
import { useTheme } from "../../context/ThemeContext";
import { LoginModal } from "../LoginModal";
import { DownloadExtensionButton } from "../DownloadExtensionButton";
import { ProfileEditModal } from "../ProfileEditModal";
const INITIAL_NOTIFICATIONS = [
  { id: "n1", type: "danger", title: "High-risk phishing URL detected", body: "paypal-security-center.com \u2014 Risk Score 94", time: "2 min ago", read: false },
  { id: "n2", type: "warning", title: "Suspicious domain flagged", body: "amazon-order-confirm.xyz \u2014 DGA pattern detected", time: "18 min ago", read: false },
  { id: "n3", type: "danger", title: "URLHaus threat feed match", body: "bankofamerica-secure-login.net \u2014 listed on URLHaus", time: "1 hr ago", read: false },
  { id: "n4", type: "info", title: "VirusTotal quota at 80%", body: "720 / 900 daily API calls consumed", time: "3 hrs ago", read: true },
  { id: "n5", type: "success", title: "IOC Report generated", body: "Weekly threat intelligence report is ready", time: "5 hrs ago", read: true }
];
const notifIcon = (type) => {
  if (type === "danger") return <AlertTriangle size={13} className="text-red-400" />;
  if (type === "warning") return <AlertTriangle size={13} className="text-yellow-400" />;
  if (type === "success") return <CheckCircle size={13} className="text-green-400" />;
  return <Info size={13} className="text-cyan-400" />;
};
const notifRing = (type) => type === "danger" ? "bg-red-500/15" : type === "warning" ? "bg-yellow-500/15" : type === "success" ? "bg-green-500/15" : "bg-cyan-500/15";
const notifDot = (type) => type === "danger" ? "bg-red-500" : type === "warning" ? "bg-yellow-500" : type === "success" ? "bg-green-500" : "bg-cyan-500";
const STATUS_DOT = {
  "on-duty": "bg-green-400",
  "off-duty": "bg-slate-500",
  "break": "bg-yellow-400"
};
const STATUS_LABEL = {
  "on-duty": "On Duty",
  "off-duty": "Off Duty",
  "break": "On Break"
};
function Header({ title, subtitle }) {
  const { isLoggedIn, user, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const { notifications, unreadCount, markRead, markAllRead } = useNotifications();
  const [time, setTime] = useState(/* @__PURE__ */ new Date());
  const [showNotifs, setShowNotifs] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showLogin, setShowLogin] = useState(false);
  const [showEditProfile, setShowEditProfile] = useState(false);
  const [settings, setSettings] = useState({
    theme: "dark",
    alertThreshold: 70,
    vtEnabled: true,
    urlhausEnabled: true,
    phishtankEnabled: true,
    apiUrl: "http://localhost:8000",
    maxHistory: "200"
  });
  const [settingsSaved, setSettingsSaved] = useState(false);
  const notifsRef = useRef(null);
  const settingsRef = useRef(null);
  const profileRef = useRef(null);
  useEffect(() => {
    const t = setInterval(() => setTime(/* @__PURE__ */ new Date()), 1e3);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    const handler = (e) => {
      if (notifsRef.current && !notifsRef.current.contains(e.target)) setShowNotifs(false);
      if (settingsRef.current && !settingsRef.current.contains(e.target)) setShowSettings(false);
      if (profileRef.current && !profileRef.current.contains(e.target)) setShowProfile(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);
  const closeAll = (except) => {
    if (except !== "notifs") setShowNotifs(false);
    if (except !== "settings") setShowSettings(false);
    if (except !== "profile") setShowProfile(false);
  };
  const saveSettings = () => {
    setSettingsSaved(true);
    setTimeout(() => setSettingsSaved(false), 2e3);
  };
  return <>
      {
    /* ── Modals ─────────────────────────────────────────── */
  }
      {showLogin && <LoginModal onClose={() => setShowLogin(false)} />}
      {showEditProfile && <ProfileEditModal onClose={() => {
    setShowEditProfile(false);
    setShowProfile(false);
  }} />}

      <header className="sticky top-0 z-20 flex items-center justify-between px-6 py-4 bg-slate-950/80 backdrop-blur-md border-b border-slate-800">
        {
    /* Page title */
  }
        <div>
          <h1 className="text-slate-100" style={{ fontSize: "1.15rem", fontWeight: 600 }}>{title}</h1>
          {subtitle && <p className="text-slate-500 mt-0.5" style={{ fontSize: "0.775rem" }}>{subtitle}</p>}
        </div>

        <div className="flex items-center gap-3">
          {
    /* Clock */
  }
          {/* Download Extension */}
          <DownloadExtensionButton variant="navbar" />

          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700/50">
            <Clock size={13} className="text-slate-500" />
            <span className="text-slate-400 font-mono" style={{ fontSize: "0.75rem" }}>
              {time.toLocaleTimeString("en-US", { hour12: false })}
            </span>
          </div>

          {
    /* ── Notification Bell ──────────────────────────── */
  }
          <div className="relative" ref={notifsRef}>
            <button
    onClick={() => {
      closeAll("notifs");
      setShowNotifs((v) => !v);
    }}
    className="relative p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
  >
              <Bell size={18} />
              {unreadCount > 0 && <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-red-500 border border-slate-950 flex items-center justify-center text-white font-mono" style={{ fontSize: "0.55rem" }}>
                  {unreadCount}
                </span>}
            </button>

            {showNotifs && <div className="absolute right-0 top-full mt-2 w-80 rounded-2xl bg-slate-900 border border-slate-700/60 shadow-2xl overflow-hidden z-50">
                <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <Bell size={14} className="text-cyan-400" />
                    <span className="text-slate-200" style={{ fontSize: "0.85rem", fontWeight: 600 }}>Notifications</span>
                    {unreadCount > 0 && <span className="px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 font-mono" style={{ fontSize: "0.6rem" }}>{unreadCount} new</span>}
                  </div>
                  <div className="flex items-center gap-2">
                    {unreadCount > 0 && <button onClick={markAllRead} className="text-cyan-400 hover:text-cyan-300 transition-colors" style={{ fontSize: "0.7rem" }}>Mark all read</button>}
                    <button onClick={() => setShowNotifs(false)} className="text-slate-500 hover:text-slate-300"><X size={14} /></button>
                  </div>
                </div>
                <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
                  {notifications.map((n) => <button
    key={n.id}
    onClick={() => markRead(n.id)}
    className={`w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-slate-800/50 transition-colors ${!n.read ? "bg-slate-800/20" : ""}`}
  >
                      <div className={`mt-0.5 p-1.5 rounded-lg ${notifRing(n.type)}`}>{notifIcon(n.type)}</div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-slate-200 truncate" style={{ fontSize: "0.78rem", fontWeight: n.read ? 400 : 600 }}>{n.title}</p>
                          {!n.read && <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${notifDot(n.type)}`} />}
                        </div>
                        <p className="text-slate-500 truncate mt-0.5" style={{ fontSize: "0.7rem" }}>{n.body}</p>
                        <p className="text-slate-600 mt-0.5" style={{ fontSize: "0.65rem" }}>{n.time}</p>
                      </div>
                    </button>)}
                  {notifications.length === 0 && <div className="px-4 py-8 text-center">
                      <Bell size={24} className="text-slate-700 mx-auto mb-2" />
                      <p className="text-slate-600" style={{ fontSize: "0.78rem" }}>No notifications yet</p>
                    </div>}
                </div>
                <div className="px-4 py-2.5 border-t border-slate-800 bg-slate-900/50">
                  <button className="w-full flex items-center justify-center gap-1 text-slate-500 hover:text-cyan-400 transition-colors" style={{ fontSize: "0.72rem" }}>
                    View all alerts <ChevronRight size={11} />
                  </button>
                </div>
              </div>}
          </div>

          {
    /* ── Settings ───────────────────────────────────── */
  }
          <div className="relative" ref={settingsRef}>
            <button
    onClick={() => {
      closeAll("settings");
      setShowSettings((v) => !v);
    }}
    className={`p-2 rounded-lg transition-colors ${showSettings ? "text-cyan-400 bg-slate-800" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
  >
              <Settings size={18} style={{ transition: "transform 0.3s", transform: showSettings ? "rotate(45deg)" : "none" }} />
            </button>

            {showSettings && <div className="absolute right-0 top-full mt-2 w-96 rounded-2xl bg-slate-900 border border-slate-700/60 shadow-2xl overflow-hidden z-50">
                <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <Settings size={15} className="text-cyan-400" />
                    <span className="text-slate-200" style={{ fontSize: "0.9rem", fontWeight: 600 }}>Settings</span>
                  </div>
                  <button onClick={() => setShowSettings(false)} className="text-slate-500 hover:text-slate-300"><X size={15} /></button>
                </div>

                <div className="p-5 space-y-5 max-h-[480px] overflow-y-auto">
                  {
    /* Appearance */
  }
                  <section>
                    <div className="flex items-center gap-2 mb-3">
                      <Monitor size={13} className="text-slate-500" />
                      <p className="text-slate-400 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>Appearance</p>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      {[
    { id: "light",    label: "Light",    Icon: Sun    },
    { id: "dark",     label: "Dark",     Icon: Moon   },
    { id: "midnight", label: "Midnight", Icon: Shield },
  ].map(({ id, label, Icon }) => (
    <button
      key={id}
      onClick={() => setTheme(id)}
      className={`flex flex-col items-center gap-1 py-2.5 rounded-xl border transition-all ${
        theme === id
          ? "bg-cyan-500/15 border-cyan-500/40 text-cyan-400"
          : "bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600"
      }`}
      style={{ fontSize: "0.7rem" }}
    >
      <Icon size={13} />
      {label}
    </button>
  ))}
                    </div>
                  </section>

                  {
    /* Detection */
  }
                  <section>
                    <div className="flex items-center gap-2 mb-3">
                      <Sliders size={13} className="text-slate-500" />
                      <p className="text-slate-400 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>Detection Threshold</p>
                    </div>
                    <div className="flex justify-between mb-1">
                      <label className="text-slate-400" style={{ fontSize: "0.78rem" }}>Alert Risk Score</label>
                      <span className="text-cyan-400 font-mono" style={{ fontSize: "0.78rem" }}>{settings.alertThreshold}</span>
                    </div>
                    <input
    type="range"
    min={30}
    max={95}
    step={5}
    value={settings.alertThreshold}
    onChange={(e) => setSettings((s) => ({ ...s, alertThreshold: +e.target.value }))}
    className="w-full accent-cyan-500"
  />
                    <div className="flex justify-between mt-0.5">
                      <span className="text-slate-600" style={{ fontSize: "0.62rem" }}>30 (Sensitive)</span>
                      <span className="text-slate-600" style={{ fontSize: "0.62rem" }}>95 (Strict)</span>
                    </div>
                  </section>

                  {
    /* Integrations */
  }
                  <section>
                    <div className="flex items-center gap-2 mb-3">
                      <Database size={13} className="text-slate-500" />
                      <p className="text-slate-400 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>Threat Intel Feeds</p>
                    </div>
                    <div className="space-y-2">
                      {[
    { key: "vtEnabled", label: "VirusTotal API", icon: <Shield size={12} /> },
    { key: "urlhausEnabled", label: "URLHaus Feed", icon: <Globe size={12} /> },
    { key: "phishtankEnabled", label: "PhishTank DB", icon: <Database size={12} /> }
  ].map(({ key, label, icon }) => <div key={key} className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-800/50 border border-slate-700/40">
                          <div className="flex items-center gap-2 text-slate-400">{icon}<span style={{ fontSize: "0.78rem" }}>{label}</span></div>
                          <button
    onClick={() => setSettings((s) => ({ ...s, [key]: !s[key] }))}
    className={`w-9 h-5 rounded-full transition-colors relative ${settings[key] ? "bg-cyan-500" : "bg-slate-700"}`}
  >
                            <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${settings[key] ? "left-4.5" : "left-0.5"}`} />
                          </button>
                        </div>)}
                    </div>
                  </section>

                  {
    /* API */
  }
                  <section>
                    <div className="flex items-center gap-2 mb-3">
                      <Wifi size={13} className="text-slate-500" />
                      <p className="text-slate-400 uppercase tracking-wider" style={{ fontSize: "0.65rem" }}>API Configuration</p>
                    </div>
                    <input
    type="text"
    value={settings.apiUrl}
    onChange={(e) => setSettings((s) => ({ ...s, apiUrl: e.target.value }))}
    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 font-mono focus:outline-none focus:border-cyan-500/50"
    style={{ fontSize: "0.75rem" }}
  />
                  </section>
                </div>

                <div className="px-5 py-3 border-t border-slate-800 flex justify-end">
                  <button
    onClick={saveSettings}
    className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${settingsSaved ? "bg-green-500/20 text-green-400 border border-green-500/30" : "bg-cyan-500 hover:bg-cyan-400 text-slate-950"}`}
    style={{ fontSize: "0.8rem", fontWeight: 600 }}
  >
                    <Save size={13} />
                    {settingsSaved ? "Saved!" : "Save Settings"}
                  </button>
                </div>
              </div>}
          </div>

          {
    /* ── Profile / Login ───────────────────────────── */
  }
          <div className="relative" ref={profileRef}>
            {!isLoggedIn ? (
    /* Not logged in → show Login button */
    <button
      onClick={() => {
        closeAll();
        setShowLogin(true);
      }}
      className="flex items-center gap-2 pl-3 border-l border-slate-700"
    >
                <div className="w-8 h-8 rounded-full bg-slate-700 border border-slate-600 flex items-center justify-center">
                  <User size={15} className="text-slate-400" />
                </div>
                <div className="hidden sm:block text-left">
                  <p className="text-slate-400" style={{ fontSize: "0.8rem" }}>Not signed in</p>
                  <div className="flex items-center gap-1">
                    <LogIn size={9} className="text-slate-500" />
                    <p className="text-slate-500" style={{ fontSize: "0.65rem" }}>Click to sign in</p>
                  </div>
                </div>
              </button>
  ) : (
    /* Logged in → avatar + dropdown */
    <>
                <button
      onClick={() => {
        closeAll("profile");
        setShowProfile((v) => !v);
      }}
      className="flex items-center gap-2 pl-3 border-l border-slate-700"
    >
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center transition-all ${showProfile ? "bg-cyan-500/30 border-2 border-cyan-500/60" : "bg-cyan-500/20 border border-cyan-500/40 hover:border-cyan-500/60"}`}>
                    <User size={15} className="text-cyan-400" />
                  </div>
                  <div className="hidden sm:block text-left">
                    <p className="text-slate-300" style={{ fontSize: "0.8rem", fontWeight: 500 }}>{user?.name}</p>
                    <div className="flex items-center gap-1">
                      <Shield size={9} className="text-cyan-400" />
                      <p className="text-cyan-400" style={{ fontSize: "0.65rem" }}>{user?.role}</p>
                    </div>
                  </div>
                </button>

                {showProfile && <div className="absolute right-0 top-full mt-2 w-72 rounded-2xl bg-slate-900 border border-slate-700/60 shadow-2xl overflow-hidden z-50">
                    {
      /* Profile card */
    }
                    <div className="px-5 py-4 bg-gradient-to-br from-cyan-500/10 to-slate-900 border-b border-slate-800">
                      <div className="flex items-center gap-3">
                        <div className="w-12 h-12 rounded-full bg-cyan-500/20 border-2 border-cyan-500/50 flex items-center justify-center">
                          <User size={22} className="text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-slate-100" style={{ fontSize: "0.95rem", fontWeight: 600 }}>{user?.name}</p>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <BadgeCheck size={11} className="text-cyan-400" />
                            <span className="text-cyan-400" style={{ fontSize: "0.7rem" }}>{user?.role} · {user?.level}</span>
                          </div>
                        </div>
                      </div>

                      <div className="mt-3 grid grid-cols-3 gap-2">
                        {[
      { label: "Scans Today", value: user?.scansToday ?? 0 },
      { label: "Threats", value: user?.threatsFound ?? 0 },
      { label: "Accuracy", value: `${user?.accuracy ?? 0}%` }
    ].map(({ label, value }) => <div key={label} className="text-center px-2 py-1.5 rounded-lg bg-slate-800/50 border border-slate-700/40">
                            <p className="text-slate-200 font-mono" style={{ fontSize: "0.85rem", fontWeight: 700 }}>{value}</p>
                            <p className="text-slate-500" style={{ fontSize: "0.58rem" }}>{label}</p>
                          </div>)}
                      </div>
                    </div>

                    {
      /* Info */
    }
                    <div className="px-5 py-3 border-b border-slate-800 space-y-2">
                      {user?.email && <InfoRow icon={<Mail size={12} />} value={user.email} />}
                      {user?.phone && <InfoRow icon={<Phone size={12} />} value={user.phone} />}
                      {user?.timezone && <InfoRow icon={<Globe size={12} />} value={user.timezone} />}
                    </div>

                    {
      /* Actions */
    }
                    <div className="px-3 py-2 space-y-0.5">
                      <ProfileAction icon={<UserCircle size={14} />} label="Edit Profile" onClick={() => {
      setShowEditProfile(true);
      setShowProfile(false);
    }} />
                      <ProfileAction icon={<Key size={14} />} label="Change Password" onClick={() => {
    }} />
                      <ProfileAction icon={<Moon size={14} />} label="Preferences" onClick={() => {
      setShowProfile(false);
      setShowSettings(true);
    }} />
                    </div>

                    {
      /* Status + Logout */
    }
                    <div className="px-5 py-3 border-t border-slate-800 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full animate-pulse ${STATUS_DOT[user?.status ?? "on-duty"]}`} />
                        <span className="text-slate-400" style={{ fontSize: "0.7rem" }}>
                          {STATUS_LABEL[user?.status ?? "on-duty"]}
                        </span>
                      </div>
                      <button
      onClick={() => {
        logout();
        setShowProfile(false);
      }}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors"
      style={{ fontSize: "0.75rem" }}
    >
                        <LogOut size={13} /> Sign Out
                      </button>
                    </div>
                  </div>}
              </>
  )}
          </div>
        </div>
      </header>
    </>;
}
function InfoRow({ icon, value }) {
  return <div className="flex items-center gap-2.5 text-slate-400">
      <span className="text-slate-600">{icon}</span>
      <span style={{ fontSize: "0.75rem" }}>{value}</span>
    </div>;
}
function ProfileAction({ icon, label, onClick }) {
  return <button
    onClick={onClick}
    className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
    style={{ fontSize: "0.8rem" }}
  >
      {icon}{label}<ChevronRight size={12} className="ml-auto text-slate-600" />
    </button>;
}
export {
  Header
};
