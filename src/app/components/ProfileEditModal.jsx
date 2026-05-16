import { useState } from "react";
import {
  X,
  User,
  Save,
  Mail,
  Phone,
  Globe,
  Shield,
  BadgeCheck,
  CheckCircle,
  Loader2
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
const ROLES = [
  "SOC Analyst",
  "Senior SOC Analyst",
  "Lead SOC Analyst",
  "Threat Researcher",
  "Incident Responder",
  "Security Engineer",
  "CISO"
];
const LEVELS = ["L1", "L2", "L3", "L4", "Manager"];
const TIMEZONES = [
  "UTC",
  "UTC+1",
  "UTC+2",
  "UTC+5:30",
  "UTC+8",
  "UTC+9",
  "US-East \xB7 UTC-5",
  "US-West \xB7 UTC-8"
];
const STATUSES = [
  { value: "on-duty", label: "On Duty", color: "bg-green-400" },
  { value: "off-duty", label: "Off Duty", color: "bg-slate-500" },
  { value: "break", label: "On Break", color: "bg-yellow-400" }
];
function ProfileEditModal({ onClose }) {
  const { user, updateProfile } = useAuth();
  const [form, setForm] = useState({
    name: user?.name ?? "",
    email: user?.email ?? "",
    phone: user?.phone ?? "",
    role: user?.role ?? "SOC Analyst",
    level: user?.level ?? "L2",
    timezone: user?.timezone ?? "UTC",
    department: user?.department ?? "Threat Intelligence",
    status: user?.status ?? "on-duty"
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const set = (key, val) => setForm((f) => ({ ...f, [key]: val }));
  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    await new Promise((r) => setTimeout(r, 600));
    updateProfile(form);
    setSaving(false);
    setSaved(true);
    setTimeout(onClose, 900);
  };
  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl overflow-hidden">
        <div className="h-1 w-full bg-gradient-to-r from-cyan-500 to-blue-600" />

        {
    /* Header */
  }
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <User size={16} className="text-cyan-400" />
            <span className="text-slate-200" style={{ fontSize: "0.95rem", fontWeight: 600 }}>Edit Profile</span>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors">
            <X size={15} />
          </button>
        </div>

        {
    /* Avatar preview */
  }
        <div className="flex items-center gap-4 px-6 pt-5 pb-4 border-b border-slate-800/60">
          <div className="w-16 h-16 rounded-full bg-cyan-500/20 border-2 border-cyan-500/50 flex items-center justify-center shrink-0">
            <User size={28} className="text-cyan-400" />
          </div>
          <div>
            <p className="text-slate-200" style={{ fontWeight: 600, fontSize: "1rem" }}>{form.name || "Your Name"}</p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <BadgeCheck size={12} className="text-cyan-400" />
              <span className="text-cyan-400" style={{ fontSize: "0.72rem" }}>{form.role} · {form.level}</span>
            </div>
            {
    /* Status selector inline */
  }
            <div className="flex gap-2 mt-2">
              {STATUSES.map((s) => <button
    key={s.value}
    type="button"
    onClick={() => set("status", s.value)}
    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs transition-all border ${form.status === s.value ? "bg-slate-700 border-slate-500 text-slate-200" : "border-transparent text-slate-500 hover:text-slate-300"}`}
  >
                  <div className={`w-1.5 h-1.5 rounded-full ${s.color}`} />
                  {s.label}
                </button>)}
            </div>
          </div>
        </div>

        {
    /* Form */
  }
        <form onSubmit={handleSave} className="px-6 py-5 space-y-4 max-h-[55vh] overflow-y-auto">
          {
    /* Name */
  }
          <Field label="Full Name" icon={<User size={13} />}>
            <input
    type="text"
    value={form.name}
    onChange={(e) => set("name", e.target.value)}
    required
    placeholder="Alex Morgan"
    className={inputCls}
    style={{ fontSize: "0.85rem" }}
  />
          </Field>

          {
    /* Email */
  }
          <Field label="Email" icon={<Mail size={13} />}>
            <input
    type="email"
    value={form.email}
    onChange={(e) => set("email", e.target.value)}
    required
    placeholder="analyst@phishguard.io"
    className={inputCls}
    style={{ fontSize: "0.85rem" }}
  />
          </Field>

          {
    /* Phone */
  }
          <Field label="Phone" icon={<Phone size={13} />}>
            <input
    type="tel"
    value={form.phone}
    onChange={(e) => set("phone", e.target.value)}
    placeholder="+1 (555) 000-0000"
    className={inputCls}
    style={{ fontSize: "0.85rem" }}
  />
          </Field>

          {
    /* Role + Level row */
  }
          <div className="grid grid-cols-2 gap-3">
            <Field label="Role" icon={<Shield size={13} />}>
              <select value={form.role} onChange={(e) => set("role", e.target.value)} className={selectCls} style={{ fontSize: "0.85rem" }}>
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </Field>
            <Field label="Level" icon={<BadgeCheck size={13} />}>
              <select value={form.level} onChange={(e) => set("level", e.target.value)} className={selectCls} style={{ fontSize: "0.85rem" }}>
                {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
              </select>
            </Field>
          </div>

          {
    /* Department */
  }
          <Field label="Department" icon={<Shield size={13} />}>
            <input
    type="text"
    value={form.department}
    onChange={(e) => set("department", e.target.value)}
    placeholder="Threat Intelligence"
    className={inputCls}
    style={{ fontSize: "0.85rem" }}
  />
          </Field>

          {
    /* Timezone */
  }
          <Field label="Timezone" icon={<Globe size={13} />}>
            <select value={form.timezone} onChange={(e) => set("timezone", e.target.value)} className={selectCls} style={{ fontSize: "0.85rem" }}>
              {TIMEZONES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </Field>
        </form>

        {
    /* Footer */
  }
        <div className="px-6 py-4 border-t border-slate-800 flex items-center justify-end gap-3">
          <button
    type="button"
    onClick={onClose}
    className="px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
    style={{ fontSize: "0.8rem" }}
  >
            Cancel
          </button>
          <button
    onClick={handleSave}
    disabled={saving || saved}
    className={`flex items-center gap-2 px-5 py-2 rounded-lg transition-all ${saved ? "bg-green-500/20 border border-green-500/30 text-green-400" : "bg-cyan-500 hover:bg-cyan-400 text-slate-950 disabled:opacity-60"}`}
    style={{ fontSize: "0.85rem", fontWeight: 600 }}
  >
            {saved ? <><CheckCircle size={14} /> Saved!</> : saving ? <><Loader2 size={14} className="animate-spin" /> Saving...</> : <><Save size={14} /> Save Changes</>}
          </button>
        </div>
      </div>
    </div>;
}
const inputCls = "w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all";
const selectCls = "w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500/50 transition-all";
function Field({ label, icon, children }) {
  return <div>
      <label className="flex items-center gap-1.5 text-slate-500 mb-1.5" style={{ fontSize: "0.75rem" }}>
        <span className="text-slate-600">{icon}</span>
        {label}
      </label>
      {children}
    </div>;
}
export {
  ProfileEditModal
};
