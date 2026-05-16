import { useState } from "react";
import { Shield, X, Eye, EyeOff, LogIn, AlertCircle, Loader2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";
function LoginModal({ onClose }) {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    await new Promise((r) => setTimeout(r, 700));
    const result = login(email.trim(), password);
    setLoading(false);
    if (result.success) {
      onClose();
    } else {
      setError(result.error || "Login failed");
    }
  };
  const fillDemo = () => {
    setEmail("alex.morgan@phishguard.io");
    setPassword("phishguard123");
    setError("");
  };
  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {
    /* Backdrop */
  }
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

      {
    /* Modal */
  }
      <div className="relative w-full max-w-md bg-slate-900 border border-slate-700/60 rounded-2xl shadow-2xl overflow-hidden">
        {
    /* Top accent */
  }
        <div className="h-1 w-full bg-gradient-to-r from-cyan-500 to-blue-600" />

        {
    /* Header */
  }
        <div className="flex items-center justify-between px-6 py-5 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/30">
              <Shield size={20} className="text-cyan-400" />
            </div>
            <div>
              <h2 className="text-slate-100" style={{ fontSize: "1.05rem", fontWeight: 700 }}>
                PhishGuard SOC
              </h2>
              <p className="text-slate-500" style={{ fontSize: "0.72rem" }}>
                Sign in to your analyst account
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors">
            <X size={16} />
          </button>
        </div>

        {
    /* Body */
  }
        <div className="px-6 py-6">
          {
    /* Demo hint */
  }
          <button
    onClick={fillDemo}
    type="button"
    className="w-full mb-5 px-4 py-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-left"
    style={{ fontSize: "0.78rem" }}
  >
            <span className="font-semibold">Demo Account:</span>{" "}
            alex.morgan@phishguard.io / phishguard123{" "}
            <span className="underline ml-1">→ Click to fill</span>
          </button>

          <form onSubmit={handleSubmit} className="space-y-4">
            {
    /* Email */
  }
            <div>
              <label className="block text-slate-400 mb-1.5" style={{ fontSize: "0.8rem" }}>
                Email Address
              </label>
              <input
    type="email"
    value={email}
    onChange={(e) => setEmail(e.target.value)}
    placeholder="analyst@phishguard.io"
    required
    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all"
    style={{ fontSize: "0.875rem" }}
  />
            </div>

            {
    /* Password */
  }
            <div>
              <label className="block text-slate-400 mb-1.5" style={{ fontSize: "0.8rem" }}>
                Password
              </label>
              <div className="relative">
                <input
    type={showPwd ? "text" : "password"}
    value={password}
    onChange={(e) => setPassword(e.target.value)}
    placeholder="Min 6 characters"
    required
    className="w-full pl-3.5 pr-10 py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all"
    style={{ fontSize: "0.875rem" }}
  />
                <button
    type="button"
    onClick={() => setShowPwd((v) => !v)}
    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
  >
                  {showPwd ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {
    /* Error */
  }
            {error && <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400" style={{ fontSize: "0.8rem" }}>
                <AlertCircle size={13} />
                {error}
              </div>}

            {
    /* Submit */
  }
            <button
    type="submit"
    disabled={loading}
    className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 transition-all"
    style={{ fontSize: "0.9rem", fontWeight: 700 }}
  >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <LogIn size={16} />}
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>

          <p className="text-center text-slate-600 mt-5" style={{ fontSize: "0.72rem" }}>
            Any valid email + password ≥ 6 chars works in demo mode
          </p>
        </div>
      </div>
    </div>;
}
export {
  LoginModal
};
