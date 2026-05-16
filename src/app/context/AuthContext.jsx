import {
  createContext,
  useContext,
  useState,
  useCallback
} from "react";
const AUTH_KEY = "phishguard_auth";
function loadAuth() {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function saveAuth(user) {
  localStorage.setItem(AUTH_KEY, JSON.stringify({ user }));
}
function clearAuth() {
  localStorage.removeItem(AUTH_KEY);
}
function buildProfile(email) {
  const name = email.split("@")[0].replace(/[._-]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  return {
    id: `usr_${Date.now()}`,
    name,
    email,
    phone: "",
    role: "SOC Analyst",
    level: "L2",
    timezone: "UTC",
    department: "Threat Intelligence",
    status: "on-duty",
    scansToday: 0,
    threatsFound: 0,
    accuracy: 97.4
  };
}
const DEMO_USER = {
  id: "usr_demo",
  name: "Alex Morgan",
  email: "alex.morgan@phishguard.io",
  phone: "+1 (555) 012-3456",
  role: "Senior SOC Analyst",
  level: "L3",
  timezone: "US-East \xB7 UTC-5",
  department: "Threat Intelligence",
  status: "on-duty",
  scansToday: 47,
  threatsFound: 12,
  accuracy: 98.2
};
const AuthContext = createContext(null);
function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const stored = loadAuth();
    return stored?.user ?? null;
  });
  const login = useCallback((email, password) => {
    if (!email.includes("@") || !email.includes(".")) {
      return { success: false, error: "Enter a valid email address" };
    }
    if (password.length < 6) {
      return { success: false, error: "Password must be at least 6 characters" };
    }
    const profile = email === "alex.morgan@phishguard.io" || email === "admin@phishguard.io" ? DEMO_USER : buildProfile(email);
    saveAuth(profile);
    setUser(profile);
    return { success: true };
  }, []);
  const logout = useCallback(() => {
    clearAuth();
    setUser(null);
  }, []);
  const updateProfile = useCallback((patch) => {
    setUser((prev) => {
      if (!prev) return prev;
      const updated = { ...prev, ...patch };
      saveAuth(updated);
      return updated;
    });
  }, []);
  return <AuthContext.Provider value={{ isLoggedIn: !!user, user, login, logout, updateProfile }}>
      {children}
    </AuthContext.Provider>;
}
function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
export {
  AuthProvider,
  useAuth
};
