import {
  createContext,
  useContext,
  useState,
  useCallback
} from "react";
const NotificationContext = createContext(null);
const SEED_NOTIFICATIONS = [
  {
    id: "seed_1",
    type: "danger",
    title: "High-risk phishing URL detected",
    body: "paypal-security-center.com \u2014 Risk Score 94",
    time: "2 min ago",
    read: false
  },
  {
    id: "seed_2",
    type: "warning",
    title: "Suspicious domain flagged",
    body: "amazon-order-confirm.xyz \u2014 DGA pattern detected",
    time: "18 min ago",
    read: false
  },
  {
    id: "seed_3",
    type: "danger",
    title: "URLHaus threat feed match",
    body: "bankofamerica-secure-login.net \u2014 listed on URLHaus",
    time: "1 hr ago",
    read: false
  },
  {
    id: "seed_4",
    type: "info",
    title: "VirusTotal quota at 80%",
    body: "720 / 900 daily API calls consumed",
    time: "3 hrs ago",
    read: true
  },
  {
    id: "seed_5",
    type: "success",
    title: "IOC Report ready",
    body: "Weekly threat intelligence report has been generated",
    time: "5 hrs ago",
    read: true
  }
];
function timeAgo() {
  return "just now";
}
function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState(SEED_NOTIFICATIONS);
  const push = useCallback((n) => {
    const newNotif = {
      ...n,
      id: `notif_${Date.now()}`,
      time: timeAgo(),
      read: false
    };
    setNotifications((prev) => [newNotif, ...prev].slice(0, 30));
  }, []);
  const markRead = useCallback((id) => {
    setNotifications((prev) => prev.map((n) => n.id === id ? { ...n, read: true } : n));
  }, []);
  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);
  const dismiss = useCallback((id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  }, []);
  const unreadCount = notifications.filter((n) => !n.read).length;
  return <NotificationContext.Provider value={{ notifications, unreadCount, push, markRead, markAllRead, dismiss }}>
      {children}
    </NotificationContext.Provider>;
}
function useNotifications() {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error("useNotifications must be used within NotificationProvider");
  return ctx;
}
export {
  NotificationProvider,
  useNotifications
};
