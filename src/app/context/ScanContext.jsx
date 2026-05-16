import {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo
} from "react";
import { getSavedScans, saveScan as persistScan, clearSavedScans } from "../utils/scanStore";
import { MOCK_SCAN_HISTORY } from "../data/mockData";
import { useNotifications } from "./NotificationContext";
const ScanContext = createContext(null);
const MOCK_IDS = new Set(MOCK_SCAN_HISTORY.map((r) => r.id));
function ScanProvider({ children }) {
  const [userScans, setUserScans] = useState(() => getSavedScans());
  const { push } = useNotifications();
  const addScan = useCallback((scan) => {
    persistScan(scan);
    setUserScans((prev) => [scan, ...prev.filter((s) => s.id !== scan.id)]);
    if (scan.prediction === "phishing") {
      push({
        type: "danger",
        title: `Phishing URL detected!`,
        body: `${scan.domain} \u2014 Risk Score ${scan.risk_score}/100`,
        scanId: scan.id,
        url: scan.url
      });
    } else if (scan.prediction === "suspicious") {
      push({
        type: "warning",
        title: `Suspicious URL flagged`,
        body: `${scan.domain} \u2014 ${scan.threat_indicators[0] ?? "Multiple signals detected"}`,
        scanId: scan.id,
        url: scan.url
      });
    } else {
      push({
        type: "success",
        title: `Clean URL confirmed`,
        body: `${scan.domain} \u2014 Risk Score ${scan.risk_score}/100`,
        scanId: scan.id,
        url: scan.url
      });
    }
  }, [push]);
  const clearUserScans = useCallback(() => {
    clearSavedScans();
    setUserScans([]);
  }, []);
  const allScans = useMemo(() => {
    const fresh = userScans.filter((r) => !MOCK_IDS.has(r.id));
    return [...fresh, ...MOCK_SCAN_HISTORY];
  }, [userScans]);
  return <ScanContext.Provider value={{ userScans, allScans, addScan, clearUserScans }}>
      {children}
    </ScanContext.Provider>;
}
function useScanContext() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScanContext must be used within ScanProvider");
  return ctx;
}
export {
  ScanProvider,
  useScanContext
};
