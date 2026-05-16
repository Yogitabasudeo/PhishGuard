const KEY = "phishguard_scan_history";
const MAX = 200;
function getSavedScans() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}
function saveScan(result) {
  try {
    const prev = getSavedScans();
    const deduped = [result, ...prev.filter((r) => r.id !== result.id)].slice(0, MAX);
    localStorage.setItem(KEY, JSON.stringify(deduped));
  } catch {
  }
}
function clearSavedScans() {
  try {
    localStorage.removeItem(KEY);
  } catch {
  }
}
export {
  clearSavedScans,
  getSavedScans,
  saveScan
};
