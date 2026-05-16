import { useState, useCallback } from "react";
import { Download, CheckCircle, Loader2, Chrome, AlertCircle, X } from "lucide-react";
import { zipSync, strToU8 } from "fflate";

// Files served from /public/extension/
const EXT_FILES = [
  { path: "/extension/manifest.json",  zipName: "manifest.json"      },
  { path: "/extension/background.js",  zipName: "background.js"      },
  { path: "/extension/popup.html",     zipName: "popup.html"         },
  { path: "/extension/popup.js",       zipName: "popup.js"           },
  { path: "/extension/styles.css",     zipName: "styles.css"         },
  { path: "/extension/icons/icon16.png",  zipName: "icons/icon16.png"  },
  { path: "/extension/icons/icon32.png",  zipName: "icons/icon32.png"  },
  { path: "/extension/icons/icon48.png",  zipName: "icons/icon48.png"  },
  { path: "/extension/icons/icon128.png", zipName: "icons/icon128.png" },
];

// ── Install Guide Modal ────────────────────────────────────────────────────
const STEPS = [
  {
    icon: "📦",
    title: "Download & Extract",
    body: <>Download the ZIP and extract it to a permanent folder <strong>(e.g. ~/phishguard-extension/)</strong>. Don't delete this folder — Chrome loads the extension from it.</>,
  },
  {
    icon: "🧩",
    title: 'Open Chrome Extensions',
    body: <>Navigate to <code className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-xs">chrome://extensions</code> in your browser address bar and press Enter.</>,
  },
  {
    icon: "🔧",
    title: "Enable Developer Mode",
    body: <>Toggle <strong>Developer mode</strong> ON using the switch in the <strong>top-right corner</strong> of the Extensions page.</>,
  },
  {
    icon: "📂",
    title: 'Click "Load unpacked"',
    body: <>Click the <strong>Load unpacked</strong> button that appears after enabling Developer mode, then select the extracted <code className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-xs">phishguard-extension/</code> folder.</>,
  },
  {
    icon: "📌",
    title: "Pin & Test",
    body: <>Click the puzzle-piece icon 🧩 in Chrome's toolbar → pin <strong>PhishGuard</strong>. Browse to any URL — the badge turns green ✓, amber ?, or red !! based on risk level.</>,
  },
];

export function InstallModal({ onClose }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(2,8,23,0.85)", backdropFilter: "blur(6px)" }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="relative w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden"
        style={{ maxHeight: "90vh", overflowY: "auto" }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-900/80 sticky top-0 backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/25">
              <Chrome size={16} className="text-cyan-400" />
            </div>
            <div>
              <p className="text-slate-100" style={{ fontSize: "0.9rem", fontWeight: 700 }}>
                Installation Guide
              </p>
              <p className="text-slate-500" style={{ fontSize: "0.7rem" }}>
                PhishGuard v1.0.0 · Manifest V3
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <X size={15} />
          </button>
        </div>

        <div className="p-5 space-y-3">
          {/* Note */}
          <div className="flex items-start gap-2.5 px-3.5 py-3 rounded-xl bg-amber-500/8 border border-amber-500/20">
            <span style={{ fontSize: "14px" }}>⚠️</span>
            <p className="text-amber-200/80" style={{ fontSize: "0.75rem", lineHeight: 1.55 }}>
              PhishGuard is a <strong>developer extension</strong> — not yet on the Chrome Web Store.
              You must load it manually using <strong>Developer Mode</strong>. It takes under 60 seconds.
            </p>
          </div>

          {/* Steps */}
          {STEPS.map((step, i) => (
            <div
              key={i}
              className="flex gap-3.5 bg-slate-800/40 border border-slate-700/40 rounded-xl p-4"
            >
              <div className="shrink-0 flex flex-col items-center gap-1.5">
                <div className="w-7 h-7 rounded-full bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
                  <span className="text-cyan-400 font-mono" style={{ fontSize: "0.72rem", fontWeight: 700 }}>
                    {i + 1}
                  </span>
                </div>
                {i < STEPS.length - 1 && (
                  <div className="w-px flex-1 bg-slate-700/60 min-h-4" />
                )}
              </div>
              <div className="pb-1">
                <div className="flex items-center gap-2 mb-1">
                  <span style={{ fontSize: "15px" }}>{step.icon}</span>
                  <p className="text-slate-200" style={{ fontSize: "0.82rem", fontWeight: 600 }}>
                    {step.title}
                  </p>
                </div>
                <p className="text-slate-400" style={{ fontSize: "0.77rem", lineHeight: 1.6 }}>
                  {step.body}
                </p>
              </div>
            </div>
          ))}

          {/* Requirements */}
          <div className="px-4 py-3 rounded-xl bg-slate-800/50 border border-slate-700/40">
            <p className="text-slate-500 mb-2" style={{ fontSize: "0.65rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.8px" }}>
              Requirements
            </p>
            <div className="grid grid-cols-2 gap-1.5">
              {[
                ["Chrome", "v88+  (Manifest V3)"],
                ["Brave", "Fully compatible"],
                ["Edge",  "Fully compatible"],
                ["Firefox", "Not supported"],
              ].map(([browser, note]) => (
                <div key={browser} className="flex items-center gap-2">
                  <div className={`w-1.5 h-1.5 rounded-full ${browser === "Firefox" ? "bg-slate-600" : "bg-green-400"}`} />
                  <span className="text-slate-400" style={{ fontSize: "0.73rem" }}>
                    <strong className="text-slate-300">{browser}</strong> — {note}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 pb-5">
          <button
            onClick={onClose}
            className="w-full py-2.5 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-600 transition-colors"
            style={{ fontSize: "0.82rem", fontWeight: 500 }}
          >
            Got it — close
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Download hook ──────────────────────────────────────────────────────────
function useExtensionDownload() {
  const [state, setState] = useState("idle"); // idle | loading | done | error
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");

  const download = useCallback(async () => {
    if (state === "loading") return;
    setState("loading");
    setProgress(0);
    setErrorMsg("");

    try {
      const files = {};
      for (let i = 0; i < EXT_FILES.length; i++) {
        const { path, zipName } = EXT_FILES[i];
        setProgress(Math.round(((i + 1) / EXT_FILES.length) * 80));

        const res = await fetch(path);
        if (!res.ok) throw new Error(`Could not fetch ${path} (HTTP ${res.status})`);
        const buf = await res.arrayBuffer();
        files[zipName] = new Uint8Array(buf);
      }

      setProgress(90);
      // Create a README inside the ZIP
      files["README.txt"] = strToU8(
        [
          "PhishGuard Chrome Extension v1.0.0",
          "====================================",
          "",
          "INSTALLATION",
          "1. Extract this ZIP to a permanent folder",
          "2. Open chrome://extensions in Chrome",
          "3. Enable Developer Mode (top-right toggle)",
          '4. Click "Load unpacked" -> select this folder',
          "5. Pin the PhishGuard extension to your toolbar",
          "",
          "COMPATIBLE BROWSERS",
          "- Google Chrome v88+",
          "- Microsoft Edge",
          "- Brave Browser",
          "",
          "Support: https://github.com/phishguard",
        ].join("\n")
      );

      const zipped = zipSync(files, { level: 6 });
      setProgress(100);

      // Trigger browser download
      const blob = new Blob([zipped], { type: "application/zip" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "phishguard-extension.zip";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      setState("done");
      setTimeout(() => setState("idle"), 3500);
    } catch (err) {
      setErrorMsg(err.message || "Download failed");
      setState("error");
      setTimeout(() => setState("idle"), 4000);
    }
  }, [state]);

  return { state, progress, errorMsg, download };
}

// ── Public component ───────────────────────────────────────────────────────
export function DownloadExtensionButton({ variant = "full", onShowGuide }) {
  const { state, progress, errorMsg, download } = useExtensionDownload();

  if (variant === "navbar") {
    return (
      <button
        onClick={download}
        disabled={state === "loading"}
        title="Download PhishGuard Extension"
        className={`hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all ${
          state === "done"
            ? "bg-green-500/15 border border-green-500/30 text-green-400"
            : state === "loading"
            ? "bg-cyan-500/10 border border-cyan-500/20 text-cyan-400/60 cursor-wait"
            : "bg-cyan-500/15 border border-cyan-500/30 hover:bg-cyan-500/25 text-cyan-400"
        }`}
        style={{ fontSize: "0.75rem", fontWeight: 600, textDecoration: "none" }}
      >
        {state === "done" ? (
          <><CheckCircle size={13} /> Downloaded!</>
        ) : state === "loading" ? (
          <><Loader2 size={13} className="animate-spin" /> {progress}%</>
        ) : (
          <><Download size={13} /> Get Extension</>
        )}
      </button>
    );
  }

  return (
    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
      {/* Primary download button */}
      <button
        onClick={download}
        disabled={state === "loading"}
        className={`group relative flex items-center justify-center gap-2.5 px-6 py-3 rounded-xl font-bold transition-all overflow-hidden ${
          state === "done"
            ? "bg-green-500 text-white shadow-[0_0_20px_rgba(34,197,94,0.35)]"
            : state === "error"
            ? "bg-red-500/20 border border-red-500/40 text-red-400"
            : state === "loading"
            ? "bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 cursor-wait"
            : "bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:shadow-[0_0_28px_rgba(6,182,212,0.5)]"
        }`}
        style={{ fontSize: "0.88rem", minWidth: 200 }}
      >
        {/* Progress bar under loading state */}
        {state === "loading" && (
          <div
            className="absolute left-0 bottom-0 h-0.5 bg-cyan-400 transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        )}
        {state === "done" && <CheckCircle size={16} />}
        {state === "loading" && <Loader2 size={16} className="animate-spin" />}
        {state === "error" && <AlertCircle size={16} />}
        {state === "idle" && <Download size={16} />}

        {state === "done"
          ? "Download Complete!"
          : state === "loading"
          ? `Packaging… ${progress}%`
          : state === "error"
          ? "Download Failed — Retry"
          : "Download Extension"}

        {state === "idle" && (
          <span
            className="ml-1 px-1.5 py-0.5 rounded bg-slate-950/20 text-slate-900"
            style={{ fontSize: "0.65rem" }}
          >
            ZIP
          </span>
        )}
      </button>

      {/* Install guide button */}
      <button
        onClick={onShowGuide}
        className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-600 transition-all"
        style={{ fontSize: "0.82rem", fontWeight: 500 }}
      >
        <Chrome size={14} />
        How to Install
      </button>

      {/* Error hint */}
      {state === "error" && errorMsg && (
        <p className="text-red-400 text-xs mt-1 col-span-2">{errorMsg}</p>
      )}
    </div>
  );
}
