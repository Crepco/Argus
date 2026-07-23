import { useState } from "react";

const SEV_COLOR = {
  CRITICAL: "text-red-400",
  HIGH: "text-red-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-yellow-300",
  CLEAN: "text-emerald-400",
};

export default function FindingCard({ result }) {
  const [open, setOpen] = useState(false);
  const findings = result.findings || [];

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40">
      <button
        className="w-full flex justify-between items-center px-4 py-3"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="font-mono text-sm">{result.module}</span>
        <span className={`text-xs ${SEV_COLOR[result.severity] || "text-slate-400"}`}>
          {result.severity} · {findings.length} finding(s) {open ? "▲" : "▼"}
        </span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3">
          {result.error && <p className="text-xs text-slate-500">error: {result.error}</p>}
          {findings.length === 0 && !result.error && (
            <p className="text-xs text-slate-500">Nothing exposed.</p>
          )}
          {findings.map((f, i) => (
            <div key={i} className="text-sm border-l-2 border-slate-700 pl-3">
              <div className="text-slate-200">{f.category || f.type}</div>
              {f.detail && <div className="text-xs text-slate-400 mt-0.5">{f.detail}</div>}
              {f.source && (
                <a
                  href={f.source}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-blue-400 break-all"
                >
                  {f.source}
                </a>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
