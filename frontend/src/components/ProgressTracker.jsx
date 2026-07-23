import { useEffect, useState, useRef } from "react";
import { openAuditSocket } from "../api.js";

const MODULES = [
  "github_module",
  "email_hunter_module",
  "dns_module",
  "dork_module",
  "metadata_module",
  "wayback_module",
  "username_module",
  "social_content_module",
  "phone_module",
  "synthesis",
];

function cardStyle(state) {
  switch (state?.kind) {
    case "running":
      return "border-blue-500 bg-blue-950/40 animate-pulse";
    case "clean":
      return "border-emerald-600 bg-emerald-950/30";
    case "warn":
      return "border-yellow-500 bg-yellow-950/30";
    case "crit":
      return "border-red-600 bg-red-950/30";
    case "error":
      return "border-slate-600 bg-slate-900";
    default:
      return "border-slate-800 bg-slate-900/40";
  }
}

function label(state) {
  switch (state?.kind) {
    case "running": return "⏳ running";
    case "clean": return "✅ clean";
    case "warn": return `⚠️ ${state.count} finding(s)`;
    case "crit": return `🔴 ${state.count} finding(s)`;
    case "error": return "❌ unavailable";
    default: return "⬜ pending";
  }
}

function severityToKind(sev, count) {
  if (sev === "CRITICAL" || sev === "HIGH") return { kind: "crit", count };
  if (sev === "MEDIUM" || sev === "LOW") return count ? { kind: "warn", count } : { kind: "clean" };
  return { kind: "clean" };
}

export default function ProgressTracker({ sessionId, onComplete }) {
  const [states, setStates] = useState(
    Object.fromEntries(MODULES.map((m) => [m, { kind: "pending" }]))
  );
  const results = useRef({});

  useEffect(() => {
    // mark all base modules running
    setStates((s) => {
      const next = { ...s };
      MODULES.forEach((m) => (next[m] = { kind: "running" }));
      return next;
    });

    const ws = openAuditSocket(sessionId, (msg) => {
      if (msg.type === "module_result") {
        const d = msg.data;
        results.current[d.module] = d;
        const count = (d.findings || []).length;
        const kind =
          d.status === "error"
            ? { kind: "error" }
            : severityToKind(d.severity, count);
        setStates((s) => ({ ...s, [d.module]: kind }));
      } else if (msg.type === "synthesis_complete") {
        setStates((s) => ({ ...s, synthesis: { kind: "clean" } }));
        onComplete(msg.data, results.current);
        ws.close();
      }
    });
    return () => ws.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  return (
    <div>
      <h2 className="text-lg mb-4">Scanning…</h2>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {MODULES.map((m) => (
          <div key={m} className={`rounded-lg border p-4 ${cardStyle(states[m])}`}>
            <div className="text-sm font-mono text-slate-300">{m}</div>
            <div className="text-xs mt-2">{label(states[m])}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
