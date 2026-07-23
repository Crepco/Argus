import FindingCard from "./FindingCard.jsx";
import RemediationPlan from "./RemediationPlan.jsx";
import { deleteReport } from "../api.js";

const SEV_BANNER = {
  CRITICAL: "bg-red-900/60 border-red-600",
  HIGH: "bg-red-900/40 border-red-600",
  MEDIUM: "bg-yellow-900/40 border-yellow-500",
  LOW: "bg-emerald-900/30 border-emerald-600",
  MINIMAL: "bg-emerald-900/30 border-emerald-600",
};

function downloadHtml(report, moduleResults) {
  const date = new Date().toISOString().slice(0, 10);
  const html = `<!doctype html><meta charset=utf-8>
<title>OSINT self-audit report ${date}</title>
<body style="font-family:system-ui;max-width:800px;margin:2rem auto;padding:0 1rem">
<h1>OSINT Self-Audit Report</h1>
<p><b>Overall severity:</b> ${report.overall_severity || "-"}</p>
<p>${report.executive_summary || ""}</p>
<h2>What an attacker could do</h2><p>${report.attacker_simulation || ""}</p>
<h2>Findings</h2>
<pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(moduleResults, null, 2))}</pre>
<h2>Remediation</h2>
<pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(report.remediation_plan, null, 2))}</pre>
</body>`;
  const blob = new Blob([html], { type: "text/html" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `osint-report-${date}.html`;
  a.click();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

export default function ReportView({ report, moduleResults, sessionId }) {
  if (!report) return null;
  const score = report.digital_footprint_score?.score ?? "—";

  return (
    <div className="space-y-6">
      <div className={`rounded-lg border p-4 ${SEV_BANNER[report.overall_severity] || "border-slate-700"}`}>
        <div className="text-sm text-slate-300">Overall severity</div>
        <div className="text-2xl font-bold">{report.overall_severity || "—"}</div>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
          <div className="text-sm text-slate-400">Digital footprint score</div>
          <div className="text-4xl font-bold mt-1">{score}<span className="text-lg text-slate-500">/100</span></div>
          <p className="text-xs text-slate-400 mt-2">{report.digital_footprint_score?.explanation}</p>
        </div>
        <div className="md:col-span-2 rounded-lg border border-slate-800 bg-slate-900/40 p-4">
          <div className="text-sm text-slate-400">Executive summary</div>
          <p className="text-sm mt-1">{report.executive_summary}</p>
        </div>
      </div>

      {report.attacker_simulation && (
        <div className="rounded-lg border border-red-700 bg-red-950/30 p-4">
          <div className="text-sm font-semibold text-red-300">What an attacker could do in 15 minutes</div>
          <p className="text-sm mt-1 text-slate-200">{report.attacker_simulation}</p>
        </div>
      )}

      {report.platforms_exposed?.length > 0 && (
        <div>
          <h3 className="text-sm text-slate-400 mb-2">Platforms confirmed</h3>
          <div className="flex flex-wrap gap-2">
            {report.platforms_exposed.map((p) => (
              <span key={p} className="text-xs bg-slate-800 rounded px-2 py-1">{p}</span>
            ))}
          </div>
        </div>
      )}

      {report.data_categories_exposed?.length > 0 && (
        <div>
          <h3 className="text-sm text-slate-400 mb-2">Data categories exposed</h3>
          <div className="flex flex-wrap gap-2">
            {report.data_categories_exposed.map((c) => (
              <span key={c} className="text-xs bg-yellow-900/40 border border-yellow-700 rounded px-2 py-1">{c}</span>
            ))}
          </div>
        </div>
      )}

      {report.cross_linked_findings?.length > 0 && (
        <div>
          <h3 className="text-sm text-slate-400 mb-2">Cross-linked findings</h3>
          <div className="space-y-2">
            {report.cross_linked_findings.map((f, i) => (
              <div key={i} className="rounded border border-slate-800 bg-slate-900/40 p-3 text-sm">
                <div>{f.description}</div>
                <div className="flex flex-wrap gap-2 mt-1">
                  {(f.sources || []).map((s) => (
                    <a key={s} href={s} target="_blank" rel="noreferrer" className="text-xs text-blue-400 break-all">{s}</a>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="text-sm text-slate-400 mb-2">Per-module detail</h3>
        <div className="space-y-2">
          {Object.values(moduleResults || {}).map((r) => (
            <FindingCard key={r.module} result={r} />
          ))}
        </div>
      </div>

      <div>
        <h3 className="text-sm text-slate-400 mb-2">Remediation plan</h3>
        <RemediationPlan plan={report.remediation_plan} />
      </div>

      <div className="flex gap-3 pt-4 border-t border-slate-800">
        <button
          className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-sm"
          onClick={() => downloadHtml(report, moduleResults)}
        >
          Download report (HTML)
        </button>
        <button
          className="px-4 py-2 rounded bg-slate-700 hover:bg-slate-600 text-sm"
          onClick={() => deleteReport(sessionId).then(() => location.reload())}
        >
          Purge my data now
        </button>
      </div>
    </div>
  );
}
