import { useState } from "react";
import InputForm from "./components/InputForm.jsx";
import ProgressTracker from "./components/ProgressTracker.jsx";
import ReportView from "./components/ReportView.jsx";

export default function App() {
  const [stage, setStage] = useState("form"); // form | progress | report
  const [sessionId, setSessionId] = useState(null);
  const [report, setReport] = useState(null);
  const [moduleResults, setModuleResults] = useState({});

  const onStarted = (id) => {
    setSessionId(id);
    setStage("progress");
  };

  const onComplete = (rep, mods) => {
    setReport(rep);
    setModuleResults(mods);
    setStage("report");
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-4">
        <h1 className="text-xl font-semibold">
          Argus <span className="text-slate-400 font-normal">— Personal OSINT Exposure Auditor</span>
        </h1>
        <p className="text-xs text-slate-500 mt-1">
          Self-audit only. You must prove ownership of each identifier before it is scanned.
        </p>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        {stage === "form" && <InputForm onStarted={onStarted} />}
        {stage === "progress" && (
          <ProgressTracker sessionId={sessionId} onComplete={onComplete} />
        )}
        {stage === "report" && (
          <ReportView report={report} moduleResults={moduleResults} sessionId={sessionId} />
        )}
      </main>
    </div>
  );
}
