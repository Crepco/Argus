import { useState, useEffect } from "react";
import {
  requestDomainChallenge,
  confirmDomain,
  startGithubVerify,
  startAudit,
} from "../api.js";

const BACKEND = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

function Verified() {
  return <span className="text-emerald-400 text-sm">✓ verified</span>;
}

export default function InputForm({ onStarted }) {
  const [form, setForm] = useState({
    name: "",
    email: "",
    github_username: "",
    linkedin_url: "",
    domain: "",
    phone: "",
    usernames: "",
  });
  const [consent, setConsent] = useState(false);
  const [error, setError] = useState("");

  // ownership proofs keyed by type -> { value, token }
  const [tokens, setTokens] = useState({});
  const [domainChallenge, setDomainChallenge] = useState(null);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const proven = (type, value) =>
    tokens[type] && tokens[type].value === (value || "").toLowerCase().trim();

  // GitHub OAuth popup -> postMessage token back
  useEffect(() => {
    const handler = (evt) => {
      if (evt.data?.source === "osint-github-verify") {
        const d = evt.data.data;
        setTokens((t) => ({ ...t, github: { value: d.value, token: d.token } }));
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, []);

  const doGithub = async () => {
    setError("");
    try {
      const { authorize_url } = await startGithubVerify();
      window.open(authorize_url, "gh-verify", "width=600,height=700");
    } catch (e) {
      setError(e.response?.data?.detail || "GitHub OAuth is not configured.");
    }
  };

  const doDomainRequest = async () => {
    setError("");
    try {
      setDomainChallenge(await requestDomainChallenge(form.domain));
    } catch (e) {
      setError(e.response?.data?.detail || "Could not start domain challenge.");
    }
  };

  const doDomainConfirm = async () => {
    setError("");
    try {
      const res = await confirmDomain(form.domain);
      setTokens((t) => ({ ...t, domain: { value: res.value, token: res.token } }));
    } catch (e) {
      setError(e.response?.data?.detail || "TXT record not found yet.");
    }
  };

  // Which proofs are required for the identifiers the user actually entered.
  const githubOk = !form.github_username || proven("github", form.github_username);
  const domainOk = !form.domain || proven("domain", form.domain);

  const canSubmit = form.name && form.email && consent;

  const submit = async () => {
    setError("");
    const payload = {
      name: form.name,
      email: form.email,
      github_username: form.github_username || null,
      linkedin_url: form.linkedin_url || null,
      domain: form.domain || null,
      phone: form.phone || null,
      usernames: form.usernames
        ? form.usernames.split(",").map((s) => s.trim()).filter(Boolean)
        : [],
      consent,
      verification_tokens: Object.values(tokens).map((t) => t.token),
    };
    try {
      const { session_id } = await startAudit(payload);
      onStarted(session_id);
    } catch (e) {
      setError(e.response?.data?.detail || "Could not start audit.");
    }
  };

  const field = "w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm";
  const btn = "px-3 py-1.5 rounded text-sm bg-slate-700 hover:bg-slate-600 disabled:opacity-40";

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <label className="text-sm text-slate-300">Full name</label>
        <input className={field} value={form.name} onChange={set("name")} />
      </div>

      <div>
        <label className="text-sm text-slate-300">Email</label>
        <input className={field} value={form.email} onChange={set("email")} />
      </div>

      {/* GitHub OAuth */}
      <div>
        <label className="text-sm text-slate-300">
          GitHub username (optional) {form.github_username && githubOk && <Verified />}
        </label>
        <div className="flex gap-2">
          <input className={field} value={form.github_username} onChange={set("github_username")} disabled={githubOk && form.github_username} />
          {form.github_username && !githubOk && (
            <button className={btn} onClick={doGithub}>Verify via OAuth</button>
          )}
        </div>
      </div>

      {/* Domain TXT challenge */}
      <div>
        <label className="text-sm text-slate-300">
          Personal domain (optional) {form.domain && domainOk && <Verified />}
        </label>
        <div className="flex gap-2">
          <input className={field} value={form.domain} onChange={set("domain")} disabled={domainOk && form.domain} />
          {form.domain && !domainOk && (
            <button className={btn} onClick={doDomainRequest}>Get TXT record</button>
          )}
        </div>
        {domainChallenge && !domainOk && (
          <div className="mt-2 text-xs bg-slate-900 border border-slate-700 rounded p-3">
            <div className="text-slate-400">Add this TXT record, then confirm:</div>
            <code className="block mt-1 text-emerald-300 break-all">
              {domainChallenge.detail?.value}
            </code>
            <button className={`${btn} mt-2`} onClick={doDomainConfirm}>I've added it — confirm</button>
          </div>
        )}
      </div>

      <div>
        <label className="text-sm text-slate-300">Phone number (optional)</label>
        <input className={field} value={form.phone} onChange={set("phone")} placeholder="+1 555 123 4567" />
      </div>

      <div>
        <label className="text-sm text-slate-300">LinkedIn URL (optional)</label>
        <input className={field} value={form.linkedin_url} onChange={set("linkedin_url")} />
      </div>

      <div>
        <label className="text-sm text-slate-300">Known usernames (optional, comma-separated)</label>
        <input className={field} value={form.usernames} onChange={set("usernames")} />
      </div>

      <label className="flex gap-2 items-start text-sm text-slate-300">
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-1" />
        <span>I confirm I am auditing myself.</span>
      </label>

      {error && <p className="text-sm text-red-400">{error}</p>}

      <button
        className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 font-medium"
        disabled={!canSubmit}
        onClick={submit}
      >
        Start audit
      </button>
    </div>
  );
}
