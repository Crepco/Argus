import axios from "axios";

const BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

export const api = axios.create({ baseURL: BASE });

// ---- ownership verification ----
export const requestDomainChallenge = (domain) =>
  api.post("/api/verify/domain/request", { domain }).then((r) => r.data);

export const confirmDomain = (domain) =>
  api.post("/api/verify/domain/confirm", { domain }).then((r) => r.data);

export const startGithubVerify = () =>
  api.get("/api/verify/github/start").then((r) => r.data);

// ---- audit ----
export const startAudit = (payload) =>
  api.post("/api/audit/start", payload).then((r) => r.data);

export const openAuditSocket = (sessionId, onMessage) => {
  const wsBase = BASE.replace(/^http/, "ws");
  const ws = new WebSocket(`${wsBase}/ws/audit/${sessionId}`);
  ws.onmessage = (evt) => onMessage(JSON.parse(evt.data));
  return ws;
};

export const getReport = (sessionId) =>
  api.get(`/api/audit/report/${sessionId}`).then((r) => r.data);

export const deleteReport = (sessionId) =>
  api.delete(`/api/audit/report/${sessionId}`).then((r) => r.data);
