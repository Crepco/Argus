import { useState } from "react";

const COLUMNS = [
  { key: "critical", title: "Critical", color: "border-red-600" },
  { key: "medium", title: "Medium", color: "border-yellow-500" },
  { key: "low", title: "Low", color: "border-emerald-600" },
];

export default function RemediationPlan({ plan }) {
  const [done, setDone] = useState({}); // local only, not persisted

  if (!plan) return null;

  return (
    <div className="grid md:grid-cols-3 gap-4">
      {COLUMNS.map((col) => (
        <div key={col.key}>
          <h4 className="text-sm font-semibold mb-2">{col.title}</h4>
          <div className="space-y-2">
            {(plan[col.key] || []).map((item, i) => {
              const id = `${col.key}-${i}`;
              return (
                <div key={id} className={`rounded border-l-4 ${col.color} bg-slate-900/50 p-3`}>
                  <label className="flex gap-2 items-start text-sm">
                    <input
                      type="checkbox"
                      checked={!!done[id]}
                      onChange={() => setDone((d) => ({ ...d, [id]: !d[id] }))}
                      className="mt-1"
                    />
                    <span className={done[id] ? "line-through text-slate-500" : ""}>
                      <span className="text-slate-100">{item.action}</span>
                      <span className="block text-xs text-slate-400 mt-1">{item.reason}</span>
                      {item.source && (
                        <a href={item.source} target="_blank" rel="noreferrer" className="text-xs text-blue-400 break-all">
                          {item.source}
                        </a>
                      )}
                    </span>
                  </label>
                </div>
              );
            })}
            {(plan[col.key] || []).length === 0 && (
              <p className="text-xs text-slate-600">None.</p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
