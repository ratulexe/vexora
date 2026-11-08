"use client";

import { CircleCheck, Circle, LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";

// The server does not stream progress, so the percentage is estimated from typical
// check times: it rises quickly, slows down near 95%, and only reaches 100% when
// the result has actually arrived. The stages are the real checks Vexora runs.
const STAGES = {
  url: [
    { at: 0, label: "Reading and normalising the link" },
    { at: 8, label: "Checking threat intelligence feeds" },
    { at: 24, label: "Following redirects safely" },
    { at: 42, label: "Inspecting the TLS certificate" },
    { at: 60, label: "Assessing website security" },
    { at: 75, label: "Comparing with earlier reports" },
    { at: 86, label: "Writing the AI explanation" },
  ],
  message: [
    { at: 0, label: "Extracting links, numbers and payment details" },
    { at: 12, label: "Checking scam-pattern rules" },
    { at: 30, label: "Investigating links in the message" },
    { at: 62, label: "Comparing with earlier reports" },
    { at: 78, label: "Writing the AI explanation" },
  ],
};

// Time constant for the estimate: about 85% is reached after 2 × this many seconds.
const TYPICAL_SECONDS = { url: 4, message: 3 };

export default function AnalysisProgress({ mode, finished }: { mode: "url" | "message"; finished: boolean }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (finished) return;
    const started = performance.now();
    const timer = setInterval(() => setElapsed((performance.now() - started) / 1000), 150);
    return () => clearInterval(timer);
  }, [finished]);

  const estimate = 95 * (1 - Math.exp(-elapsed / TYPICAL_SECONDS[mode]));
  const percent = finished ? 100 : Math.floor(estimate);
  const stages = STAGES[mode];
  const activeIndex = finished ? stages.length : stages.findLastIndex((stage) => percent >= stage.at);

  return (
    <div className="card progress-card" role="status" aria-live="polite">
      <div className="progress-head">
        <span>{finished ? "Done. Preparing your report" : "Investigating"}</span>
        <span className="progress-percent">{percent}%</span>
      </div>
      <div
        className="progress-track"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
        aria-label="Investigation progress"
      >
        <div className="progress-fill" style={{ width: `${percent}%` }} />
      </div>
      <ul className="stage-list">
        {stages.map((stage, index) => {
          const state = index < activeIndex ? "done" : index === activeIndex ? "active" : "pending";
          return (
            <li key={stage.label} data-state={state}>
              {state === "done" ? (
                <CircleCheck size={16} aria-hidden />
              ) : state === "active" ? (
                <LoaderCircle size={16} className="spin" aria-hidden />
              ) : (
                <Circle size={16} aria-hidden />
              )}
              {stage.label}
            </li>
          );
        })}
      </ul>
      {!finished && elapsed > 15 && (
        <p className="note" style={{ marginTop: 14 }}>
          Still working. If the server has been idle, it can take up to a minute to wake up.
        </p>
      )}
      <p className="note" style={{ marginTop: 10 }}>
        Progress is estimated from typical check times.
      </p>
    </div>
  );
}
