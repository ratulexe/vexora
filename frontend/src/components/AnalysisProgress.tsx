"use client";

import {
  Bot,
  Check,
  Circle,
  CircleCheck,
  Link2,
  ListChecks,
  LoaderCircle,
  Lock,
  Network,
  QrCode,
  Radar,
  Route,
  ScanText,
  Search,
  ShieldHalf,
  type LucideIcon,
} from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useEffect, useState } from "react";

// The server does not stream progress, so the percentage is estimated from typical
// check times: it rises quickly, slows down near 95%, and only reaches 100% when
// the result has actually arrived. The stages are the real checks Vexora runs.
const STAGES: Record<"url" | "message" | "qr", { at: number; label: string; icon: LucideIcon }[]> = {
  url: [
    { at: 0, label: "Reading and normalising the link", icon: Link2 },
    { at: 8, label: "Checking threat intelligence feeds", icon: Radar },
    { at: 24, label: "Following redirects safely", icon: Route },
    { at: 42, label: "Inspecting the TLS certificate", icon: Lock },
    { at: 60, label: "Assessing website security", icon: ShieldHalf },
    { at: 75, label: "Comparing with earlier reports", icon: Network },
    { at: 86, label: "Writing the AI explanation", icon: Bot },
  ],
  message: [
    { at: 0, label: "Extracting links, numbers and payment details", icon: ScanText },
    { at: 12, label: "Checking scam-pattern rules", icon: ListChecks },
    { at: 30, label: "Investigating links in the message", icon: Link2 },
    { at: 62, label: "Comparing with earlier reports", icon: Network },
    { at: 78, label: "Writing the AI explanation", icon: Bot },
  ],
  qr: [
    { at: 0, label: "Reading what the QR code contains", icon: QrCode },
    { at: 12, label: "Checking the payment details or link", icon: ScanText },
    { at: 35, label: "Running the matching security checks", icon: ShieldHalf },
    { at: 68, label: "Comparing with earlier reports", icon: Network },
    { at: 82, label: "Writing the AI explanation", icon: Bot },
  ],
};

// Time constant for the estimate: about 85% is reached after 2 × this many seconds.
const TYPICAL_SECONDS = { url: 4, message: 3, qr: 3 };

export default function AnalysisProgress({ mode, finished }: { mode: "url" | "message" | "qr"; finished: boolean }) {
  const [elapsed, setElapsed] = useState(0);
  const reduceMotion = useReducedMotion() ?? false;

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
  const ActiveIcon = finished ? Check : stages[Math.max(0, activeIndex)].icon;

  return (
    <motion.div
      className="card progress-card"
      role="status"
      aria-live="polite"
      initial={reduceMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="scan-layout">
        {mode === "url" ? (
          <RadarScanner icon={ActiveIcon} finished={finished} still={reduceMotion} stageKey={finished ? "done" : activeIndex} />
        ) : (
          <DocumentScanner finished={finished} still={reduceMotion} />
        )}

        <div className="scan-detail">
          <div className="progress-head">
            <span>{finished ? "Done. Preparing your report" : stages[Math.max(0, activeIndex)].label}</span>
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
            <motion.div
              className="progress-fill"
              animate={{ width: `${percent}%` }}
              transition={reduceMotion ? { duration: 0 } : { type: "spring", stiffness: 80, damping: 20 }}
            />
          </div>

          <ul className="stage-list">
            {stages.map((stage, index) => {
              const state = index < activeIndex ? "done" : index === activeIndex ? "active" : "pending";
              return (
                <motion.li
                  key={stage.label}
                  data-state={state}
                  initial={reduceMotion ? false : { opacity: 0, x: -8 }}
                  animate={{ opacity: state === "pending" ? 0.55 : 1, x: 0 }}
                  transition={{ delay: reduceMotion ? 0 : index * 0.05 }}
                >
                  <AnimatePresence mode="wait" initial={false}>
                    <motion.span
                      key={state}
                      className="stage-icon"
                      initial={reduceMotion ? false : { scale: 0.4, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      exit={{ scale: 0.4, opacity: 0 }}
                      transition={{ type: "spring", stiffness: 500, damping: 22 }}
                    >
                      {state === "done" ? (
                        <CircleCheck size={16} aria-hidden />
                      ) : state === "active" ? (
                        <LoaderCircle size={16} className="spin" aria-hidden />
                      ) : (
                        <Circle size={16} aria-hidden />
                      )}
                    </motion.span>
                  </AnimatePresence>
                  {stage.label}
                </motion.li>
              );
            })}
          </ul>
        </div>
      </div>

      {!finished && elapsed > 15 && (
        <p className="note" style={{ marginTop: 14 }}>
          Still working. If the server has been idle, it can take up to a minute to wake up.
        </p>
      )}
      <p className="note" style={{ marginTop: 10 }}>
        Progress is estimated from typical check times.
      </p>
    </motion.div>
  );
}

function RadarScanner({
  icon: Icon,
  finished,
  still,
  stageKey,
}: {
  icon: LucideIcon;
  finished: boolean;
  still: boolean;
  stageKey: string | number;
}) {
  return (
    <div className="scanner radar" aria-hidden>
      {!still &&
        !finished &&
        [0, 1, 2].map((ring) => (
          <motion.span
            key={ring}
            className="radar-ring"
            initial={{ scale: 0.35, opacity: 0.6 }}
            animate={{ scale: 1.15, opacity: 0 }}
            transition={{ duration: 2.4, repeat: Infinity, delay: ring * 0.8, ease: "easeOut" }}
          />
        ))}
      {!finished && (
        <motion.span
          className="radar-sweep"
          animate={still ? undefined : { rotate: 360 }}
          transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
        />
      )}
      <AnimatePresence mode="wait">
        <motion.span
          key={stageKey}
          className={finished ? "scanner-core scanner-core-done" : "scanner-core"}
          initial={still ? false : { scale: 0.5, opacity: 0, rotate: -20 }}
          animate={{ scale: 1, opacity: 1, rotate: 0 }}
          exit={{ scale: 0.5, opacity: 0, rotate: 20 }}
          transition={{ type: "spring", stiffness: 400, damping: 20 }}
        >
          <Icon size={30} />
        </motion.span>
      </AnimatePresence>
    </div>
  );
}

function DocumentScanner({ finished, still }: { finished: boolean; still: boolean }) {
  const lines = [92, 70, 84, 56, 78, 64];
  return (
    <div className="scanner document" aria-hidden>
      <div className="doc-lines">
        {lines.map((width, index) => (
          <motion.span
            key={index}
            className="doc-line"
            style={{ width: `${width}%` }}
            animate={still || finished ? undefined : { opacity: [0.35, 1, 0.35] }}
            transition={{ duration: 1.6, repeat: Infinity, delay: index * 0.18 }}
          />
        ))}
      </div>
      {!finished && !still && (
        <>
          <motion.span
            className="scan-line"
            animate={{ top: ["6%", "90%", "6%"] }}
            transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
          />
          <motion.span
            className="magnifier"
            animate={{ x: [0, 46, 10, 52, 0], y: [0, 18, 40, 62, 0] }}
            transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }}
          >
            <Search size={26} />
          </motion.span>
        </>
      )}
      <AnimatePresence>
        {finished && (
          <motion.span
            className="scanner-core scanner-core-done doc-done"
            initial={still ? false : { scale: 0.4, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: "spring", stiffness: 400, damping: 18 }}
          >
            <Check size={30} />
          </motion.span>
        )}
      </AnimatePresence>
    </div>
  );
}
