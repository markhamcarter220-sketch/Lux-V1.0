import React, { useReducer, useState, useRef, useEffect } from "react";

// ---------------------------------------------------------------------------
// Lux Kernel — Agent Capability Enforcement Demo
//
// Pure UI simulation. No Lux binary, no backend, no network calls.
// The gate() function below mirrors the real kernel's enforcement path:
//   auth::policy::Policy::check -> auth::capability::Capability::authorises
// Revocation mirrors ADR-0003 (epoch/generation rotation, O(1), monotonic).
// ---------------------------------------------------------------------------

const CAPABILITY_DEFS = [
  { id: "cap:web_search", label: "Web Search", tools: ["search()", "fetch_url()"] },
  { id: "cap:file_read", label: "File System Read", tools: ["read_file()", "list_dir()"] },
  { id: "cap:file_write", label: "File System Write", tools: ["write_file()", "delete_file()"] },
  { id: "cap:llm_call", label: "LLM Inference", tools: ["generate()", "embed()"] },
  { id: "cap:memory_write", label: "Memory Write", tools: ["store()", "update_memory()"] },
];

const TASK_SCRIPT = [
  { call: 'search("AI safety papers 2024")', capId: "cap:web_search" },
  { call: 'fetch_url("arxiv.org/abs/2406.10281")', capId: "cap:web_search" },
  { call: 'generate("summarize these abstracts")', capId: "cap:llm_call" },
  { call: 'embed("store semantic index")', capId: "cap:llm_call" },
  { call: 'store("save to working memory")', capId: "cap:memory_write" },
  { call: 'write_file("safety_report.md", summary)', capId: "cap:file_write" },
  { call: 'read_file("template.md")', capId: "cap:file_read" },
  { call: 'generate("format final report")', capId: "cap:llm_call" },
];

const TASK_DESCRIPTION =
  "Research recent AI safety papers, summarize findings, write report to disk.";

function makeInitialCapabilities() {
  const out = {};
  CAPABILITY_DEFS.forEach((def) => {
    out[def.id] = { label: def.label, tools: def.tools, status: "active", grantedEpoch: 0 };
  });
  return out;
}

function initialKernelState() {
  return { epoch: 0, capabilities: makeInitialCapabilities(), auditLog: [] };
}

function nowStamp() {
  const d = new Date();
  return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

// gate(capId, kernelState) -> { allowed, reason, epoch }
// Fail-closed: any unrecognised or ambiguous state returns allowed: false.
function gate(capId, kernelState) {
  const cap = kernelState.capabilities[capId];
  if (!cap) {
    return { allowed: false, reason: "UNKNOWN_CAPABILITY", epoch: kernelState.epoch };
  }
  if (cap.grantedEpoch > kernelState.epoch) {
    return { allowed: false, reason: "FUTURE_ISSUED_CAPABILITY", epoch: kernelState.epoch };
  }
  if (cap.status === "revoked") {
    return { allowed: false, reason: "CAPABILITY_REVOKED", epoch: kernelState.epoch };
  }
  if (cap.status === "suspended") {
    return { allowed: false, reason: "CAPABILITY_SUSPENDED", epoch: kernelState.epoch };
  }
  return { allowed: true, reason: "CAPABILITY_VALID", epoch: kernelState.epoch };
}

function kernelReducer(state, action) {
  switch (action.type) {
    case "REVOKE": {
      const cap = state.capabilities[action.capId];
      if (!cap || cap.status === "revoked") return state; // irreversible: no-op once revoked
      const epoch = state.epoch + 1;
      const entry = {
        id: state.auditLog.length,
        epoch,
        timestamp: nowStamp(),
        capId: action.capId,
        outcome: "KERNEL_REVOKE",
        message: `${action.capId} revoked — generation rotated, epoch ${state.epoch} -> ${epoch}`,
      };
      return {
        epoch,
        capabilities: { ...state.capabilities, [action.capId]: { ...cap, status: "revoked" } },
        auditLog: [...state.auditLog, entry],
      };
    }
    case "SUSPEND": {
      const cap = state.capabilities[action.capId];
      if (!cap || cap.status !== "active") return state;
      const entry = {
        id: state.auditLog.length,
        epoch: state.epoch,
        timestamp: nowStamp(),
        capId: action.capId,
        outcome: "KERNEL_SUSPEND",
        message: `${action.capId} suspended — checks will deny until reactivated`,
      };
      return {
        ...state,
        capabilities: { ...state.capabilities, [action.capId]: { ...cap, status: "suspended" } },
        auditLog: [...state.auditLog, entry],
      };
    }
    case "REACTIVATE": {
      const cap = state.capabilities[action.capId];
      if (!cap || cap.status !== "suspended") return state; // cannot reactivate active or revoked
      const entry = {
        id: state.auditLog.length,
        epoch: state.epoch,
        timestamp: nowStamp(),
        capId: action.capId,
        outcome: "KERNEL_REACTIVATE",
        message: `${action.capId} reactivated by operator`,
      };
      return {
        ...state,
        capabilities: { ...state.capabilities, [action.capId]: { ...cap, status: "active" } },
        auditLog: [...state.auditLog, entry],
      };
    }
    case "GATE_RESULT": {
      const entry = {
        id: state.auditLog.length,
        epoch: state.epoch,
        timestamp: nowStamp(),
        capId: action.capId,
        outcome: action.allowed ? "KERNEL_ALLOW" : "KERNEL_DENY",
        message: action.message,
      };
      return { ...state, auditLog: [...state.auditLog, entry] };
    }
    case "RESET":
      return initialKernelState();
    default:
      return state;
  }
}

const AUDIT_STYLES = {
  KERNEL_ALLOW: { border: "border-l-[3px] border-l-emerald-500/70", badge: null },
  KERNEL_DENY: {
    border: "border-l-[3px] border-l-red-500",
    badge: { text: "DENY", cls: "bg-red-500/20 text-red-400 border border-red-500/40" },
  },
  KERNEL_SUSPEND: {
    border: "border-l-[3px] border-l-amber-500",
    badge: { text: "SUSPEND", cls: "bg-amber-500/20 text-amber-400 border border-amber-500/40" },
  },
  KERNEL_REVOKE: {
    border: "border-l-[3px] border-l-red-600",
    badge: { text: "REVOKE", cls: "bg-red-600/30 text-red-300 border border-red-600/50 font-bold" },
  },
  KERNEL_REACTIVATE: {
    border: "border-l-[3px] border-l-[#60A5FA]",
    badge: { text: "REACTIVATE", cls: "bg-[#60A5FA]/20 text-[#93C5FD] border border-[#60A5FA]/40" },
  },
};

function SegmentedControl({ cap, capId, onChange }) {
  const options = [
    { key: "active", label: "ACTIVE" },
    { key: "suspended", label: "SUSPEND" },
    { key: "revoked", label: "REVOKE" },
  ];
  return (
    <div className="flex rounded overflow-hidden border border-slate-700 text-[10px] font-medium">
      {options.map((opt) => {
        const isCurrent = cap.status === opt.key;
        const disabled = cap.status === "revoked" && opt.key !== "revoked";
        const activeCls =
          isCurrent && opt.key === "active" ? "bg-emerald-500/90 text-slate-900" : "";
        const suspendCls =
          isCurrent && opt.key === "suspended" ? "bg-amber-500/90 text-slate-900" : "";
        const revokeCls =
          isCurrent && opt.key === "revoked" ? "bg-red-500/90 text-slate-900" : "";
        const idleCls =
          !isCurrent && !disabled
            ? "bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200 cursor-pointer"
            : "";
        const disabledCls = disabled ? "bg-slate-900 text-slate-600 cursor-not-allowed opacity-50" : "";
        return (
          <button
            key={opt.key}
            disabled={disabled}
            onClick={(e) => {
              e.stopPropagation();
              onChange(capId, opt.key);
            }}
            className={`px-2 py-1 transition-colors ${activeCls} ${suspendCls} ${revokeCls} ${idleCls} ${disabledCls}`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

function CapabilityCard({ capId, cap, selected, onSelect, onChange, lastUsed }) {
  const statusColor =
    cap.status === "active" ? "#22C55E" : cap.status === "suspended" ? "#F59E0B" : "#EF4444";
  return (
    <div
      onClick={() => onSelect(capId)}
      className={`cap-card rounded-md border p-3 cursor-pointer bg-[#111827] ${
        cap.status === "revoked" ? "cap-card-revoked border-red-600/60" : "border-slate-700"
      } ${selected ? "ring-1 ring-[#60A5FA]" : ""}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-sm text-slate-100 font-medium">{cap.label}</div>
          <div className="text-[10px] text-slate-500">{capId}</div>
        </div>
        <span
          className="text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase shrink-0"
          style={{
            color: statusColor,
            borderWidth: "1px",
            borderStyle: "solid",
            borderColor: statusColor,
            backgroundColor: `${statusColor}1A`,
          }}
        >
          {cap.status}
        </span>
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500">
        <span>granted epoch {cap.grantedEpoch}</span>
        <span>{lastUsed !== null ? `last used @ epoch ${lastUsed}` : "never used"}</span>
      </div>

      {selected && (
        <div className="mt-2 text-[10px] text-slate-400 border-t border-slate-700 pt-2">
          gates: {cap.tools.join(", ")}
        </div>
      )}

      <div className="mt-3" onClick={(e) => e.stopPropagation()}>
        <SegmentedControl cap={cap} capId={capId} onChange={onChange} />
      </div>
    </div>
  );
}

const AGENT_STATUS_STYLE = {
  idle: { label: "IDLE", cls: "bg-slate-700/60 text-slate-300" },
  running: { label: "RUNNING", cls: "bg-[#60A5FA]/20 text-[#93C5FD]" },
  blocked: { label: "BLOCKED", cls: "bg-amber-500/20 text-amber-400" },
  halted: { label: "HALTED", cls: "bg-red-500/20 text-red-400" },
};

export default function LuxKernelAgentDemo() {
  const [kernelState, dispatch] = useReducer(kernelReducer, undefined, initialKernelState);
  const [agentStatus, setAgentStatus] = useState("idle");
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [execLog, setExecLog] = useState([]);
  const [selectedCapId, setSelectedCapId] = useState(null);
  const [epochPulse, setEpochPulse] = useState(false);

  const kernelStateRef = useRef(kernelState);
  const timeoutRef = useRef(null);
  const runIdRef = useRef(0);
  const prevEpochRef = useRef(kernelState.epoch);
  const execLogEndRef = useRef(null);
  const auditLogEndRef = useRef(null);

  useEffect(() => {
    kernelStateRef.current = kernelState;
  }, [kernelState]);

  useEffect(() => {
    if (kernelState.epoch !== prevEpochRef.current) {
      prevEpochRef.current = kernelState.epoch;
      setEpochPulse(true);
      const t = setTimeout(() => setEpochPulse(false), 450);
      return () => clearTimeout(t);
    }
  }, [kernelState.epoch]);

  useEffect(() => {
    if (execLogEndRef.current && typeof execLogEndRef.current.scrollIntoView === "function") {
      execLogEndRef.current.scrollIntoView({ block: "nearest" });
    }
  }, [execLog]);

  useEffect(() => {
    if (auditLogEndRef.current && typeof auditLogEndRef.current.scrollIntoView === "function") {
      auditLogEndRef.current.scrollIntoView({ block: "nearest" });
    }
  }, [kernelState.auditLog]);

  useEffect(() => () => clearTimeout(timeoutRef.current), []);

  function appendExec(entry) {
    setExecLog((prev) => [...prev, { ...entry, id: prev.length }]);
  }

  function runStep(stepIndex, runId) {
    if (runId !== runIdRef.current) return;
    const step = TASK_SCRIPT[stepIndex];
    appendExec({
      stepIndex,
      phase: "pending",
      capId: step.capId,
      text: step.call,
      label: `requires ${step.capId}`,
    });
    const delay = 800 + Math.random() * 700;
    timeoutRef.current = setTimeout(() => {
      if (runId !== runIdRef.current) return;
      // Capability check and execution happen in the same tick: no async
      // gap between gate() and the effect it authorises.
      const snapshot = kernelStateRef.current;
      const result = gate(step.capId, snapshot);
      dispatch({
        type: "GATE_RESULT",
        capId: step.capId,
        allowed: result.allowed,
        message: result.allowed
          ? `${step.call} authorised by gate(${step.capId}, epoch ${snapshot.epoch})`
          : `${step.call} denied by gate(${step.capId}, epoch ${snapshot.epoch}) — ${result.reason}`,
      });
      if (result.allowed) {
        appendExec({
          stepIndex,
          phase: "allowed",
          capId: step.capId,
          text: `gate(${step.capId}) -> ALLOW`,
          label: `epoch ${snapshot.epoch}`,
        });
        if (stepIndex === TASK_SCRIPT.length - 1) {
          setAgentStatus("idle");
          appendExec({ stepIndex, phase: "complete", text: "task complete — safety_report.md written to disk" });
        } else {
          setCurrentStepIndex(stepIndex + 1);
          runStep(stepIndex + 1, runId);
        }
      } else {
        const terminal =
          result.reason === "CAPABILITY_REVOKED" ||
          result.reason === "FUTURE_ISSUED_CAPABILITY" ||
          result.reason === "UNKNOWN_CAPABILITY";
        appendExec({
          stepIndex,
          phase: terminal ? "denied-halt" : "denied-suspend",
          capId: step.capId,
          text: `gate(${step.capId}) -> DENY (${result.reason})`,
          label: terminal ? "KERNEL_DENY — agent halted" : "KERNEL_DENY — agent blocked",
        });
        setCurrentStepIndex(stepIndex);
        setAgentStatus(terminal ? "halted" : "blocked");
      }
    }, delay);
  }

  function startAgent() {
    if (agentStatus === "running") return;
    runIdRef.current += 1;
    const runId = runIdRef.current;
    setExecLog([]);
    setAgentStatus("running");
    setCurrentStepIndex(0);
    runStep(0, runId);
  }

  function resumeAgent() {
    if (agentStatus !== "blocked") return;
    setAgentStatus("running");
    runStep(currentStepIndex, runIdRef.current);
  }

  function resetAll() {
    runIdRef.current += 1; // invalidates any in-flight timeout from the previous run
    clearTimeout(timeoutRef.current);
    dispatch({ type: "RESET" });
    setAgentStatus("idle");
    setCurrentStepIndex(0);
    setExecLog([]);
    setSelectedCapId(null);
  }

  function setCapStatus(capId, target) {
    const cap = kernelState.capabilities[capId];
    if (!cap || cap.status === "revoked") return;
    if (target === cap.status) return;
    if (target === "active") dispatch({ type: "REACTIVATE", capId });
    else if (target === "suspended") dispatch({ type: "SUSPEND", capId });
    else if (target === "revoked") dispatch({ type: "REVOKE", capId });
  }

  function lastUsedEpoch(capId) {
    const entries = kernelState.auditLog.filter(
      (e) => e.capId === capId && e.outcome === "KERNEL_ALLOW"
    );
    if (entries.length === 0) return null;
    return entries[entries.length - 1].epoch;
  }

  const statusInfo = AGENT_STATUS_STYLE[agentStatus];

  return (
    <div className="min-h-screen bg-[#0A0E1A] text-slate-300 p-4" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        .lux-demo, .lux-demo * { font-family: 'JetBrains Mono', monospace; }
        @keyframes epochPulse {
          0% { transform: scale(1); text-shadow: 0 0 0 rgba(96,165,250,0); }
          30% { transform: scale(1.18); text-shadow: 0 0 14px rgba(96,165,250,0.9); }
          100% { transform: scale(1); text-shadow: 0 0 0 rgba(96,165,250,0); }
        }
        .epoch-pulse { animation: epochPulse 450ms ease-out; }
        .cap-card { transition: opacity 300ms ease, border-color 300ms ease, filter 300ms ease; }
        .cap-card-revoked { opacity: 0.4; filter: saturate(0.4); }
        @keyframes rowIn { from { opacity: 0; transform: translateY(-3px); } to { opacity: 1; transform: translateY(0); } }
        .log-row { animation: rowIn 180ms ease-out; }
      `}</style>

      <div className="lux-demo">
        {/* Header */}
        <div className="flex flex-wrap items-center gap-3 border border-slate-800 rounded-md bg-[#0d1220] px-4 py-3">
          <span className="text-sm font-bold text-slate-100 tracking-wide">LUX KERNEL DEMO</span>
          <span className="text-slate-600">│</span>
          <span className={`text-sm text-[#60A5FA] ${epochPulse ? "epoch-pulse" : ""}`}>
            epoch: {String(kernelState.epoch).padStart(4, "0")}
          </span>
          <span className="text-slate-600">│</span>
          <span className="text-xs">
            agent:{" "}
            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${statusInfo.cls}`}>
              {statusInfo.label}
            </span>
          </span>

          <div className="flex-1" />

          {agentStatus === "idle" && (
            <button
              onClick={startAgent}
              className="text-xs px-3 py-1.5 rounded bg-[#60A5FA] text-slate-900 font-semibold hover:bg-[#7CB4FB]"
            >
              RUN TASK
            </button>
          )}
          {agentStatus === "running" && (
            <button disabled className="text-xs px-3 py-1.5 rounded bg-slate-700 text-slate-400 cursor-not-allowed">
              RUNNING…
            </button>
          )}
          {agentStatus === "blocked" && (
            <button
              onClick={resumeAgent}
              className="text-xs px-3 py-1.5 rounded bg-amber-500 text-slate-900 font-semibold hover:bg-amber-400"
            >
              RESUME
            </button>
          )}
          {agentStatus === "halted" && (
            <span className="text-xs px-3 py-1.5 rounded bg-red-500/20 text-red-400 font-semibold">
              HALTED — RESET REQUIRED
            </span>
          )}

          <button
            onClick={resetAll}
            className="text-xs px-3 py-1.5 rounded border border-slate-600 text-slate-300 hover:bg-slate-800"
          >
            RESET
          </button>
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
          {/* Agent execution log */}
          <div className="flex flex-col border border-slate-800 rounded-md bg-[#0d1220] overflow-hidden" style={{ height: "calc(100vh - 130px)" }}>
            <div className="px-3 py-2 border-b border-slate-800 shrink-0">
              <div className="text-xs font-semibold text-slate-200">AGENT EXECUTION LOG</div>
              <div className="text-[10px] text-slate-500 mt-1">{TASK_DESCRIPTION}</div>
              <div className="text-[10px] text-slate-600 mt-0.5">
                step {Math.min(currentStepIndex + 1, TASK_SCRIPT.length)}/{TASK_SCRIPT.length}
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-1.5 text-xs">
              {execLog.length === 0 && (
                <div className="text-slate-600 text-[11px]">no execution yet — press RUN TASK</div>
              )}
              {execLog.map((entry) => {
                let rowCls = "log-row pl-2 py-1 border-l-[3px]";
                if (entry.phase === "pending") rowCls += " border-l-slate-600 text-slate-500";
                if (entry.phase === "allowed") rowCls += " border-l-emerald-500/70 text-slate-300";
                if (entry.phase === "denied-halt") rowCls += " border-l-red-500 bg-red-500/10 text-red-300";
                if (entry.phase === "denied-suspend") rowCls += " border-l-amber-500 bg-amber-500/10 text-amber-300";
                if (entry.phase === "complete") rowCls += " border-l-[#60A5FA] text-[#93C5FD] font-semibold";
                return (
                  <div key={entry.id} className={rowCls}>
                    <div>{entry.text}</div>
                    {entry.label && <div className="text-[10px] opacity-70">{entry.label}</div>}
                  </div>
                );
              })}
              <div ref={execLogEndRef} />
            </div>
          </div>

          {/* Right column: capabilities + audit log */}
          <div className="flex flex-col gap-4" style={{ height: "calc(100vh - 130px)" }}>
            <div className="flex flex-col border border-slate-800 rounded-md bg-[#0d1220] overflow-hidden flex-1">
              <div className="px-3 py-2 border-b border-slate-800 text-xs font-semibold text-slate-200 shrink-0">
                CAPABILITY CONTROL PANEL
              </div>
              <div className="flex-1 overflow-y-auto p-3 space-y-2">
                {CAPABILITY_DEFS.map((def) => (
                  <CapabilityCard
                    key={def.id}
                    capId={def.id}
                    cap={kernelState.capabilities[def.id]}
                    selected={selectedCapId === def.id}
                    onSelect={(id) => setSelectedCapId((prev) => (prev === id ? null : id))}
                    onChange={setCapStatus}
                    lastUsed={lastUsedEpoch(def.id)}
                  />
                ))}
              </div>
            </div>

            <div className="flex flex-col border border-slate-800 rounded-md bg-[#0d1220] overflow-hidden flex-1">
              <div className="px-3 py-2 border-b border-slate-800 text-xs font-semibold text-slate-200 shrink-0">
                AUDIT LOG
              </div>
              <div className="flex-1 overflow-y-auto p-3 space-y-1 text-[11px]">
                {kernelState.auditLog.length === 0 && (
                  <div className="text-slate-600 text-[11px]">append-only — empty since last reset</div>
                )}
                {kernelState.auditLog.map((entry) => {
                  const style = AUDIT_STYLES[entry.outcome];
                  return (
                    <div key={entry.id} className={`log-row pl-2 py-1 ${style.border}`}>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">[{String(entry.epoch).padStart(4, "0")}]</span>
                        <span className="text-slate-600">{entry.timestamp}</span>
                        {style.badge && (
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${style.badge.cls}`}>
                            {style.badge.text}
                          </span>
                        )}
                        <span className="text-slate-500">{entry.capId}</span>
                      </div>
                      <div className="text-slate-400 mt-0.5">{entry.message}</div>
                    </div>
                  );
                })}
                <div ref={auditLogEndRef} />
              </div>
            </div>
          </div>
        </div>

        <div className="text-[10px] text-slate-600 mt-3 leading-relaxed">
          Simulation only — no Lux binary, no backend. gate() mirrors{" "}
          <span className="text-slate-500">auth::policy::Policy::check → auth::capability::Capability::authorises</span>.
          Revocation mirrors ADR-0003 generation rotation: O(1), epoch-monotonic, irreversible.
        </div>
      </div>
    </div>
  );
}
