import "@xyflow/react/dist/style.css";
import { Background, Controls, ReactFlow, type Edge, type Node } from "@xyflow/react";
import type { GuardrailTrace } from "@/lib/types";

export function GuardrailTraceFlow({ trace }: { trace: GuardrailTrace }) {
  const stages = trace.stages ?? [];
  const stageLabel =
    stages.length === 0
      ? "not run"
      : stages.map((s) => `${s.provider_id}/${s.entry_id}: ${s.verdict}`).join("\n");
  const latency = stages.reduce((sum, stage) => sum + (stage.latency_ms || 0), 0);
  const verdictClass = (verdict: string) =>
    verdict === "deny"
      ? "trace-node deny"
      : verdict === "abstain"
        ? "trace-node abstain"
        : "trace-node allow";
  const nodes: Node[] = [
    {
      id: "local",
      position: { x: 0, y: 20 },
      data: { label: `local\n${trace.local_policy_verdict}` },
      className: verdictClass(trace.local_policy_verdict),
    },
    {
      id: "guardrail",
      position: { x: 220, y: 20 },
      data: { label: `guardrail\n${trace.guardrail_verdict}\n${latency}ms\n${stageLabel}` },
      className: verdictClass(trace.guardrail_verdict),
    },
    {
      id: "final",
      position: { x: 500, y: 20 },
      data: { label: `final\n${trace.final_verdict}` },
      className: verdictClass(trace.final_verdict),
    },
  ];
  const edges: Edge[] = [
    { id: "local-guardrail", source: "local", target: "guardrail", animated: true },
    { id: "guardrail-final", source: "guardrail", target: "final", animated: true },
  ];
  return (
    <div className="h-48 overflow-hidden rounded border border-border bg-bg">
      <ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} nodesConnectable={false}>
        <Background gap={18} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
