import type { V1NetworkPolicy } from "@kubernetes/client-node";
import type { KubernetesApiClient } from "../types.js";
import { tenantBaseLabels, PAPERCLIP_ROLE, ROLE_AGENT_RUNTIME } from "./labels.js";

const RFC1918_AND_INTERNAL_DENY = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",   // link-local incl. cloud metadata
  "100.64.0.0/10",    // CGNAT
  "fd00::/8",         // IPv6 ULA
];

export interface BuildDefaultDenyInput {
  namespace: string;
  companyId: string;
  companySlug: string;
}

export function buildDefaultDenyPolicies(input: BuildDefaultDenyInput): V1NetworkPolicy[] {
  const labels = tenantBaseLabels({ companyId: input.companyId, companySlug: input.companySlug });
  return [
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "default-deny-ingress", namespace: input.namespace, labels },
      spec: { podSelector: {}, policyTypes: ["Ingress"] },
    },
    {
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: { name: "default-deny-egress", namespace: input.namespace, labels },
      spec: { podSelector: {}, policyTypes: ["Egress"] },
    },
  ];
}

export interface AgentEgressInput {
  namespace: string;
  companyId: string;
  companySlug: string;
  topology: "in-cluster" | "cross-cluster";
  controlPlaneSelector: {
    namespaceLabel: Record<string, string>;
    podLabel: Record<string, string>;
  } | null;
}

export function buildAgentEgressPolicy(input: AgentEgressInput): V1NetworkPolicy {
  const labels = tenantBaseLabels({ companyId: input.companyId, companySlug: input.companySlug });
  const egress: NonNullable<V1NetworkPolicy["spec"]>["egress"] = [
    // DNS
    {
      to: [{
        namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } },
        podSelector:       { matchLabels: { "k8s-app": "kube-dns" } },
      }],
      ports: [{ port: 53, protocol: "UDP" }, { port: 53, protocol: "TCP" }],
    },
  ];

  if (input.topology === "in-cluster" && input.controlPlaneSelector) {
    egress.push({
      to: [{
        namespaceSelector: { matchLabels: input.controlPlaneSelector.namespaceLabel },
        podSelector:       { matchLabels: input.controlPlaneSelector.podLabel },
      }],
      ports: [{ port: 443, protocol: "TCP" }, { port: 3102, protocol: "TCP" }],
    });
  }

  // Internet egress (denies internal ranges)
  egress.push({
    to: [{ ipBlock: { cidr: "0.0.0.0/0", except: RFC1918_AND_INTERNAL_DENY } }],
    ports: [{ port: 443, protocol: "TCP" }],
  });

  return {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: { name: "paperclip-agent-egress", namespace: input.namespace, labels },
    spec: {
      podSelector: { matchLabels: { [PAPERCLIP_ROLE]: ROLE_AGENT_RUNTIME } },
      policyTypes: ["Egress"],
      egress,
    },
  };
}

export async function applyNetworkPolicy(client: KubernetesApiClient, p: V1NetworkPolicy): Promise<void> {
  const ns = p.metadata!.namespace!;
  const name = p.metadata!.name!;
  try {
    await client.networking.readNamespacedNetworkPolicy(name, ns);
    await client.networking.patchNamespacedNetworkPolicy(name, ns, p, undefined, undefined, undefined, undefined, undefined, {
      headers: { "Content-Type": "application/strategic-merge-patch+json" },
    } as never);
  } catch (err) {
    if ((err as { response?: { statusCode?: number } })?.response?.statusCode === 404) {
      await client.networking.createNamespacedNetworkPolicy(ns, p);
      return;
    }
    throw err;
  }
}
