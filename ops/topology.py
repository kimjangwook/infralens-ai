from __future__ import annotations

"""Infrastructure topology built from scanned schedules and resources.

The topology layer does not call any cloud API. It joins the evidence that
scanners already stored (``Schedule.target_ref`` against
``Resource.provider_id``/names) into a graph, renders that graph as a Mermaid
flowchart, and derives structural insights such as orphan schedule targets,
untriggered workloads, and fan-in hotspots.
"""

from dataclasses import dataclass, field

from .models import CloudAccount, Finding, Resource, ScanRun, Schedule


# Resource kinds that normally exist to be triggered by a schedule. Anything
# else (e.g. a Cloud Run service serving HTTP traffic) is fine without one.
TRIGGERED_KINDS = {"aws.lambda", "gcp.cloud_run.job"}

# Target types that point at infrastructure we expect to have scanned. HTTP and
# Pub/Sub targets are external by nature and never count as orphans.
INTERNAL_TARGET_TYPES = {"aws.lambda", "aws.ecs", "aws.stepfunctions", "gcp.cloud_run"}

HOTSPOT_FAN_IN = 3


@dataclass
class TopologyNode:
    id: str
    label: str
    kind: str  # "schedule" | "resource" | "external"
    account: str
    provider: str
    state: str = ""
    detail: str = ""


@dataclass
class TopologyEdge:
    source: str
    target: str


@dataclass
class TopologyGraph:
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    orphan_schedules: list[Schedule] = field(default_factory=list)
    untriggered_resources: list[Resource] = field(default_factory=list)
    hotspots: list[tuple[Resource, int]] = field(default_factory=list)
    inactive_schedules: list[Schedule] = field(default_factory=list)

    @property
    def stats(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "orphan_schedules": len(self.orphan_schedules),
            "untriggered_resources": len(self.untriggered_resources),
            "hotspots": len(self.hotspots),
            "inactive_schedules": len(self.inactive_schedules),
        }


def build_topology(accounts) -> TopologyGraph:
    graph = TopologyGraph()
    for account in accounts:
        _add_account(graph, account)
    return graph


def _add_account(graph: TopologyGraph, account: CloudAccount) -> None:
    resources = list(account.resources.all())
    schedules = list(account.schedules.all())

    resource_nodes: dict[str, str] = {}
    inbound: dict[str, int] = {}
    by_provider_id = {resource.provider_id: resource for resource in resources}

    iam_nodes: dict[str, str] = {}
    for resource in resources:
        node_id = f"r_{resource.id.hex[:10]}"
        resource_nodes[resource.provider_id] = node_id
        inbound[resource.provider_id] = 0
        graph.nodes.append(
            TopologyNode(
                id=node_id,
                label=resource.name,
                kind="resource",
                account=account.name,
                provider=account.provider,
                detail=resource.resource_type,
            )
        )
        iam_ref = (resource.metadata or {}).get("iam_role", "")
        if iam_ref:
            if iam_ref not in iam_nodes:
                iam_id = f"i_{len(iam_nodes)}_{resource.id.hex[:8]}"
                iam_nodes[iam_ref] = iam_id
                graph.nodes.append(
                    TopologyNode(
                        id=iam_id,
                        label=iam_ref.rsplit("/", 1)[-1],
                        kind="iam",
                        account=account.name,
                        provider=account.provider,
                        detail="identity",
                    )
                )
            graph.edges.append(
                TopologyEdge(source=node_id, target=iam_nodes[iam_ref])
            )

    external_nodes: dict[str, str] = {}
    for schedule in schedules:
        schedule_node = f"s_{schedule.id.hex[:10]}"
        inactive = schedule.state.upper() in {"DISABLED", "PAUSED"}
        if inactive:
            graph.inactive_schedules.append(schedule)
        graph.nodes.append(
            TopologyNode(
                id=schedule_node,
                label=schedule.name,
                kind="schedule",
                account=account.name,
                provider=account.provider,
                state="inactive" if inactive else "active",
                detail=schedule.schedule_expression or "manual",
            )
        )
        if not schedule.target_ref:
            continue

        matched = _match_resource(schedule, by_provider_id, resources)
        if matched is not None:
            inbound[matched.provider_id] = inbound.get(matched.provider_id, 0) + 1
            graph.edges.append(
                TopologyEdge(source=schedule_node, target=resource_nodes[matched.provider_id])
            )
            continue

        if schedule.target_type in INTERNAL_TARGET_TYPES:
            graph.orphan_schedules.append(schedule)

        external_key = f"{account.pk}:{schedule.target_ref}"
        if external_key not in external_nodes:
            node_id = f"x_{len(external_nodes)}_{schedule.id.hex[:8]}"
            external_nodes[external_key] = node_id
            graph.nodes.append(
                TopologyNode(
                    id=node_id,
                    label=_external_label(schedule.target_ref),
                    kind="external",
                    account=account.name,
                    provider=account.provider,
                    detail=schedule.target_type or "external",
                )
            )
        graph.edges.append(
            TopologyEdge(source=schedule_node, target=external_nodes[external_key])
        )

    for resource in resources:
        fan_in = inbound.get(resource.provider_id, 0)
        if fan_in >= HOTSPOT_FAN_IN:
            graph.hotspots.append((resource, fan_in))
        elif fan_in == 0 and resource.resource_type in TRIGGERED_KINDS:
            graph.untriggered_resources.append(resource)


def _match_resource(
    schedule: Schedule,
    by_provider_id: dict[str, Resource],
    resources: list[Resource],
) -> Resource | None:
    target = schedule.target_ref
    if target in by_provider_id:
        return by_provider_id[target]
    # GCP HTTP targets reference a Cloud Run URL rather than the resource name;
    # fall back to matching the resource's short name inside the target ref.
    for resource in resources:
        short = resource.name.rsplit("/", 1)[-1]
        if len(short) >= 4 and short in target:
            return resource
    return None


def _external_label(target_ref: str) -> str:
    label = target_ref
    for prefix in ("https://", "http://"):
        if label.startswith(prefix):
            label = label[len(prefix):]
    return label if len(label) <= 42 else f"{label[:39]}..."


def _mermaid_label(text: str) -> str:
    cleaned = text.replace('"', "'").replace("\n", " ")
    return cleaned if len(cleaned) <= 48 else f"{cleaned[:45]}..."


def render_mermaid(graph: TopologyGraph) -> str:
    lines = ["flowchart LR"]
    by_account: dict[str, list[TopologyNode]] = {}
    for node in graph.nodes:
        by_account.setdefault(f"{node.account} ({node.provider})", []).append(node)

    for index, (title, nodes) in enumerate(sorted(by_account.items())):
        lines.append(f'  subgraph acct{index}["{_mermaid_label(title)}"]')
        for node in nodes:
            # Plain-text labels only: securityLevel "strict" in the template
            # escapes HTML, and node names come from scanned cloud data.
            label = _mermaid_label(f"{node.label} | {node.detail}" if node.detail else node.label)
            if node.kind == "schedule":
                lines.append(f'    {node.id}(["{label}"])')
            elif node.kind == "external":
                lines.append(f'    {node.id}[/"{label}"/]')
            elif node.kind == "iam":
                lines.append(f'    {node.id}{{{{"{label}"}}}}')
            else:
                lines.append(f'    {node.id}["{label}"]')
            css = node.kind if node.state != "inactive" else "inactive"
            lines.append(f"    class {node.id} {css}")
        lines.append("  end")

    for edge in graph.edges:
        lines.append(f"  {edge.source} --> {edge.target}")

    lines.extend(
        [
            "  classDef schedule fill:#1e3a8a,stroke:#3b82f6,color:#e0e7ff",
            "  classDef resource fill:#064e3b,stroke:#10b981,color:#d1fae5",
            "  classDef external fill:#3f3f46,stroke:#a1a1aa,color:#f4f4f5,stroke-dasharray: 4 3",
            "  classDef inactive fill:#52525b,stroke:#71717a,color:#d4d4d8",
            "  classDef iam fill:#713f12,stroke:#f59e0b,color:#fef3c7",
        ]
    )
    return "\n".join(lines)


def topology_insights(graph: TopologyGraph) -> list[dict]:
    """Human-readable structural insights for the topology page."""
    insights: list[dict] = []
    for schedule in graph.orphan_schedules:
        insights.append(
            {
                "severity": Finding.Severity.WARNING,
                "title": f"Schedule '{schedule.name}' targets a resource that was not found",
                "detail": (
                    f"Target {schedule.target_ref or '-'} ({schedule.target_type or 'unknown'}) "
                    "did not match any scanned resource. The target may be deleted, "
                    "in an unscanned region, or outside the read-only role's scope."
                ),
            }
        )
    for resource, fan_in in graph.hotspots:
        insights.append(
            {
                "severity": Finding.Severity.INFO,
                "title": f"'{resource.name}' is a fan-in hotspot ({fan_in} schedules)",
                "detail": (
                    "Several schedules converge on this resource. A failure here "
                    "stops multiple pipelines at once; consider monitoring it first."
                ),
            }
        )
    for resource in graph.untriggered_resources:
        insights.append(
            {
                "severity": Finding.Severity.INFO,
                "title": f"'{resource.name}' is not triggered by any schedule",
                "detail": (
                    f"{resource.resource_type} has no inbound schedule edge. It may be "
                    "invoked another way, or it may be an unused resource costing money."
                ),
            }
        )
    for schedule in graph.inactive_schedules:
        insights.append(
            {
                "severity": Finding.Severity.INFO,
                "title": f"Schedule '{schedule.name}' is {schedule.state.lower() or 'inactive'}",
                "detail": "Verify whether this pause is intentional.",
            }
        )
    return insights


def analyze_topology(account: CloudAccount, scan_run: ScanRun) -> int:
    """Persist structural findings for one account after a scan.

    Runs inside the scan pipeline so scheduled and webhook-triggered scans get
    topology insights without any extra step.
    """
    from .scanners.common import upsert_finding

    graph = build_topology([account])
    created = 0
    for schedule in graph.orphan_schedules:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.WARNING,
            "topology",
            f"Schedule '{schedule.name}' targets an unknown resource",
            resource_ref=schedule.target_ref,
            evidence={
                "schedule": schedule.name,
                "target_type": schedule.target_type,
                "target_ref": schedule.target_ref,
                "region": schedule.region,
            },
            suggested_action=(
                "Confirm the target still exists, or widen the scanned regions / "
                "read-only role so InfraLens can see it."
            ),
        )
        created += 1
    for resource, fan_in in graph.hotspots:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "topology",
            f"'{resource.name}' receives {fan_in} schedules (fan-in hotspot)",
            resource_ref=resource.provider_id,
            evidence={"fan_in": fan_in, "resource_type": resource.resource_type},
            suggested_action=(
                "A failure in this resource stops multiple pipelines. Prioritize "
                "alerting and capacity review here."
            ),
        )
        created += 1
    for resource in graph.untriggered_resources:
        upsert_finding(
            account,
            scan_run,
            Finding.Severity.INFO,
            "topology",
            f"'{resource.name}' has no schedule trigger",
            resource_ref=resource.provider_id,
            evidence={"resource_type": resource.resource_type, "region": resource.region},
            suggested_action=(
                "Check how this workload is invoked. If nothing calls it, removing "
                "it reduces cost and attack surface."
            ),
        )
        created += 1
    return created
