"""ASM Analyzer — graph queries against the ApplicationModel."""

from __future__ import annotations

from agentwall.models import (
    ApplicationModel,
    ASMConfidence,
    Category,
    ConfidenceLevel,
    Finding,
    Severity,
)
from agentwall.rules import AW_MEM_001, AW_MEM_002, AW_MEM_003, AW_MEM_005

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_CAP: dict[str, Severity] = {
    "confirmed": Severity.CRITICAL,
    "possible": Severity.HIGH,
    "uncertain": Severity.MEDIUM,
}

_CONFIDENCE_MAP: dict[str, ConfidenceLevel] = {
    "confirmed": ConfidenceLevel.HIGH,
    "possible": ConfidenceLevel.MEDIUM,
    "uncertain": ConfidenceLevel.LOW,
}

_TENANT_KEYS = frozenset({"user_id", "tenant_id", "org_id", "owner_id"})


class ASMAnalyzer:
    """Run graph queries against an ApplicationModel."""

    def analyze(self, model: ApplicationModel) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._q1_unauthenticated_write(model))
        findings.extend(self._q2_write_read_key_mismatch(model))
        findings.extend(self._q3_static_shared_collection(model))
        findings.extend(self._q4_cross_tenant_reachable(model))
        findings.extend(self._q5_unsanitized_context(model))
        return findings

    def _proof_strength(self, nodes: list[object]) -> str:
        """Compute proof strength from weakest confidence in the node chain."""
        for node in nodes:
            if getattr(node, "confidence", None) == ASMConfidence.UNKNOWN:
                return "uncertain"
        for node in nodes:
            if getattr(node, "confidence", None) == ASMConfidence.INFERRED:
                return "possible"
        return "confirmed"

    def _cap_severity(self, desired: Severity, proof: str) -> Severity:
        cap = _SEVERITY_CAP.get(proof, Severity.MEDIUM)
        if _SEVERITY_RANK[desired] < _SEVERITY_RANK[cap]:
            return cap
        return desired

    def _make_finding(
        self,
        rule_id: str,
        title: str,
        desired_severity: Severity,
        description: str,
        fix: str,
        evidence_nodes: list[object],
        evidence_path: list[dict[str, object]],
    ) -> Finding:
        proof = self._proof_strength(evidence_nodes)
        severity = self._cap_severity(desired_severity, proof)
        first = evidence_nodes[0] if evidence_nodes else None
        prov = getattr(first, "provenance", None)
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            category=Category.MEMORY,
            description=description,
            fix=fix,
            layer="ASM",
            confidence=_CONFIDENCE_MAP.get(proof, ConfidenceLevel.LOW),
            evidence_path=evidence_path,
            proof_strength=proof,
            file=prov.file if prov else None,
            line=prov.line if prov else None,
        )

    def _serialize_node(self, node: object) -> dict[str, object]:
        typ = type(node).__name__
        prov = getattr(node, "provenance", None)
        detail = ""
        if hasattr(node, "metadata_keys"):
            detail = f"metadata_keys: {set(getattr(node, 'metadata_keys', set()))}"
        elif hasattr(node, "filter_keys"):
            detail = f"filter_keys: {set(getattr(node, 'filter_keys', set()))}"
        elif hasattr(node, "collection_name") and hasattr(node, "backend"):
            detail = f"{getattr(node, 'backend')}, collection='{getattr(node, 'collection_name')}'"
        elif hasattr(node, "auth"):
            detail = f"auth: {getattr(node, 'auth')}"
        elif hasattr(node, "sanitized"):
            detail = f"sanitized: {getattr(node, 'sanitized')}"
        return {
            "type": typ,
            "file": str(prov.file) if prov else None,
            "line": prov.line if prov else None,
            "detail": detail,
        }

    # ── Q1: Unauthenticated Write Path ────────────────────────────────────

    def _q1_unauthenticated_write(self, model: ApplicationModel) -> list[Finding]:
        findings: list[Finding] = []
        trigger_map: dict[str, list[str]] = {}
        for edge in model.edges:
            if edge.kind == "triggers":
                trigger_map.setdefault(edge.target_id, []).append(edge.source_id)

        ep_map = {ep.id: ep for ep in model.entry_points}

        for write in model.write_ops:
            for ep_id in trigger_map.get(write.id, []):
                ep = ep_map.get(ep_id)
                if ep and ep.auth == "unauthenticated":
                    store = next(
                        (s for s in model.stores if s.id == write.store_id), None
                    )
                    nodes = [n for n in [ep, write, store] if n is not None]
                    findings.append(self._make_finding(
                        rule_id=AW_MEM_003.rule_id,
                        title="Unauthenticated entry point writes to vector store",
                        desired_severity=Severity.HIGH,
                        description=AW_MEM_003.description,
                        fix=AW_MEM_003.fix,
                        evidence_nodes=nodes,
                        evidence_path=[self._serialize_node(n) for n in nodes],
                    ))
        return findings

    # ── Q2: Write-Read Metadata Key Mismatch ──────────────────────────────

    def _q2_write_read_key_mismatch(self, model: ApplicationModel) -> list[Finding]:
        findings: list[Finding] = []
        for store in model.stores:
            write_keys: set[str] = set()
            store_writes = [w for w in model.write_ops if w.store_id == store.id]
            for w in store_writes:
                write_keys |= w.metadata_keys
            for r in model.read_ops:
                if r.store_id == store.id and r.filter_keys:
                    missing = r.filter_keys - frozenset(write_keys)
                    if missing:
                        nodes: list[object] = list(store_writes) + [store, r]
                        findings.append(self._make_finding(
                            rule_id=AW_MEM_002.rule_id,
                            title=f"Filter key(s) {missing} never written at ingestion",
                            desired_severity=Severity.HIGH,
                            description=AW_MEM_002.description,
                            fix=AW_MEM_002.fix,
                            evidence_nodes=nodes,
                            evidence_path=[self._serialize_node(n) for n in nodes],
                        ))
        return findings

    # ── Q3: Static Shared Collection ──────────────────────────────────────

    def _q3_static_shared_collection(self, model: ApplicationModel) -> list[Finding]:
        findings: list[Finding] = []
        trigger_map: dict[str, list[str]] = {}
        for edge in model.edges:
            if edge.kind == "triggers":
                trigger_map.setdefault(edge.target_id, []).append(edge.source_id)

        ep_map = {ep.id: ep for ep in model.entry_points}

        for store in model.stores:
            if not store.collection_name_is_static:
                continue
            writer_eps: set[str] = set()
            for w in model.write_ops:
                if w.store_id == store.id:
                    for ep_id in trigger_map.get(w.id, []):
                        writer_eps.add(ep_id)
            if len(writer_eps) <= 1:
                continue
            unfiltered = [r for r in model.read_ops
                         if r.store_id == store.id and not r.has_filter]
            if unfiltered:
                nodes: list[object] = [ep_map[eid] for eid in writer_eps if eid in ep_map]
                nodes.extend([store, *unfiltered])
                findings.append(self._make_finding(
                    rule_id=AW_MEM_001.rule_id,
                    title=f"Static collection '{store.collection_name}' shared across {len(writer_eps)} entry points without filter",
                    desired_severity=Severity.CRITICAL,
                    description=AW_MEM_001.description,
                    fix=AW_MEM_001.fix,
                    evidence_nodes=nodes,
                    evidence_path=[self._serialize_node(n) for n in nodes],
                ))
        return findings

    # ── Q4: Cross-Tenant Reachable Path ───────────────────────────────────

    def _q4_cross_tenant_reachable(self, model: ApplicationModel) -> list[Finding]:
        findings: list[Finding] = []
        for store in model.stores:
            writes = [w for w in model.write_ops if w.store_id == store.id]
            reads = [r for r in model.read_ops if r.store_id == store.id]
            for w in writes:
                if not (w.metadata_keys & _TENANT_KEYS):
                    for r in reads:
                        if not r.has_filter:
                            nodes: list[object] = [w, store, r]
                            findings.append(self._make_finding(
                                rule_id=AW_MEM_001.rule_id,
                                title="Cross-tenant data reachable: no user scope at write or read",
                                desired_severity=Severity.CRITICAL,
                                description=(
                                    "Data is written to the vector store without user/tenant metadata "
                                    "and retrieved without a filter. Any user's query returns any user's data."
                                ),
                                fix="Add user_id to metadata at write time AND filter on user_id at read time.",
                                evidence_nodes=nodes,
                                evidence_path=[self._serialize_node(n) for n in nodes],
                            ))
        return findings

    # ── Q5: Unsanitized Context Assembly ──────────────────────────────────

    def _q5_unsanitized_context(self, model: ApplicationModel) -> list[Finding]:
        findings: list[Finding] = []
        sink_map = {s.id: s for s in model.sinks}

        for edge in model.edges:
            if edge.kind != "assembles_into":
                continue
            sink = sink_map.get(edge.target_id)
            if sink and not sink.sanitized:
                read = next(
                    (r for r in model.read_ops if r.id == edge.source_id), None
                )
                nodes: list[object] = [n for n in [read, sink] if n is not None]
                findings.append(self._make_finding(
                    rule_id=AW_MEM_005.rule_id,
                    title="Retrieved memory injected into LLM context without sanitization",
                    desired_severity=Severity.MEDIUM,
                    description=AW_MEM_005.description,
                    fix=AW_MEM_005.fix,
                    evidence_nodes=nodes,
                    evidence_path=[self._serialize_node(n) for n in nodes],
                ))
        return findings
