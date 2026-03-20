"""Link ASM nodes into a graph via structural relationships.

Phase 1: Links based on explicit IDs (store_id references) and
co-location in the same file. Cross-function call graph linking
is deferred to Phase 2.
"""

from __future__ import annotations

from agentwall.models import ApplicationModel, ASMConfidence, Edge


def link_edges(model: ApplicationModel) -> list[Edge]:
    """Generate edges between ASM nodes based on structural relationships.

    Links:
    1. WriteOp -> Store (writes_to) via store_id match
    2. ReadOp -> Store (reads_from) via store_id match
    3. ReadOp -> ContextSink (assembles_into) via same-file co-location
    4. EntryPoint -> WriteOp/ReadOp (triggers) via same-file co-location
    """
    edges: list[Edge] = []
    store_ids = {s.id for s in model.stores}

    # 1. WriteOp -> Store
    for write in model.write_ops:
        if write.store_id in store_ids:
            edges.append(
                Edge(
                    source_id=write.id,
                    target_id=write.store_id,
                    kind="writes_to",
                    confidence=ASMConfidence.CONFIRMED,
                    provenance=write.provenance,
                )
            )

    # 2. ReadOp -> Store
    for read in model.read_ops:
        if read.store_id in store_ids:
            edges.append(
                Edge(
                    source_id=read.id,
                    target_id=read.store_id,
                    kind="reads_from",
                    confidence=ASMConfidence.CONFIRMED,
                    provenance=read.provenance,
                )
            )

    # 3. ReadOp -> nearest ContextSink (same file, sink after read)
    for read in model.read_ops:
        nearest_sink = None
        nearest_line = float("inf")
        for sink in model.sinks:
            if (
                read.provenance.file == sink.provenance.file
                and read.provenance.line < sink.provenance.line < nearest_line
            ):
                nearest_sink = sink
                nearest_line = sink.provenance.line
        if nearest_sink is not None:
            edges.append(
                Edge(
                    source_id=read.id,
                    target_id=nearest_sink.id,
                    kind="assembles_into",
                    confidence=ASMConfidence.INFERRED,
                    provenance=read.provenance,
                )
            )

    # 4. EntryPoint -> WriteOp/ReadOp (same file, within function body)
    # Scoped by line range: only link ops whose line falls within the
    # entry point's function body [line, end_line]. Falls back to same-file
    # when end_line is unavailable (Python <3.8 or missing AST info).
    for ep in model.entry_points:
        ep_start = ep.provenance.line
        ep_end = ep.provenance.end_line
        for write in model.write_ops:
            if ep.provenance.file != write.provenance.file:
                continue
            if ep_end is not None and not (ep_start <= write.provenance.line <= ep_end):
                continue
            edges.append(
                Edge(
                    source_id=ep.id,
                    target_id=write.id,
                    kind="triggers",
                    confidence=ASMConfidence.INFERRED,
                    provenance=ep.provenance,
                )
            )
        for read in model.read_ops:
            if ep.provenance.file != read.provenance.file:
                continue
            if ep_end is not None and not (ep_start <= read.provenance.line <= ep_end):
                continue
            edges.append(
                Edge(
                    source_id=ep.id,
                    target_id=read.id,
                    kind="triggers",
                    confidence=ASMConfidence.INFERRED,
                    provenance=ep.provenance,
                )
            )

    return edges
