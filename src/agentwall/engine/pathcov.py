"""L6 engine: path coverage aggregator.

Aggregates PropertyVerification results produced by the L3 verifier into
per-store PathCoverage reports. This is a pure aggregation layer — it does
not perform additional interprocedural analysis.

Logic:
  1. Group verifications by store_id.
  2. For each StoreProfile:
     - COLLECTION_PER_TENANT isolation → all read paths are VerifiedPath.
     - Otherwise, map each PropertyVerification verdict:
         VERIFIED → VerifiedPath
         VIOLATED → ViolatedPath
         UNKNOWN or PARTIAL → UnknownPath
  3. Emit one PathCoverage per profile.

Never executes user code. All analysis is over pre-computed model objects.
"""

from __future__ import annotations

from pathlib import Path

from agentwall.engine.graph import ProjectGraph
from agentwall.engine.models import (
    IsolationStrategy,
    PathCoverage,
    PropertyVerification,
    SecurityProperty,
    StoreProfile,
    UnknownPath,
    Verdict,
    VerifiedPath,
    ViolatedPath,
)


def compute_path_coverage(
    profiles: list[StoreProfile],
    graph: ProjectGraph,  # noqa: ARG001 — reserved for future interprocedural use
    verifications: list[PropertyVerification],
) -> list[PathCoverage]:
    """Compute path coverage for each store profile.

    Args:
        profiles: Store profiles produced by extract_properties.
        graph: Project call graph (reserved for future interprocedural use).
        verifications: Verification results from verify_tenant_isolation.

    Returns:
        One PathCoverage per profile that has at least one read extraction.
        Profiles with no read extractions are omitted.
        Returns an empty list when profiles is empty.
    """
    if not profiles:
        return []

    by_store: dict[str, list[PropertyVerification]] = {}
    for v in verifications:
        by_store.setdefault(v.store_id, []).append(v)

    results: list[PathCoverage] = []

    for profile in profiles:
        reads = [e for e in profile.extractions if e.operation == "read"]
        if not reads:
            continue

        is_collection_isolated = (
            profile.isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT
        )

        store_verifications = by_store.get(profile.store_id, [])

        verified: list[VerifiedPath] = []
        violated: list[ViolatedPath] = []
        unknown: list[UnknownPath] = []

        if is_collection_isolated:
            for v in store_verifications:
                entry_file, entry_line = _location(v)
                verified.append(VerifiedPath(entry_file=entry_file, entry_line=entry_line))
            # If no verifications were emitted (e.g. no explicit read extractions tracked),
            # fall back to one VerifiedPath per read extraction.
            if not store_verifications:
                for ext in reads:
                    verified.append(VerifiedPath(entry_file=ext.file, entry_line=ext.line))
        else:
            for v in store_verifications:
                entry_file, entry_line = _location(v)
                if v.verdict == Verdict.VERIFIED:
                    verified.append(VerifiedPath(entry_file=entry_file, entry_line=entry_line))
                elif v.verdict == Verdict.VIOLATED:
                    violated.append(
                        ViolatedPath(
                            entry_file=entry_file,
                            entry_line=entry_line,
                            violation_file=entry_file,
                            violation_line=entry_line,
                        )
                    )
                else:
                    unknown.append(
                        UnknownPath(
                            entry_file=entry_file,
                            entry_line=entry_line,
                            reason="unresolved",
                        )
                    )

        total = len(verified) + len(violated) + len(unknown)

        results.append(
            PathCoverage(
                store_id=profile.store_id,
                property=SecurityProperty.TENANT_ISOLATION,
                total_paths=total,
                verified_paths=verified,
                violated_paths=violated,
                unknown_paths=unknown,
            )
        )

    return results


def _location(v: PropertyVerification) -> tuple[Path, int]:
    """Extract file and line from a PropertyVerification, with safe defaults."""
    file = v.file if v.file is not None else Path("<unknown>")
    line = v.line if v.line is not None else 0
    return file, line
