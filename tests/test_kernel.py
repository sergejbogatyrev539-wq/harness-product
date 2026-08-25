from __future__ import annotations

from copy import deepcopy
import unittest

from harness_product import (
    ClassifiedInput,
    Decision,
    DerivedAuthority,
    NormalizedInput,
    Outcome,
    Reason,
    Stage,
    classify,
    derive,
    normalize,
)


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def clause(
    *,
    effect: str = "MUTATE",
    resource: str = "FILE",
    operation: str = "WRITE",
    selector_kind: str = "PATH_PREFIX",
    selector_value: str = "/project/reports",
    facets: list[str] | None = None,
    not_before: str = "2026-08-25T00:00:00Z",
    not_after: str = "2026-08-26T00:00:00Z",
    max_duration_ms: int = 60_000,
    quantity_unit: str = "FILES",
    max_quantity: int = 10,
    max_concurrency: int = 4,
) -> dict[str, object]:
    return {
        "effect": effect,
        "resource": resource,
        "operation": operation,
        "selector": {"kind": selector_kind, "value": selector_value},
        "facets": ["EXECUTE_EFFECT"] if facets is None else facets,
        "not_before": not_before,
        "not_after": not_after,
        "max_duration_ms": max_duration_ms,
        "quantity_unit": quantity_unit,
        "max_quantity": max_quantity,
        "max_concurrency": max_concurrency,
    }


def raw_input() -> dict[str, object]:
    requested = clause(
        selector_kind="PATH_EXACT",
        selector_value="/project/reports/report.txt",
        not_before="2026-08-25T11:00:00Z",
        not_after="2026-08-25T13:00:00Z",
        max_duration_ms=30_000,
        max_quantity=1,
        max_concurrency=2,
    )
    bound = clause()
    source = {"operation_id": "write-report/v1", "authority": [bound]}
    return {
        "evaluation_time": "2026-08-25T12:00:00Z",
        "proposal": {
            "operation_id": "write-report/v1",
            "principal_id": "worker-1",
            "material_digest": DIGEST_A,
            "authority": requested,
        },
        "manifest": deepcopy(source),
        "policy": deepcopy(source),
        "physical_ceiling": deepcopy(source),
        "trusted_facts": {
            "operation_id": "write-report/v1",
            "material_digest": DIGEST_A,
            "observed_at": "2026-08-25T11:59:00Z",
            "expires_at": "2026-08-25T12:05:00Z",
            "authority": [deepcopy(bound)],
        },
    }


class KernelStagesTests(unittest.TestCase):
    def assert_failure(
        self,
        result: object,
        outcome: Outcome,
        reason: Reason,
        stage: Stage,
    ) -> Decision:
        self.assertIs(type(result), Decision)
        self.assertEqual((result.outcome, result.reason, result.stage), (outcome, reason, stage))
        self.assertIsNone(result.proposal_digest)
        self.assertEqual(result.proposals, ())
        self.assertRegex(result.decision_digest, r"^sha256:[0-9a-f]{64}$")
        return result

    def pipeline_to_classified(self, raw: object) -> ClassifiedInput:
        normalized = normalize(raw)
        self.assertIs(type(normalized), NormalizedInput)
        classified = classify(normalized)
        self.assertIs(type(classified), ClassifiedInput)
        return classified

    def test_positive_normalize_classify_derive_is_deterministic_and_pure(self) -> None:
        raw = raw_input()
        extra = clause(
            effect="OBSERVE",
            resource="MEMORY",
            operation="READ",
            selector_kind="LOCAL_EXACT",
            selector_value="memory-session",
            quantity_unit="BYTES",
        )
        for name in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
            raw[name]["authority"].append(deepcopy(extra))
        snapshot = deepcopy(raw)

        normalized = normalize(raw)
        self.assertIs(type(normalized), NormalizedInput)
        reordered = deepcopy(raw)
        for name in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
            reordered[name]["authority"].reverse()
        self.assertEqual(normalized, normalize(reordered))
        self.assertEqual(raw, snapshot)

        classified = classify(normalized)
        self.assertIs(type(classified), ClassifiedInput)
        derived = derive(classified)
        self.assertIs(type(derived), DerivedAuthority)
        self.assertEqual(derived.effective, normalized.proposal.authority)
        self.assertEqual(len(derived.source_clause_digests), 4)
        self.assertTrue(all(item.startswith("sha256:") for item in derived.source_clause_digests))
        self.assertEqual(derived, derive(classified))
        self.assertEqual(raw, snapshot)

    def test_logical_paths_are_not_tied_to_one_project_root(self) -> None:
        for root in ("/srv/customer-a", "/opt/product-b/repository"):
            raw = raw_input()
            raw["proposal"]["authority"]["selector"]["value"] = root + "/out/report.txt"
            for name in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
                raw[name]["authority"][0]["selector"]["value"] = root + "/out"
            result = derive(self.pipeline_to_classified(raw))
            self.assertIs(type(result), DerivedAuthority)

    def test_closed_normalization_rejects_missing_extra_unknown_and_unbounded_mutations(self) -> None:
        cases: list[tuple[dict[str, object], Reason]] = []

        missing = raw_input()
        del missing["policy"]
        cases.append((missing, Reason.MALFORMED_INPUT))

        extra = raw_input()
        extra["ambient_authority"] = True
        cases.append((extra, Reason.MALFORMED_INPUT))

        unknown = raw_input()
        unknown["proposal"]["authority"]["effect"] = "TRANSFORM"
        cases.append((unknown, Reason.UNKNOWN_INPUT))

        unbounded_quantity = raw_input()
        unbounded_quantity["proposal"]["authority"]["max_quantity"] = None
        cases.append((unbounded_quantity, Reason.UNBOUNDED_INPUT))

        unbounded_facets = raw_input()
        unbounded_facets["manifest"]["authority"][0]["facets"] = []
        cases.append((unbounded_facets, Reason.UNBOUNDED_INPUT))

        bool_bound = raw_input()
        bool_bound["proposal"]["authority"]["max_duration_ms"] = True
        cases.append((bool_bound, Reason.MALFORMED_INPUT))

        bad_path = raw_input()
        bad_path["proposal"]["authority"]["selector"]["value"] = "/project/reports/../escape"
        cases.append((bad_path, Reason.MALFORMED_INPUT))

        no_expiry = raw_input()
        no_expiry["trusted_facts"]["expires_at"] = None
        cases.append((no_expiry, Reason.UNBOUNDED_INPUT))

        duplicate = raw_input()
        duplicate["manifest"]["authority"].append(deepcopy(duplicate["manifest"]["authority"][0]))
        cases.append((duplicate, Reason.MALFORMED_INPUT))

        for mutated, reason in cases:
            with self.subTest(reason=reason, mutation=mutated):
                self.assert_failure(normalize(mutated), Outcome.STOP, reason, Stage.NORMALIZE)

    def test_hostile_python_objects_do_not_escape_the_public_stage_api(self) -> None:
        class ExplodingStr(str):
            def __len__(self):
                raise AssertionError("must not inspect subclasses")

        class ExplodingDict(dict):
            def keys(self):
                raise AssertionError("must not inspect subclasses")

        raw = raw_input()
        raw["proposal"]["operation_id"] = ExplodingStr("write-report/v1")
        self.assert_failure(normalize(raw), Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)
        self.assert_failure(normalize(ExplodingDict(raw_input())), Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)
        self.assert_failure(classify(object()), Outcome.STOP, Reason.MALFORMED_INPUT, Stage.CLASSIFY)
        self.assert_failure(derive(object()), Outcome.STOP, Reason.MALFORMED_INPUT, Stage.DERIVE)

        cyclic = raw_input()
        cyclic["proposal"] = cyclic
        self.assert_failure(normalize(cyclic), Outcome.STOP, Reason.MALFORMED_INPUT, Stage.NORMALIZE)

    def test_classification_rejects_cross_pairs_and_selector_kind_mismatch(self) -> None:
        cross_pair = raw_input()
        cross_pair["proposal"]["authority"]["operation"] = "READ"
        normalized = normalize(cross_pair)
        self.assertIs(type(normalized), NormalizedInput)
        self.assert_failure(classify(normalized), Outcome.STOP, Reason.UNKNOWN_INPUT, Stage.CLASSIFY)

        typed_mismatch = raw_input()
        typed_mismatch["proposal"]["authority"]["selector"] = {
            "kind": "ENDPOINT_EXACT",
            "value": "https://example.invalid/report",
        }
        normalized = normalize(typed_mismatch)
        self.assertIs(type(normalized), NormalizedInput)
        self.assert_failure(classify(normalized), Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH, Stage.CLASSIFY)

    def test_binding_and_freshness_mutations_stop_before_derivation(self) -> None:
        mutations: list[tuple[dict[str, object], Reason]] = []
        for source in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
            raw = raw_input()
            raw[source]["operation_id"] = "different/v1"
            mutations.append((raw, Reason.BINDING_MISMATCH))

        material = raw_input()
        material["trusted_facts"]["material_digest"] = DIGEST_B
        mutations.append((material, Reason.BINDING_MISMATCH))

        stale_facts = raw_input()
        stale_facts["trusted_facts"]["expires_at"] = "2026-08-25T12:00:00Z"
        mutations.append((stale_facts, Reason.STALE_INPUT))

        stale_proposal = raw_input()
        stale_proposal["proposal"]["authority"]["not_after"] = "2026-08-25T12:00:00Z"
        mutations.append((stale_proposal, Reason.STALE_INPUT))

        for mutated, reason in mutations:
            with self.subTest(reason=reason):
                normalized = normalize(mutated)
                self.assertIs(type(normalized), NormalizedInput)
                self.assert_failure(classify(normalized), Outcome.STOP, reason, Stage.CLASSIFY)

    def test_every_authority_source_must_cover_the_typed_selector(self) -> None:
        for source in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
            raw = raw_input()
            raw[source]["authority"][0]["selector"]["value"] = "/different/root"
            result = derive(self.pipeline_to_classified(raw))
            self.assert_failure(result, Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH, Stage.DERIVE)

        boundary = raw_input()
        boundary["proposal"]["authority"]["selector"]["value"] = "/project/reports-old/file.txt"
        result = derive(self.pipeline_to_classified(boundary))
        self.assert_failure(result, Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH, Stage.DERIVE)

    def test_each_correlated_bound_can_only_narrow_the_proposal(self) -> None:
        field_mutations = (
            ("max_duration_ms", 1_000),
            ("max_quantity", 0),
            ("max_concurrency", 1),
            ("quantity_unit", "BYTES"),
            ("not_after", "2026-08-25T12:30:00Z"),
            ("facets", ["AUTHORIZE_EFFECT"]),
        )
        for source in ("manifest", "policy", "physical_ceiling", "trusted_facts"):
            for field, replacement in field_mutations:
                with self.subTest(source=source, field=field):
                    raw = raw_input()
                    raw[source]["authority"][0][field] = replacement
                    result = derive(self.pipeline_to_classified(raw))
                    self.assert_failure(result, Outcome.DENY, Reason.AUTHORITY_EXCEEDED, Stage.DERIVE)

    def test_independently_valid_atoms_cannot_form_a_cross_source_union(self) -> None:
        raw = raw_input()
        raw["policy"]["authority"] = [
            clause(
                effect="OBSERVE",
                resource="FILE",
                operation="READ",
                selector_value="/project/reports",
            )
        ]
        result = derive(self.pipeline_to_classified(raw))
        self.assert_failure(result, Outcome.DENY, Reason.AUTHORITY_EXCEEDED, Stage.DERIVE)


if __name__ == "__main__":
    unittest.main()
