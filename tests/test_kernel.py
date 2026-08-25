import unittest

from harness_product import (
    Broker,
    CapabilityState,
    EffectKind,
    Manifest,
    Outcome,
    Policy,
    Principal,
    PrincipalRole,
    Reason,
    Request,
    ResourceKind,
    Selector,
    SelectorKind,
    ScopeBound,
    decide,
)


class KernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = Principal("worker-1", PrincipalRole.WORKER)
        self.executor = Principal("executor-1", PrincipalRole.EXECUTOR)
        self.request = Request(
            operation_id="write-report/v1",
            principal=self.worker,
            effect=EffectKind.MUTATE,
            resource=ResourceKind.FILE,
            selector=Selector(SelectorKind.PATH_EXACT, "/workspace/reports/report.txt"),
            material_digest="sha256:" + "a" * 64,
        )
        self.bound = ScopeBound(
            EffectKind.MUTATE,
            ResourceKind.FILE,
            Selector(SelectorKind.PATH_PREFIX, "/workspace/reports"),
        )
        self.manifest = Manifest("write-report/v1", frozenset({self.bound}))
        self.policy = Policy(frozenset({self.bound}))
        self.broker = Broker(self.executor, frozenset({self.bound}))

    def issue(self):
        decision, capability = self.broker.authorize(self.request, self.manifest, self.policy)
        self.assertEqual(decision.outcome, Outcome.ALLOW)
        self.assertIsNotNone(capability)
        return capability

    def test_deny_by_default_for_malformed_input(self) -> None:
        decision = decide({}, self.manifest, self.policy, frozenset({self.bound}))
        self.assertEqual((decision.outcome, decision.reason), (Outcome.STOP, Reason.MALFORMED_INPUT))

    def test_malformed_physical_ceiling_stops_without_throwing(self) -> None:
        decision = decide(self.request, self.manifest, self.policy, None)
        self.assertEqual((decision.outcome, decision.reason), (Outcome.STOP, Reason.MALFORMED_INPUT))
        malformed_broker = Broker(self.executor, None)
        decision, capability = malformed_broker.authorize(self.request, self.manifest, self.policy)
        self.assertEqual((decision.outcome, capability), (Outcome.STOP, None))
        malformed_principal_broker = Broker(object(), frozenset({self.bound}))
        decision, capability = malformed_principal_broker.authorize(self.request, self.manifest, self.policy)
        self.assertEqual((decision.outcome, capability), (Outcome.STOP, None))

    def test_noncanonical_material_digest_stops(self) -> None:
        invalid = Request(
            self.request.operation_id,
            self.worker,
            self.request.effect,
            self.request.resource,
            self.request.selector,
            "material-a",
        )
        decision, capability = self.broker.authorize(invalid, self.manifest, self.policy)
        self.assertEqual((decision.outcome, capability), (Outcome.STOP, None))

    def test_capability_is_exactly_bound_to_scope(self) -> None:
        capability = self.issue()
        changed = Request(
            operation_id=self.request.operation_id,
            principal=self.worker,
            effect=self.request.effect,
            resource=self.request.resource,
            selector=Selector(SelectorKind.PATH_EXACT, "/workspace/reports/other.txt"),
            material_digest=self.request.material_digest,
        )
        receipt = self.broker.dispatch(changed, capability)
        self.assertFalse(receipt.executed)
        self.assertEqual(receipt.reason, Reason.CAPABILITY_BINDING_MISMATCH)
        self.assertEqual(self.broker.capability_state(capability), CapabilityState.ISSUED)

    def test_material_change_stops_capability_use(self) -> None:
        capability = self.issue()
        changed = Request(
            operation_id=self.request.operation_id,
            principal=self.worker,
            effect=self.request.effect,
            resource=self.request.resource,
            selector=self.request.selector,
            material_digest="sha256:" + "b" * 64,
        )
        receipt = self.broker.dispatch(changed, capability)
        self.assertFalse(receipt.executed)
        self.assertEqual(receipt.reason, Reason.CAPABILITY_BINDING_MISMATCH)

    def test_replay_is_stopped_after_single_dispatch(self) -> None:
        capability = self.issue()
        self.assertTrue(self.broker.dispatch(self.request, capability).executed)
        replay = self.broker.dispatch(self.request, capability)
        self.assertFalse(replay.executed)
        self.assertEqual(replay.reason, Reason.REPLAY)

    def test_cross_kind_scope_is_stopped(self) -> None:
        invalid = Request(
            operation_id="write-report/v1",
            principal=self.worker,
            effect=EffectKind.MUTATE,
            resource=ResourceKind.FILE,
            selector=Selector(SelectorKind.ENDPOINT_EXACT, "/workspace/reports/report.txt"),
            material_digest="sha256:" + "a" * 64,
        )
        decision, capability = self.broker.authorize(invalid, self.manifest, self.policy)
        self.assertEqual(decision.reason, Reason.TYPED_SCOPE_MISMATCH)
        self.assertIsNone(capability)

    def test_prefix_bound_contains_exact_and_nested_prefix_requests(self) -> None:
        nested = Request(
            self.request.operation_id,
            self.worker,
            self.request.effect,
            self.request.resource,
            Selector(SelectorKind.PATH_PREFIX, "/workspace/reports/drafts"),
            self.request.material_digest,
        )
        decision, capability = self.broker.authorize(nested, self.manifest, self.policy)
        self.assertEqual(decision.outcome, Outcome.ALLOW)
        self.assertIsNotNone(capability)

    def test_same_kind_path_outside_declared_bound_is_denied(self) -> None:
        outside = Request(
            self.request.operation_id,
            self.worker,
            self.request.effect,
            self.request.resource,
            Selector(SelectorKind.PATH_EXACT, "/workspace/other/report.txt"),
            self.request.material_digest,
        )
        decision, capability = self.broker.authorize(outside, self.manifest, self.policy)
        self.assertEqual((decision.outcome, decision.reason, capability), (Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH, None))

    def test_every_authority_input_must_cover_the_exact_path_scope(self) -> None:
        other_bound = ScopeBound(
            EffectKind.MUTATE,
            ResourceKind.FILE,
            Selector(SelectorKind.PATH_EXACT, "/workspace/other/report.txt"),
        )
        for manifest, policy, physical_ceiling in (
            (Manifest(self.request.operation_id, frozenset({other_bound})), self.policy, frozenset({self.bound})),
            (self.manifest, Policy(frozenset({other_bound})), frozenset({self.bound})),
            (self.manifest, self.policy, frozenset({other_bound})),
        ):
            decision = decide(self.request, manifest, policy, physical_ceiling)
            self.assertEqual((decision.outcome, decision.reason), (Outcome.DENY, Reason.TYPED_SCOPE_MISMATCH))

    def test_unknown_or_unbounded_scope_stops_before_issuance(self) -> None:
        for selector in (
            Selector(SelectorKind.PATH_EXACT, "/outside-any-profile"),
            Selector(SelectorKind.PATH_EXACT, "/workspace/reports/../escape.txt"),
            Selector(SelectorKind.PATH_EXACT, "/workspace/reports/%2e%2e/escape.txt"),
            Selector(SelectorKind.PATH_EXACT, "/workspace/reports/bad\nname.txt"),
            object(),
        ):
            request = Request(
                self.request.operation_id,
                self.worker,
                self.request.effect,
                self.request.resource,
                selector,
                self.request.material_digest,
            )
            decision, capability = self.broker.authorize(request, self.manifest, self.policy)
            self.assertEqual((decision.outcome, decision.reason, capability), (Outcome.STOP, Reason.MALFORMED_INPUT, None))

    def test_missing_scope_bound_stops_before_issuance(self) -> None:
        decision, capability = self.broker.authorize(self.request, self.manifest, Policy(frozenset()))
        self.assertEqual((decision.outcome, decision.reason, capability), (Outcome.STOP, Reason.MALFORMED_INPUT, None))


if __name__ == "__main__":
    unittest.main()
