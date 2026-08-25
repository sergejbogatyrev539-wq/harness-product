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
    decide,
)
from harness_product.kernel import _DispatchOrder


class KernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = Principal("worker-1", PrincipalRole.WORKER)
        self.executor = Principal("executor-1", PrincipalRole.EXECUTOR)
        self.request = Request(
            operation_id="write-report/v1",
            principal=self.worker,
            effect=EffectKind.MUTATE,
            resource=ResourceKind.FILE,
            selector=Selector(SelectorKind.PATH_EXACT, "workspace/report.txt"),
            material_digest="sha256:" + "a" * 64,
        )
        self.manifest = Manifest("write-report/v1", frozenset({EffectKind.MUTATE}), ResourceKind.FILE)
        self.policy = Policy(frozenset({EffectKind.MUTATE}))
        self.broker = Broker(self.executor, frozenset({EffectKind.MUTATE}))

    def issue(self):
        decision, capability = self.broker.authorize(self.request, self.manifest, self.policy)
        self.assertEqual(decision.outcome, Outcome.ALLOW)
        self.assertIsNotNone(capability)
        return capability

    def test_deny_by_default_for_malformed_input(self) -> None:
        decision = decide({}, self.manifest, self.policy, frozenset({EffectKind.MUTATE}))
        self.assertEqual((decision.outcome, decision.reason), (Outcome.STOP, Reason.MALFORMED_INPUT))

    def test_malformed_physical_ceiling_stops_without_throwing(self) -> None:
        decision = decide(self.request, self.manifest, self.policy, None)
        self.assertEqual((decision.outcome, decision.reason), (Outcome.STOP, Reason.MALFORMED_INPUT))
        malformed_broker = Broker(self.executor, None)
        decision, capability = malformed_broker.authorize(self.request, self.manifest, self.policy)
        self.assertEqual((decision.outcome, capability), (Outcome.STOP, None))
        malformed_principal_broker = Broker(object(), frozenset({EffectKind.MUTATE}))
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

    def test_executor_has_no_direct_raw_dispatch_path(self) -> None:
        receipt = self.broker._executor.dispatch(self.request)
        self.assertFalse(receipt.executed)
        self.assertEqual(receipt.reason, Reason.NO_DIRECT_DISPATCH)

    def test_capability_is_exactly_bound_to_scope(self) -> None:
        capability = self.issue()
        changed = Request(
            operation_id=self.request.operation_id,
            principal=self.worker,
            effect=self.request.effect,
            resource=self.request.resource,
            selector=Selector(SelectorKind.PATH_EXACT, "workspace/other.txt"),
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
            selector=Selector(SelectorKind.ENDPOINT_EXACT, "workspace/report.txt"),
            material_digest="sha256:" + "a" * 64,
        )
        decision, capability = self.broker.authorize(invalid, self.manifest, self.policy)
        self.assertEqual(decision.reason, Reason.TYPED_SCOPE_MISMATCH)
        self.assertIsNone(capability)

    def test_executor_rejects_unconsumed_and_mismatched_orders(self) -> None:
        capability = self.issue()
        unconsumed = _DispatchOrder(self.request, capability, 0, self.broker._broker_key)
        self.assertEqual(self.broker._executor.dispatch(unconsumed).reason, Reason.CAPABILITY_UNCONSUMED)

        self.assertTrue(self.broker.dispatch(self.request, capability).executed)
        changed = Request(
            self.request.operation_id,
            self.worker,
            self.request.effect,
            self.request.resource,
            Selector(SelectorKind.PATH_EXACT, "workspace/other.txt"),
            self.request.material_digest,
        )
        mismatched = _DispatchOrder(changed, capability, self.broker.journal_sequence, self.broker._broker_key)
        self.assertEqual(self.broker._executor.dispatch(mismatched).reason, Reason.CAPABILITY_BINDING_MISMATCH)

    def test_direct_journal_issuance_is_not_public_and_rejects_wrong_authority(self) -> None:
        self.assertFalse(hasattr(self.broker, "journal"))
        result = self.broker._journal._issue(self.request, self.executor, object())
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
