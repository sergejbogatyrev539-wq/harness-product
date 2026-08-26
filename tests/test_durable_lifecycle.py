"""M3 durable pre-exec session regressions.

These tests intentionally use the M2 fixture verifier only as a test boundary.
No test starts a worker or performs a target filesystem effect.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from harness_product.durable import DurableOutcome, DurableReason, DurableStore
import harness_product.durable as durable_module

from tests import test_durable as m2


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _bindings(claim_digest: str) -> dict[str, object]:
    root = {
        "kind": "ROOTFS", "descriptor": 10, "descriptor_id": "rootfs-1",
        "device": 1, "inode": 10, "mount_id": 20, "mode": 0o555, "type": "DIRECTORY",
    }
    worker_endpoint = {
        "kind": "BROKER_IPC_WORKER_END", "descriptor": 11,
        "descriptor_id": "worker-pair-end-1", "device": 1, "inode": 11,
        "cookie": 101, "type": "SOCKET", "family": "AF_UNIX",
        "socket_type": "SOCK_SEQPACKET", "address_mode": "ANONYMOUS_CONNECTED",
        "pass_credentials": False, "creation_peer": {"pid": 100, "uid": 1000, "gid": 1000},
    }
    broker_endpoint = {
        "kind": "BROKER_IPC_BROKER_END", "descriptor": 20,
        "descriptor_id": "broker-pair-end-1", "device": 1, "inode": 20,
        "cookie": 102, "type": "SOCKET", "family": "AF_UNIX",
        "socket_type": "SOCK_SEQPACKET", "address_mode": "ANONYMOUS_CONNECTED",
        "pass_credentials": True, "creation_peer": {"pid": 100, "uid": 1000, "gid": 1000},
    }
    seccomp = {
        "kind": "SECCOMP_PROFILE", "descriptor": 12, "descriptor_id": "seccomp-1",
        "device": 1, "inode": 12, "mount_id": 20, "mode": 0o444, "type": "REGULAR",
        "size": 10, "bytes_digest": _digest("c"),
    }
    tool = {
        "kind": "WORKER_TOOL", "descriptor": 13, "descriptor_id": "tool-1",
        "device": 1, "inode": 13, "mount_id": 20, "mode": 0o555, "type": "REGULAR",
        "size": 10, "bytes_digest": _digest("d"),
    }
    user_namespace = {
        "kind": "USER_NAMESPACE", "descriptor": 9, "descriptor_id": "userns-1",
        "device": 1, "inode": 9, "identity": "user:[9]",
        "uid_map": "0 100000 1\n1001 3001 1\n",
        "gid_map": "0 200000 1\n2001 4001 1\n",
        "setgroups": "deny", "max_user_namespaces": 0, "type": "NAMESPACE",
    }
    broker = {
        "kind": "UNIX_CONNECTED_PAIR", "endpoint_mode": "UNIX_CONNECTED_PAIR",
        "transport": "UNIX_SEQPACKET", "worker_endpoint": "worker-endpoint",
        "broker_endpoint": "broker-endpoint", "worker_principal": "worker-1",
        "broker_principal": "broker-1", "worker_session": "session-0001",
        "broker_session": "broker-session-1", "worker_security_label": "label-1",
        "broker_security_label": "label-2", "worker_socket_identity": worker_endpoint,
        "broker_socket_identity": broker_endpoint, "operation_id": "operation-1",
        "nonce": "nonce-0001", "fencing_epoch": 11, "revocation_epoch": 7,
        "issued_at": "2026-08-25T12:00:00Z", "expires_at": "2026-08-25T12:04:00Z",
        "sender_authentication": "SCM_CREDENTIALS_PLUS_ENDPOINT_HOLDER_ATTESTATION",
        "message_binding_digest": _digest("3"),
    }
    broker["pair_binding_digest"] = durable_module.canonical_digest(broker)
    return {
        "binding_version": 1,
        "process": {
            "session_record_id": "session-record-1", "process_tree_id": "tree-0001",
            "transaction_id": "transaction-0001",
            "claim_digest": claim_digest, "lineage_root": m2.LINEAGE,
            "session_id": "session-0001", "subject_instance_id": "worker-instance-1",
            "worker_principal": "worker-1", "broker_principal": "broker-1",
            "executor_principal": "executor-1", "broker_session": "broker-session-1",
            "executor_session": "executor-session-1", "fencing_epoch": 11,
            "revocation_epoch": 7, "profile_digest": _digest("6"),
            "measurement_digest": _digest("a"), "supply_digest": _digest("b"),
            "placement_digest": _digest("7"), "runtime_digest": _digest("e"),
        },
        "namespaces": {
            "worker_principal": "worker-1", "worker_session": "session-0001", "uid": 1001,
            "gid": 2001, "security_label": "label-1", "credential_namespace": "credentials-1",
            "namespace_ids": {
                "user": "user-ns-1", "mount": "mount-ns-1", "pid": "pid-ns-1",
                "ipc": "ipc-ns-1", "uts": "uts-ns-1", "network": "network-ns-1",
                "cgroup": "cgroup-ns-1",
            },
            "user_namespace_binding_digest": durable_module.canonical_digest(user_namespace),
        },
        "cgroup": {
            "path": "/delegated/session-1", "controllers": ["cpu", "io", "memory", "pids"],
            "device_major": 259, "device_minor": 2, "delegated": True,
            "identity_digest": _digest("f"),
        },
        "mounts": {
            "rootfs": root, "read_only_inputs": [], "worker_writable_mounts": [],
            "staging_visible_to_worker": False,
        },
        "writable_scope": {
            "root_id": "staging-root-1", "root_identity": _digest("1"), "mount_id": "mnt:42",
            "mount_identity": _digest("2"), "files": 8, "inodes": 8, "bytes": 10,
        },
        "broker_ipc": broker,
        "fd_allowlist": [
            user_namespace,
            root,
            worker_endpoint,
            broker_endpoint,
            seccomp,
            tool,
            {"kind": "START_GATE", "descriptor": 14, "device": 1, "inode": 14, "type": "PIPE"},
            {"kind": "START_GATE_RELEASE", "descriptor": 15, "device": 1, "inode": 14, "type": "PIPE"},
            {"kind": "WORKER_START_GATE", "descriptor": 16, "device": 1, "inode": 16, "type": "PIPE"},
            {"kind": "WORKER_START_RELEASE", "descriptor": 17, "device": 1, "inode": 16, "type": "PIPE"},
            {"kind": "STATUS_SOURCE", "descriptor": 18, "device": 1, "inode": 18, "type": "PIPE"},
            {"kind": "STATUS_SINK", "descriptor": 19, "device": 1, "inode": 18, "type": "PIPE"},
        ],
        "cleanup": {
            "cleanup_id": "cleanup-1", "staging_root_id": "staging-root-1",
            "reuse_forbidden": True, "require_cgroup_empty": True, "quarantine_on_failure": True,
        },
    }


def _prepare_raw(claim_digest: str) -> dict[str, object]:
    bindings = _bindings(claim_digest)
    return {
        "session_record_id": "session-record-1",
        "transaction_id": "transaction-0001",
        "observed_at": "2026-08-25T12:03:00Z",
        "executor_id": "executor-1",
        "profile_digest": _digest("6"),
        "placement_digest": _digest("7"),
        "session_id": "session-0001",
        "fencing_epoch": 11,
        "runtime_bindings": bindings,
        "runtime_verification": m2._verification_source(),
    }


class DurableLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "lifecycle.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self, *, runtime: object | None = None, fault: object | None = None) -> DurableStore:
        verifier = m2.ExactVerifier()
        return DurableStore(
            str(self.path),
            m2.ExactVerifier(),
            no_effect_verifier=m2.ExactNoEffectVerifier(),
            executor_claim_verifier=verifier,
            runtime_session_verifier=verifier if runtime is None else (None if runtime is False else runtime),
            _fault=fault,
        )

    def claimed(self, store: DurableStore) -> dict[str, object]:
        self.assertTrue(store.bootstrap(m2._bootstrap_raw()).committed)
        issued = store.issue(m2._issue_raw())
        self.assertTrue(issued.committed)
        with sqlite3.connect(self.path) as connection:
            payload = json.loads(connection.execute("SELECT payload_json FROM capabilities").fetchone()[0])
        self.assertTrue(store.consume(m2._consume_from_payload(issued.capability_id, payload)).committed)
        claimed = store.claim_dispatch(m2._claim_raw())
        self.assertTrue(claimed.committed)
        self.assertIsNotNone(claimed.dispatch_claim)
        return _prepare_raw(claimed.dispatch_claim.claim_digest)

    def test_prepare_is_durable_evented_recoverable_and_never_a_retry(self) -> None:
        store = self.store()
        raw = self.claimed(store)
        prepared = store.prepare_runtime_session(raw)
        self.assertEqual(
            (prepared.outcome, prepared.reason, prepared.journal_sequence),
            (DurableOutcome.COMMITTED, DurableReason.RUNTIME_SESSION_PREPARED, 5),
        )
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT state FROM execution_sessions").fetchone(), ("PREPARED",))
            self.assertEqual(
                connection.execute("SELECT event_type FROM outbox_events WHERE sequence=5").fetchone(),
                ("RUNTIME_SESSION_PREPARED",),
            )
        recovered = self.store().recover()
        self.assertEqual(recovered.recovery_intents[0].state, "RUNTIME_SESSION_PREPARED")
        self.assertEqual(recovered.recovery_sessions[0].state, "PREPARED")
        replay = self.store().prepare_runtime_session(raw)
        self.assertEqual((replay.outcome, replay.reason), (DurableOutcome.DENY, DurableReason.REPLAY))

    def test_closed_and_mismatched_prepare_inputs_leave_no_partial_session(self) -> None:
        store = self.store()
        raw = self.claimed(store)
        cases = ({}, {**raw, "unknown": True})
        mismatched = deepcopy(raw)
        mismatched["runtime_bindings"]["process"]["placement_digest"] = _digest("1")
        cases += (mismatched,)
        for raw in cases:
            with self.subTest(raw=raw):
                result = store.prepare_runtime_session(raw)
                self.assertIn(result.outcome, {DurableOutcome.DENY, DurableOutcome.STOP})
                with sqlite3.connect(self.path) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone(), (0,))

    def test_bound_worker_start_pipe_is_mandatory_unique_and_pairwise_exact(self) -> None:
        for mutation in ("missing", "duplicate_kind", "wrong_pair", "shared_pipe"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                self.path = Path(directory) / "lifecycle.sqlite3"
                store = self.store()
                raw = self.claimed(store)
                inventory = raw["runtime_bindings"]["fd_allowlist"]
                if mutation == "missing":
                    inventory[:] = [row for row in inventory if row["kind"] != "WORKER_START_GATE"]
                elif mutation == "duplicate_kind":
                    inventory[-1]["kind"] = "WORKER_START_RELEASE"
                elif mutation == "wrong_pair":
                    next(row for row in inventory if row["kind"] == "WORKER_START_RELEASE")["inode"] = 20
                else:
                    next(row for row in inventory if row["kind"] == "WORKER_START_GATE")["inode"] = 14
                    next(row for row in inventory if row["kind"] == "WORKER_START_RELEASE")["inode"] = 14
                result = store.prepare_runtime_session(raw)
                self.assertEqual((result.outcome, result.reason), (DurableOutcome.STOP, DurableReason.MALFORMED_INPUT))
                with sqlite3.connect(self.path) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone(), (0,))

    def test_connected_pair_record_is_closed_exact_and_substitution_resistant(self) -> None:
        mutations = (
            "legacy_path", "missing_endpoint", "wrong_kind", "wrong_type", "wrong_transport",
            "wrong_cookie", "duplicate_descriptor", "passcred_disabled", "worker_principal",
            "stale_pair_digest",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                self.path = Path(directory) / "lifecycle.sqlite3"
                store = self.store()
                raw = self.claimed(store)
                broker = raw["runtime_bindings"]["broker_ipc"]
                inventory = raw["runtime_bindings"]["fd_allowlist"]
                if mutation == "legacy_path":
                    raw["runtime_bindings"]["broker_ipc"] = {
                        "kind": "BROKER_IPC_ROOT", "descriptor": 11,
                        "descriptor_id": "broker-root-1", "device": 1, "inode": 11,
                        "mount_id": 20, "mode": 0o555, "type": "DIRECTORY",
                    }
                elif mutation == "missing_endpoint":
                    del broker["broker_socket_identity"]
                elif mutation == "wrong_kind":
                    broker["worker_socket_identity"]["kind"] = "BROKER_IPC_ROOT"
                elif mutation == "wrong_type":
                    broker["worker_socket_identity"]["socket_type"] = "SOCK_STREAM"
                elif mutation == "wrong_transport":
                    broker["transport"] = "UNIX_STREAM"
                elif mutation == "wrong_cookie":
                    broker["worker_socket_identity"]["cookie"] = broker["broker_socket_identity"]["cookie"]
                elif mutation == "duplicate_descriptor":
                    broker["broker_socket_identity"]["descriptor"] = broker["worker_socket_identity"]["descriptor"]
                elif mutation == "passcred_disabled":
                    broker["broker_socket_identity"]["pass_credentials"] = False
                elif mutation == "worker_principal":
                    broker["worker_principal"] = "other-worker"
                else:
                    broker["pair_binding_digest"] = _digest("9")
                result = store.prepare_runtime_session(raw)
                self.assertEqual((result.outcome, result.reason), (DurableOutcome.STOP, DurableReason.MALFORMED_INPUT))
                with sqlite3.connect(self.path) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone(), (0,))

    def test_missing_runtime_verifier_is_stop_without_record(self) -> None:
        store = self.store(runtime=False)
        raw = self.claimed(store)
        result = store.prepare_runtime_session(raw)
        self.assertEqual((result.outcome, result.reason), (DurableOutcome.STOP, DurableReason.RUNTIME_VERIFIER_ABSENT))
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone(), (0,))

    def test_prepare_fault_rolls_back_and_post_commit_ack_is_recoverable(self) -> None:
        fault = m2.FaultAt("runtime_session_after_event")
        store = self.store(fault=fault)
        raw = self.claimed(store)
        result = store.prepare_runtime_session(raw)
        self.assertEqual((result.outcome, result.reason), (DurableOutcome.STOP, DurableReason.INTERNAL_ERROR))
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone(), (0,))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM journal_entries").fetchone(), (4,))

        fault = m2.FaultAt("runtime_session_after_commit_before_ack")
        store = self.store(fault=fault)
        result = store.prepare_runtime_session(raw)
        self.assertEqual((result.outcome, result.reason), (DurableOutcome.STOP, DurableReason.ACKNOWLEDGEMENT_UNKNOWN))
        self.assertEqual(self.store().recover().recovery_sessions[0].state, "PREPARED")

    def test_stop_verified_no_effect_releases_once_timeout_quarantines(self) -> None:
        store = self.store()
        raw = self.claimed(store)
        self.assertTrue(store.prepare_runtime_session(raw).committed)
        released = store.finalize_runtime_session(
            {
                "session_record_id": "session-record-1",
                "observed_at": "2026-08-25T12:03:30Z",
                "state": "STOPPED",
                "evidence": {
                    "verifier_id": "test-no-effect/v1",
                    "observer_id": "observer-1",
                    "key_id": "key-1",
                    "proof": _digest("9"),
                },
            }
        )
        self.assertEqual((released.outcome, released.reason), (DurableOutcome.COMMITTED, DurableReason.RELEASED))
        self.assertEqual(
            store.finalize_runtime_session(
                {
                    "session_record_id": "session-record-1", "observed_at": "2026-08-25T12:03:31Z",
                    "state": "STOPPED", "evidence": {
                        "verifier_id": "test-no-effect/v1", "observer_id": "observer-1",
                        "key_id": "key-1", "proof": _digest("9"),
                    },
                }
            ).reason,
            DurableReason.ILLEGAL_TRANSITION,
        )
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT remaining, reserved, spent FROM budgets").fetchone(), (10, 0, 0))

        # A separate intent/session would be needed to demonstrate a second terminal
        # path; this direct mutation regression proves timeout cannot downgrade a
        # completed release into an effectful retry.
        mutated = deepcopy(raw)
        mutated["session_record_id"] = "session-record-2"
        mutated["runtime_bindings"]["process"]["session_record_id"] = "session-record-2"
        self.assertEqual(store.prepare_runtime_session(mutated).reason, DurableReason.REPLAY)

    def test_timeout_quarantines_and_session_binding_mutation_fails_closed(self) -> None:
        store = self.store()
        raw = self.claimed(store)
        self.assertTrue(store.prepare_runtime_session(raw).committed)
        timed_out = store.finalize_runtime_session(
            {
                "session_record_id": "session-record-1",
                "observed_at": "2026-08-25T12:03:30Z",
                "state": "TIMED_OUT",
                "evidence": {"evidence_digest": _digest("9")},
            }
        )
        self.assertEqual(
            (timed_out.outcome, timed_out.reason),
            (DurableOutcome.COMMITTED, DurableReason.QUARANTINED_ESCROW),
        )
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("SELECT remaining, reserved, spent FROM budgets").fetchone(), (9, 1, 0))

        # A session record is part of the authority chain: a local row mutation,
        # even before attempting to rewrite external evidence, is terminally STOP.
        self.path = Path(self.temporary.name) / "mutation.sqlite3"
        store = self.store()
        raw = self.claimed(store)
        self.assertTrue(store.prepare_runtime_session(raw).committed)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "UPDATE execution_sessions SET runtime_bindings_json='{}' WHERE session_record_id='session-record-1'"
            )
        self.assertEqual(self.store().health().reason, DurableReason.CORRUPT_STORE)

    def test_empty_exact_v1_and_v2_schema_migrate_to_v3_without_intermediate_state(self) -> None:
        for version, schema in ((1, durable_module._SCHEMA_V1), (2, durable_module._SCHEMA_V2)):
            with self.subTest(version=version):
                self.path = Path(self.temporary.name) / f"migration-{version}.sqlite3"
                with sqlite3.connect(self.path) as connection:
                    for statement in schema:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO store_meta VALUES (1, ?, NULL, 0, 0, 0, 0, NULL, 0, NULL)",
                        (version,),
                    )
                    connection.execute(f"PRAGMA application_id={durable_module._APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={version}")
                migrated = self.store()
                self.assertEqual(migrated.health().reason, DurableReason.READY)
                with sqlite3.connect(self.path) as connection:
                    self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (3,))
                    self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone(), (3,))
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone(), (0,))


if __name__ == "__main__":
    unittest.main()
