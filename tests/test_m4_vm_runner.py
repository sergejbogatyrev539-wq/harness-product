from __future__ import annotations

import importlib.util
import inspect
import json
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles/m4-lx-a.json"
POLICY = ROOT / "profiles/m4-lx-a.apparmor"
RUNNER = ROOT / "scripts/run_m4_vm_conformance.py"
SERVICE = ROOT / "profiles/harness-m4-controller@.service"


def _module():
    specification = importlib.util.spec_from_file_location("harness_m4_vm_runner", RUNNER)
    if specification is None or specification.loader is None:
        raise AssertionError("runner module unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class M4VMRunnerContractTests(unittest.TestCase):
    @staticmethod
    def _run_state(module):
        digest = "sha256:" + "a" * 64
        candidate = "b" * 40
        receipt_keys = {
            "M4_AUTHORITY": digest,
            "OBSERVER": digest,
            "PUBLISHER": digest,
        }
        admission = {
            "candidate": candidate,
            "environment": digest,
            "attempt": 1,
            "receipt_public_key_digests": receipt_keys,
            "supply_public_key_digest": digest,
            "runtime_trust_digest": digest,
        }
        binding = {"composite_binding_digest": digest, "final_digest": digest}
        return {
            "record_version": "1.0.0",
            "phase": "PRE_RESTART_PASS",
            "identity": {
                "candidate": candidate,
                "environment": digest,
                "attempt": 1,
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "guest": {},
                "source": {"commit": candidate},
                "host_provenance": {},
            },
            "trust": {
                "profile_digest": digest,
                "m4_apparmor_digest": digest,
                "m3_apparmor_digest": digest,
                "runtime_trust_digest": digest,
                "key_admission": admission,
                "receipt_public_key_digests": receipt_keys,
                "supply_public_key_digest": digest,
                "verifier": {
                    "backend": "OPENSSL_LIBCRYPTO_SHARED",
                    "code_digest": digest,
                    "libcrypto_path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                    "libcrypto_digest": digest,
                    "independent_cryptographic_implementations": False,
                },
                "revocation_epoch": 0,
                "fencing_epoch": 1,
            },
            "durable": {
                "m4_recovery": {
                    "transaction_id": "transaction-1",
                    "state": "JOINED",
                    "contract_digest": digest,
                    "d2_frontier_digest": digest,
                    "fencing_epoch": 1,
                    "record_digest": digest,
                    "frontier_record_digest": digest,
                    "iteration": 1,
                    "frontier_attempt_cursor": 0,
                    "frontier_joined_iteration": 0,
                    "attempt_cursor": 1,
                    "joined_iteration": 1,
                    "journal_sequence": 20,
                    "intent_state": "SPENT",
                    "revocation_epoch": 0,
                    "resume_allowed": False,
                    "retry_allowed": False,
                },
                "m3_runtime_session": {
                    "session_record_id": "session-record-1",
                    "transaction_id": "transaction-1",
                    "claim_digest": digest,
                    "state": "STOPPED",
                    "fencing_epoch": 1,
                },
            },
            "publication": {
                "root": str(module.PUBLICATION_ROOT),
                "topology_digest": digest,
                "root_anchor": {"anchor_digest": digest},
                "target_binding": binding,
                "published_binding": binding,
                "artifact_digest": digest,
                "snapshot_digest": digest,
                "transport": module.SEALED_FD_ONLY,
            },
            "execution": {
                "controller_facts": {},
                "publisher_facts": {},
                "executor_facts": [{}],
                "observer_facts": [{}],
                "runtime_events": [],
                "denial_events": [{}, {}],
                "role_seccomp_digests": {},
                "m3_role_seccomp": {},
                "cleanup": {},
            },
        }

    def test_exact_profile_closes_roles_fds_keys_and_publication_topology(self) -> None:
        raw = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(
            frozenset(raw),
            {
                "profile_version", "profile_id", "assurance_scope", "backend",
                "publication", "roles", "receipt_keys", "supply_trust", "limits",
            },
        )
        self.assertEqual((raw["profile_version"], raw["profile_id"]), ("1.0.0", "M4-LX-A"))
        self.assertEqual(raw["assurance_scope"], "DEPLOYMENT_ATTESTED")
        self.assertEqual(raw["backend"], {"path": "/usr/bin/bwrap", "version": "bubblewrap 0.9.0"})
        roles = raw["roles"]
        self.assertEqual(
            frozenset(roles),
            {"WORKER", "CONTROLLER", "EXECUTOR", "OBSERVER", "PUBLISHER"},
        )
        identities = [
            (
                role["uid"], role["gid"], role["session_id"], role["security_label"],
                role["cgroup"], role["credential_namespace"], role["namespace_id"],
            )
            for role in roles.values()
        ]
        for index in range(7):
            self.assertEqual(len({identity[index] for identity in identities}), 5)
        self.assertEqual(roles["OBSERVER"]["fd_allowlist"], [0, 1, 2])
        self.assertEqual(roles["PUBLISHER"]["fd_allowlist"], [0, 1, 2])
        self.assertEqual(roles["EXECUTOR"]["fd_allowlist"], [0, 1, 2])
        self.assertEqual(roles["WORKER"]["fd_allowlist"], [0, 1])
        self.assertEqual(roles["CONTROLLER"]["fd_allowlist"], [0, 1, 2, 3])
        publication = raw["publication"]
        self.assertEqual(
            publication,
            {
                "root": "/var/lib/harness-m4-publication/anchor/publication",
                "sandbox_root": "/var/lib/harness-m4-publication/anchor/publication",
                "target": "/staging/artifact.txt",
                "parent_owner": "ROOT_SUPERVISOR",
                "root_owner": "PUBLISHER",
                "parent_writable_roles": [],
                "root_writable_roles": ["PUBLISHER"],
                "git_authority": "DENY",
                "transport": "SEALED_FD_ONLY",
            },
        )
        self.assertEqual(frozenset(raw["receipt_keys"]), {"M4_AUTHORITY", "OBSERVER", "PUBLISHER"})
        self.assertEqual(
            {entry["private_owner"] for entry in raw["receipt_keys"].values()},
            {"CONTROLLER", "OBSERVER", "PUBLISHER"},
        )
        self.assertEqual(
            raw["supply_trust"],
            {
                "trust_root_id": "harness-m4-disposable-supply-root-1",
                "signer_id": "harness-m4-supply-attestor",
                "key_id": "harness-m4-supply-ed25519-1",
                "private_owner": "ROOT_SUPERVISOR",
                "algorithm": "ED25519",
                "admission": "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
            },
        )

    def test_apparmor_has_exact_observer_and_publisher_domains(self) -> None:
        policy = POLICY.read_text(encoding="utf-8")
        self.assertIn("profile harness-m4-lx-a.observer", policy)
        self.assertIn("profile harness-m4-lx-a.publisher", policy)
        publication = "/var/lib/harness-m4-publication/anchor/publication"
        self.assertIn(publication + "/** rwk,", policy)
        self.assertIn("audit deny " + publication + "/.git/** rwkl,", policy)
        observer = policy.split("profile harness-m4-lx-a.observer", 1)[1].split(
            "profile harness-m4-lx-a.publisher", 1
        )[0]
        self.assertNotIn(publication + "/** rwk,", observer)
        self.assertNotIn("\n  /** mr,", policy)
        for forbidden in ("ux,", "pux", "PUx", "attach_disconnected", "/run/harness/broker.sock"):
            self.assertNotIn(forbidden, policy)
        for required in (
            "/inputs/m4-role.json r,",
            "/etc/harness-m4/runtime-trust.json r,",
            "/opt/harness-m3-source/src/harness_product/** r,",
            "/var/lib/harness-m4-keys/public/** r,",
            "audit deny mount,",
            "audit deny capability,",
            "audit deny change_profile,",
        ):
            self.assertGreaterEqual(policy.count(required), 2)
        publisher = policy.split("profile harness-m4-lx-a.publisher", 1)[1]
        self.assertIn("unix (getopt) type=seqpacket addr=none,", publisher)
        self.assertIn(
            "unix (receive) type=seqpacket addr=none peer=(addr=none,label=unconfined),",
            publisher,
        )
        for forbidden in (
            "unix (create", "unix (bind", "unix (listen", "unix (accept",
            "unix (connect", "network unix",
        ):
            self.assertNotIn(forbidden, publisher)
        for family in ("inet", "inet6", "netlink", "packet"):
            self.assertIn("audit deny network " + family + ",", publisher)

    def test_guest_runner_is_one_closed_runtime_boundary_without_pathname_broker_fallback(self) -> None:
        module = _module()
        self.assertEqual(module.M4_PROFILE, PROFILE)
        boundary = module.M4GuestRuntime
        for name in ("preflight", "stage", "observe", "publish", "continuity"):
            self.assertTrue(callable(getattr(boundary, name, None)))
        source = RUNNER.read_text(encoding="utf-8")
        for forbidden in (
            "/run/harness/broker.sock", "--broker-socket", "socket.bind(",
            "socket.listen(", "CODE_MODEL_FIXTURE", "verified=true", "shell=True",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "StageExecutionGrant", "OpenSSLEd25519Verifier", "close_range",
            "SEALED_FD_ONLY", "F_GET_SEALS", "DEPLOYMENT_ATTESTED",
            "publisher_before_replace", "PRE_COMMIT", "PRE_JOIN",
            "key-admission.json", "KEY_ADMISSION_REQUIRED",
            "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
            "SOCK_SEQPACKET", "SCM_RIGHTS", "publisher_after_pre_replace_checks",
        ):
            self.assertIn(required, source)
        for name in ("_executor_role", "_observer_role", "_publisher_role"):
            self.assertTrue(callable(getattr(module, name, None)))
        self.assertNotIn("INTERNAL_ROLE_NOT_LAUNCHED", source)
        boundary_source = source.split("class M4GuestRuntime", 1)[1].split(
            "def _prepare_publication_root", 1
        )[0]
        self.assertIn("publisher_session", boundary_source)
        self.assertIn("controller.sign", boundary_source)
        self.assertIn("self.publisher_session.publish", boundary_source)
        self.assertIn("self.publisher_session.continuity", boundary_source)
        self.assertNotIn("publisher_key", boundary_source)
        self.assertNotIn("os.open(PUBLICATION_ROOT", boundary_source)

    def test_all_effect_roles_use_the_exact_bwrap_userns_and_seccomp_launcher(self) -> None:
        module = _module()
        self.assertTrue(callable(getattr(module, "_launch_m4_role", None)))
        self.assertTrue(callable(getattr(module, "_materialize_m4_role_rootfs", None)))
        self.assertEqual(
            module.M4_ROLE_SECCOMP_ADDITIONS,
            {
                "EXECUTOR": (18, 73, 77, 437),
                "OBSERVER": (18, 77),
                "PUBLISHER": (18, 47, 55, 263, 264, 437),
            },
        )
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            "--assert-userns-disabled", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-net", "--unshare-cgroup",
            "--block-fd", "--json-status-fd", "--seccomp",
            "_create_user_namespace", "_find_confined_process",
        ):
            self.assertIn(required, source)
        for forbidden in ("--disable-userns", "--unshare-user", "--ro-bind / /"):
            self.assertNotIn(forbidden, source)

    def test_role_launcher_rejects_unowned_stdio_channels_before_allocation(self) -> None:
        module = _module()
        cases = (
            {"stdin_descriptor": module.subprocess.PIPE, "stdout_descriptor": 1, "stderr_descriptor": 2},
            {"stdin_descriptor": 0, "stdout_descriptor": module.subprocess.DEVNULL, "stderr_descriptor": 2},
            {"stdin_descriptor": 0, "stdout_descriptor": 1, "stderr_descriptor": module.subprocess.PIPE},
        )
        for descriptors in cases:
            with self.subTest(descriptors=descriptors), self.assertRaises(module.QualificationStop):
                module._launch_m4_role(
                    m3=object(), manager=object(), role="EXECUTOR",
                    role_input={}, instance="stdio-negative",
                    seccomp_program=b"x", **descriptors,
                )

    def test_role_wrappers_preserve_grant_sealed_fd_and_publisher_session_boundaries(self) -> None:
        module = _module()
        executor = getattr(module, "_executor_launcher", None)
        observer = getattr(module, "_observer_launcher", None)
        publisher = getattr(module, "_start_publisher_session", None)
        for boundary in (executor, observer, publisher):
            self.assertTrue(callable(boundary))

        executor_source = inspect.getsource(executor)
        self.assertIn("stage_execution_grant", executor_source)
        self.assertIn("durable_store", inspect.getsource(module._executor_role))
        self.assertIn("durable_store=None", inspect.getsource(module._executor_role))
        self.assertNotIn("M4_DATABASE", executor_source)
        self.assertIn("START_PACKET", executor_source)

        observer_source = inspect.getsource(observer)
        self.assertIn("snapshot_descriptor", observer_source)
        self.assertIn("F_DUPFD_CLOEXEC", observer_source)
        self.assertIn("RuntimeObserverReceipt", observer_source)
        self.assertIn('measurement["seals"]', observer_source)
        self.assertNotIn("M4_DATABASE", observer_source)

        publisher_source = inspect.getsource(publisher)
        self.assertIn("_publisher_control_pair", publisher_source)
        self.assertIn("PublisherSession", publisher_source)
        self.assertIn("PUBLICATION_ROOT", publisher_source)
        self.assertIn("_publication_descriptor_identity", publisher_source)
        self.assertNotIn("TrustedPublisher", publisher_source)

        materializer_source = inspect.getsource(module._materialize_m4_role_rootfs)
        self.assertGreater(
            materializer_source.rfind("os.chmod(key_root, 0o500)"),
            materializer_source.find("for path in sorted(root.rglob"),
        )
        self.assertIn("finally:", inspect.getsource(module._finish_m4_role))

    def test_stage_record_reconstruction_rejects_bool_and_wrong_digest(self) -> None:
        module = _module()
        valid = {
            "transaction_id": "transaction-1",
            "claim_digest": "sha256:" + "1" * 64,
            "binding_digest": "sha256:" + "2" * 64,
            "before_digest": "sha256:" + "3" * 64,
            "after_digest": "sha256:" + "4" * 64,
            "bytes_written": 4,
        }
        l0 = module._load_project()[1]
        record = {
            **valid,
            "record_digest": l0._hash_text(l0._canonical(valid)),
        }
        self.assertEqual(module._stage_record_from_data(record).bytes_written, 4)
        for mutation in (
            {**record, "bytes_written": True},
            {**record, "after_digest": "sha256:" + "5" * 64},
        ):
            with self.assertRaises(module.QualificationStop):
                module._stage_record_from_data(mutation)

    def test_controller_recovery_decoder_rejects_json_type_aliases(self) -> None:
        module = _module()
        durable = module._load_project()[0]
        digest = "sha256:" + "a" * 64
        row = durable.M4Recovery(
            transaction_id="transaction-1",
            state="JOINED",
            contract_digest=digest,
            d2_frontier_digest=digest,
            fencing_epoch=1,
            record_digest=digest,
            frontier_record_digest=digest,
            iteration=1,
            frontier_attempt_cursor=0,
            frontier_joined_iteration=0,
            attempt_cursor=1,
            joined_iteration=1,
            journal_sequence=20,
            intent_state="SPENT",
            revocation_epoch=0,
            resume_allowed=False,
            retry_allowed=False,
        )
        encoded = module._durable_result_data(
            durable.DurableResult(
                durable.DurableOutcome.OK,
                durable.DurableReason.RECOVERED,
                m4_recovery=(row,),
            )
        )
        encoded = module._strict_bytes(module._canonical(encoded))
        self.assertEqual(module._durable_result_from_data(encoded).m4_recovery, (row,))
        for field, replacement in (
            ("fencing_epoch", True),
            ("iteration", 1.0),
            ("resume_allowed", 0),
            ("record_digest", False),
        ):
            mutation = deepcopy(encoded)
            mutation["m4_recovery"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(module.QualificationStop):
                module._durable_result_from_data(mutation)

    def test_final_evidence_is_materialized_only_after_private_key_cleanup(self) -> None:
        module = _module()
        bundle = {
            "evidence.json": b"{}",
            "manifest.json": b"{}",
            "manifest.sig": b"x" * 64,
        }
        order = []
        with mock.patch.object(
            module,
            "_remove_test_private_keys",
            side_effect=lambda: order.append("keys") or ["private.pem"],
        ), mock.patch.object(
            module,
            "_materialize_m4_evidence",
            side_effect=lambda value: order.append(("bundle", value)),
        ):
            self.assertEqual(module._finalize_m4_evidence(bundle), ["private.pem"])
        self.assertEqual(order, ["keys", ("bundle", bundle)])

        with mock.patch.object(
            module,
            "_remove_test_private_keys",
            side_effect=module.QualificationStop("cleanup failed"),
        ), mock.patch.object(module, "_materialize_m4_evidence") as materialize:
            with self.assertRaises(module.QualificationStop):
                module._finalize_m4_evidence(bundle)
            materialize.assert_not_called()
        with mock.patch.object(module.os, "lstat", side_effect=OSError("denied")):
            with self.assertRaises(module.QualificationStop):
                module._remove_test_private_keys()

    def test_publication_descriptor_identity_rejects_substitution(self) -> None:
        module = _module()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "anchor"
            root = parent / "publication"
            substitute = parent / "substitute"
            root.mkdir(parents=True)
            substitute.mkdir()
            original_parent = module.PUBLICATION_PARENT
            original_root = module.PUBLICATION_ROOT
            module.PUBLICATION_PARENT = parent
            module.PUBLICATION_ROOT = root
            parent_fd = root_fd = substitute_fd = -1
            try:
                parent_fd = module.os.open(parent, module.os.O_RDONLY | module.os.O_DIRECTORY)
                root_fd = module.os.open(root, module.os.O_RDONLY | module.os.O_DIRECTORY)
                substitute_fd = module.os.open(
                    substitute, module.os.O_RDONLY | module.os.O_DIRECTORY
                )
                measured = module._publication_descriptor_identity(parent_fd, root_fd)
                self.assertEqual(measured["basename"], "publication")
                with self.assertRaises(module.QualificationStop):
                    module._publication_descriptor_identity(parent_fd, substitute_fd)
            finally:
                for descriptor in (parent_fd, root_fd, substitute_fd):
                    if descriptor >= 0:
                        module.os.close(descriptor)
                module.PUBLICATION_PARENT = original_parent
                module.PUBLICATION_ROOT = original_root

    def test_controller_owns_the_complete_m3_to_m4_durable_sequence(self) -> None:
        module = _module()
        controller = module.ControllerSession
        for operation in (
            "bootstrap", "issue", "consume", "claim_dispatch",
            "prepare_runtime_session", "verify_dispatch_claim",
            "activate_m4_contract", "bind_current_m4_frontier",
            "begin_m4_transaction", "consume_m4_stage_authorization",
            "advance_m4", "recover",
        ):
            self.assertTrue(callable(getattr(controller, operation, None)), operation)
        child_source = inspect.getsource(module._controller_role)
        self.assertIn('"PREPARE": store.prepare_runtime_session', child_source)
        self.assertIn('"BIND_CURRENT_FRONTIER"', child_source)

    def test_run_phase_enters_one_actual_m3_to_m4_join_chain(self) -> None:
        module = _module()
        source = inspect.getsource(module._run_phase)
        self.assertNotIn("M4_RUNTIME_CHAIN_NOT_ENTERED", source)
        for required in (
            "ControllerSession(", "_start_publisher_session(",
            "_authority_chain(", "bind_current_m4_frontier(",
            "M4GuestRuntime(", "M4Coordinator(", ".execute(",
            "publisher_session.install(",
        ):
            self.assertIn(required, source)

    def test_service_exposes_only_exact_run_and_recover_phases(self) -> None:
        unit = SERVICE.read_text(encoding="utf-8")
        self.assertIn("ConditionVirtualization=vm", unit)
        self.assertIn("Delegate=yes", unit)
        self.assertIn("run_m4_vm_conformance.py --phase %i", unit)
        self.assertIn("User=root", unit)
        self.assertNotIn("Restart=always", unit)
        module = _module()
        self.assertEqual(module.ALLOWED_PHASES, ("run", "recover"))

    def test_run_state_writer_and_recovery_share_one_closed_schema(self) -> None:
        module = _module()
        valid = self._run_state(module)
        self.assertIs(module._validate_run_state(valid), valid)
        for mutation in ("missing", "extra", "prepared", "cursor", "retry", "crypto-claim"):
            value = deepcopy(valid)
            if mutation == "missing":
                value.pop("publication")
            elif mutation == "extra":
                value["unknown"] = True
            elif mutation == "prepared":
                value["durable"]["m3_runtime_session"]["state"] = "PREPARED"
            elif mutation == "cursor":
                value["durable"]["m4_recovery"]["attempt_cursor"] = 0
            elif mutation == "retry":
                value["durable"]["m4_recovery"]["retry_allowed"] = True
            else:
                value["trust"]["verifier"]["independent_cryptographic_implementations"] = True
            with self.subTest(mutation=mutation), self.assertRaises(module.QualificationStop):
                module._validate_run_state(value)

    def test_restart_publication_rejects_oversized_artifact_before_hashing(self) -> None:
        module = _module()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "anchor"
            root = parent / "publication"
            artifact = root / "staging" / "artifact.txt"
            denied = Path(directory) / "synthetic-repository"
            artifact.parent.mkdir(parents=True)
            denied.mkdir()
            artifact.write_bytes(b"x" * ((1 << 20) + 1))
            root_info = root.stat()
            artifact_info = artifact.stat()
            digest = "sha256:" + "a" * 64
            state = {
                "publication": {
                    "root_anchor": {
                        "ancestry": [
                            {"device": root_info.st_dev, "inode": root_info.st_ino}
                        ]
                    },
                    "published_binding": {
                        "final_device": artifact_info.st_dev,
                        "final_inode": artifact_info.st_ino,
                        "final_digest": digest,
                    },
                    "artifact_digest": digest,
                }
            }
            old_parent = module.PUBLICATION_PARENT
            old_root = module.PUBLICATION_ROOT
            old_denied = module.DENIED_REPOSITORY
            module.PUBLICATION_PARENT = parent
            module.PUBLICATION_ROOT = root
            module.DENIED_REPOSITORY = denied
            try:
                with mock.patch.object(
                    module,
                    "_digest_bytes",
                    side_effect=AssertionError("oversized bytes reached the hasher"),
                ), self.assertRaises(module.QualificationStop):
                    module._recover_publication(state)
            finally:
                module.PUBLICATION_PARENT = old_parent
                module.PUBLICATION_ROOT = old_root
                module.DENIED_REPOSITORY = old_denied


if __name__ == "__main__":
    unittest.main()
