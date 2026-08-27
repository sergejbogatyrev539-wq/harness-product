from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_m4_runtime_evidence.py"
PROFILE = ROOT / "profiles/m4-lx-a.json"


def _module():
    specification = importlib.util.spec_from_file_location(
        "harness_m4_runtime_evidence", CHECKER
    )
    if specification is None or specification.loader is None:
        raise AssertionError("M4 evidence verifier unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


class M4RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-m4-evidence-test-")
        self.root = Path(self.temporary.name)
        self.module = _module()
        self.now = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
        self.observed_at = "2026-08-27T11:59:00Z"
        self.expires_at = "2026-08-27T12:30:00Z"
        self.fixture_index = 0
        self.keys = {
            role: self._key(role.lower().replace("_", "-"))
            for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER", "SUPPLY")
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _key(self, name: str) -> dict[str, object]:
        directory = self.root / name
        directory.mkdir(mode=0o700)
        private = directory / "private.pem"
        public = directory / "public.pem"
        for argv in (
            ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
            ["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        ):
            result = subprocess.run(
                argv,
                shell=False,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C"},
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        os.chmod(private, 0o600)
        os.chmod(public, 0o600)
        raw = public.read_bytes()
        return {
            "private": private,
            "public": public,
            "pem": raw.decode("ascii"),
            "digest": _digest_bytes(raw),
        }

    def _signature(self, role: str, value: dict[str, object]) -> bytes:
        payload = self.root / (role.lower() + "-payload.json")
        signature = self.root / (role.lower() + "-signature.bin")
        payload.write_bytes(_canonical(value))
        result = subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
                str(self.keys[role]["private"]), "-rawin", "-in", str(payload),
                "-out", str(signature),
            ],
            shell=False,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C"},
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        return signature.read_bytes()

    def _source(self) -> dict[str, object]:
        files: dict[str, str] = {}
        return {
            "commit": "b" * 40,
            "tree": "c" * 40,
            "files": files,
            "files_digest": _digest_bytes(_canonical(files)),
        }

    def _host_provenance(self, digest: str, attempt: int) -> dict[str, object]:
        return {
            "image": {
                "source_url": self.module._IMAGE_URL,
                "resolved_url": self.module._IMAGE_URL,
                "release_id": "20260814",
                "filename": "ubuntu-24.04-server-cloudimg-amd64.img",
                "bytes": 624447488,
                "sha256": self.module._IMAGE_DIGEST,
                "sums_sha256": self.module._SUMS_DIGEST,
                "sums_signature_sha256": self.module._SUMS_SIGNATURE_DIGEST,
                "signer_fingerprint": self.module._UBUNTU_SIGNER,
            },
            "vm": {
                "qemu_path": "/usr/bin/qemu-system-x86_64",
                "qemu_version": "QEMU emulator version 8.2.2 (fixture)",
                "qemu_digest": self.module._QEMU_DIGEST,
                "machine": "q35",
                "kvm_api": 12,
                "vcpus": 2,
                "memory_bytes": 2147483648,
                "overlay_virtual_bytes": 3758096384,
                "seed_digest": digest,
                "management_address": "127.0.0.1:22227",
                "shared_host_mounts": 0,
                "qemu_argv_digest": _digest_bytes(
                    _canonical(self.module._qemu_lifecycle(attempt))
                ),
            },
        }

    def _role_facts(self, profile: dict[str, object], role: str) -> dict[str, object]:
        expected = profile["roles"][role]
        if role == "CONTROLLER":
            return {
                "role": role,
                "uid": expected["uid"],
                "gid": expected["gid"],
                "label": expected["security_label"],
                "fd_inventory": expected["fd_allowlist"],
                "cgroup": "/harness/" + expected["cgroup"],
            }
        return {
            "role": role,
            "launcher_uid": expected["uid"],
            "launcher_gid": expected["gid"],
            "label": expected["security_label"],
            "fd_inventory": expected["fd_allowlist"],
            "cgroup": "/harness/" + expected["cgroup"],
        }

    def _verification_source(
        self, profile: dict[str, object], role: str, payload: dict[str, object]
    ) -> dict[str, object]:
        route = profile["receipt_keys"][role]
        return {
            "verifier_id": "harness-m4-openssl-libcrypto/v1",
            "issuer_id": route["issuer_id"],
            "key_id": route["key_id"],
            "proof": "ed25519:" + self._signature(role, payload).hex(),
        }

    def _verification_record(
        self, profile: dict[str, object], role: str, payload: dict[str, object]
    ) -> dict[str, object]:
        source = self._verification_source(profile, role, payload)
        return {
            "verification_version": 1,
            "verifier_id": source["verifier_id"],
            "issuer_id": source["issuer_id"],
            "key_id": source["key_id"],
            "payload_digest": _digest_bytes(_canonical(payload)),
            "bindings": payload,
            "proof": source["proof"],
        }

    def _ledger_row(
        self,
        *,
        sequence: int,
        previous: str | None,
        entry_type: str,
        candidate: str,
        tree: str,
        environment: str,
        attempt: int,
        goal_reference: str,
        goal_digest: str,
        extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "ledger_version": "1.0.0",
            "sequence": sequence,
            "previous_entry_digest": previous,
            "entry_type": entry_type,
            "recorded_at": self.observed_at,
            "candidate": candidate,
            "tree": tree,
            "environment": environment,
            "user_scope_reference": goal_reference,
            "user_goal_digest": goal_digest,
            "max_attempts": 2,
            "success_target": 1,
            "attempt": attempt,
            **({} if extra is None else extra),
        }

    def _fixture(
        self,
        *,
        attempt: int = 1,
        prior_result: str | None = None,
        repeat_candidate_environment: bool = False,
    ) -> tuple[Path, Path, dict[str, object], str, str]:
        if attempt not in {1, 2} or (attempt == 1) != (prior_result is None):
            raise AssertionError("invalid synthetic attempt history")
        self.fixture_index += 1
        workspace = self.root / f"case-{self.fixture_index}"
        workspace.mkdir(mode=0o700)
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        digest = "sha256:" + "a" * 64
        source = self._source()
        host_provenance = self._host_provenance(digest, attempt)
        profile_digest = _digest_bytes(_canonical(profile))
        environment = _digest_bytes(
            _canonical({"host_provenance": host_provenance, "profile_digest": profile_digest})
        )
        receipt_digests = {
            role: self.keys[role]["digest"]
            for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER")
        }
        runtime_trust_digest = _digest_bytes(
            _canonical({
                "profile_digest": profile_digest,
                "receipt_public_key_digests": receipt_digests,
                "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
            })
        )
        goal_reference = "/tmp/authorized-m4-goal.md"
        goal_digest = _digest_bytes(b"authorized M4 test goal\n")
        ledger_prefix = b""
        sequence = 1
        previous: str | None = None
        if prior_result is not None:
            prior_candidate = source["commit"] if repeat_candidate_environment else "a" * 40
            prior_tree = source["tree"] if repeat_candidate_environment else "d" * 40
            prior_environment = (
                environment
                if repeat_candidate_environment
                else "sha256:" + "e" * 64
            )
            prior_start = self._ledger_row(
                sequence=1,
                previous=None,
                entry_type="ATTEMPT_STARTED",
                candidate=prior_candidate,
                tree=prior_tree,
                environment=prior_environment,
                attempt=1,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )
            prior_start_line = _canonical(prior_start)
            prior_start_digest = _digest_bytes(prior_start_line)
            prior_terminal = self._ledger_row(
                sequence=2,
                previous=prior_start_digest,
                entry_type="ATTEMPT_TERMINAL",
                candidate=prior_candidate,
                tree=prior_tree,
                environment=prior_environment,
                attempt=1,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
                extra={
                    "attempt_start_digest": prior_start_digest,
                    "key_admission_digest": None,
                    "result": prior_result,
                    "manifest_digest": None,
                    "bundle_digest": None,
                    "qemu_phase_outcomes": None,
                },
            )
            prior_terminal_line = _canonical(prior_terminal)
            previous = _digest_bytes(prior_terminal_line)
            ledger_prefix = prior_start_line + b"\n" + prior_terminal_line + b"\n"
            sequence = 3
        start = self._ledger_row(
            sequence=sequence,
            previous=previous,
            entry_type="ATTEMPT_STARTED",
            candidate=source["commit"],
            tree=source["tree"],
            environment=environment,
            attempt=attempt,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
        )
        start_line = _canonical(start)
        start_digest = _digest_bytes(start_line)
        key_row = self._ledger_row(
            sequence=sequence + 1,
            previous=start_digest,
            entry_type="KEY_ADMITTED",
            candidate=source["commit"],
            tree=source["tree"],
            environment=environment,
            attempt=attempt,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
            extra={
                "attempt_start_digest": start_digest,
                "receipt_public_key_digests": receipt_digests,
                "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
                "runtime_trust_digest": runtime_trust_digest,
            },
        )
        key_line = _canonical(key_row)
        key_digest = _digest_bytes(key_line)
        binding_body = {
            "canonical_path": "/staging/artifact.txt",
            "descriptor_id": "publication-target-1",
            "root_id": "publication-root-1",
            "root_identity": digest,
            "mount_id": "mnt:1",
            "mount_identity": digest,
            "resolution_epoch": 1,
            "final_device": 1,
            "final_inode": 3,
            "final_type": "REGULAR_FILE",
            "final_digest": digest,
        }
        binding = {
            **binding_body,
            "composite_binding_digest": _digest_bytes(_canonical(binding_body)),
        }
        root_anchor_body = {
            "anchor_version": 1,
            "mount_namespace_id": "mntns:1:1",
            "mount_id": "mnt:1",
            "mountpoint": "/",
            "root_path": "/var/lib/harness-m4-publication/anchor/publication",
            "basename": "publication",
            "root_identity": digest,
            "ancestry": [
                {
                    "component": "publication",
                    "device": 1,
                    "inode": 2,
                    "mode": 0o040000,
                    "mount_id": "mnt:1",
                }
            ],
        }
        root_anchor = {
            **root_anchor_body,
            "anchor_digest": _digest_bytes(_canonical(root_anchor_body)),
        }
        durable = {
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
        }
        common = {
            "transaction_id": durable["transaction_id"],
            "contract_digest": durable["contract_digest"],
            "d2_frontier_digest": durable["d2_frontier_digest"],
            "attempt_cursor": 1,
            "iteration": 1,
            "publication_target_binding_digest": binding["composite_binding_digest"],
            "publication_root_anchor_digest": root_anchor["anchor_digest"],
            "snapshot_digest": digest,
            "revocation_epoch": 0,
            "fencing_epoch": 1,
            "issued_at": self.observed_at,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
        }
        preflight = {
            "runtime_version": "1.0.0",
            "outcome": "READY",
            "transaction_id": durable["transaction_id"],
            "claim_digest": digest,
            "profile_digest": profile_digest,
            "placement_digest": digest,
            "session_id": "session-1",
            "revocation_epoch": 0,
            "fencing_epoch": 1,
            "executor_principal": profile["roles"]["EXECUTOR"]["principal_id"],
            "executor_session": profile["roles"]["EXECUTOR"]["session_id"],
            "staging_binding_digest": digest,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
        }
        observer_body = {
            **common,
            "receipt_version": 1,
            "outcome": "PASS",
            "proposal_digest": digest,
        }
        observer = {
            **observer_body,
            "receipt_digest": _digest_bytes(_canonical(observer_body)),
        }
        publication_body = {
            **common,
            "receipt_version": 1,
            "outcome": "PUBLISHED",
            "published_binding": binding,
        }
        publication_receipt = {
            **publication_body,
            "receipt_digest": _digest_bytes(_canonical(publication_body)),
        }
        pre_commit = {**common, "purpose": "PRE_COMMIT", "outcome": "CONTINUOUS"}
        pre_join = {**common, "purpose": "PRE_JOIN", "outcome": "CONTINUOUS"}
        authorization_body = {
            "authorization_version": 1,
            "transaction_id": durable["transaction_id"],
            "claim_digest": digest,
            "intent_digest": digest,
            "capability_id": digest,
            "contract_digest": durable["contract_digest"],
            "d2_frontier_digest": durable["d2_frontier_digest"],
            "iteration": durable["iteration"],
            "target_authority_digest": digest,
            "target_binding": binding,
            "publication_target_binding_digest": binding["composite_binding_digest"],
            "publication_root_anchor_digest": root_anchor["anchor_digest"],
            "profile_digest": profile_digest,
            "placement_digest": digest,
            "session_id": "session-1",
            "revocation_epoch": durable["revocation_epoch"],
            "fencing_epoch": durable["fencing_epoch"],
            "issued_at": self.observed_at,
            "expires_at": self.expires_at,
        }
        authorization = {
            **authorization_body,
            "authorization_digest": _digest_bytes(_canonical(authorization_body)),
        }
        authorization_payload = {
            "record_type": "M4_STAGE_AUTHORIZATION",
            "authorization": authorization,
        }
        authorization_verification = self._verification_record(
            profile, "M4_AUTHORITY", authorization_payload
        )
        consumption = {
            "consumption_version": 1,
            "transaction_id": durable["transaction_id"],
            "stage_authorization_digest": authorization["authorization_digest"],
            "claim_digest": authorization["claim_digest"],
            "intent_digest": authorization["intent_digest"],
            "capability_id": authorization["capability_id"],
            "contract_digest": authorization["contract_digest"],
            "d2_frontier_digest": authorization["d2_frontier_digest"],
            "iteration": authorization["iteration"],
            "target_authority_digest": authorization["target_authority_digest"],
            "target_binding": authorization["target_binding"],
            "profile_digest": authorization["profile_digest"],
            "placement_digest": authorization["placement_digest"],
            "session_id": authorization["session_id"],
            "revocation_epoch": authorization["revocation_epoch"],
            "fencing_epoch": authorization["fencing_epoch"],
            "consumed_at": self.observed_at,
            "expires_at": authorization["expires_at"],
        }
        grant_payload = {
            "record_type": "M4_STAGE_EXECUTION_GRANT",
            "authorization": authorization,
            "authorization_verification": authorization_verification,
            "consumption": consumption,
        }
        grant_verification = self._verification_record(
            profile, "M4_AUTHORITY", grant_payload
        )
        events = [
            {
                "type": "M4_RUNTIME_PREFLIGHT",
                "payload": preflight,
                "verification_source": self._verification_source(profile, "M4_AUTHORITY", preflight),
            },
            {
                "type": "TCB_STAGE",
                "pid": 3101,
                "session": 3101,
                "stage_authorization_digest": authorization["authorization_digest"],
                "target_binding": binding,
                "grant_payload": grant_payload,
                "grant_verification": grant_verification,
                "grant_payload_digest": _digest_bytes(_canonical(grant_payload)),
                "grant_verification_digest": _digest_bytes(_canonical(grant_verification)),
            },
            {
                "type": "TCB_POSTCHECK",
                "pid": 3102,
                "session": 3102,
                "receipt": observer,
                "verification_source": self._verification_source(profile, "OBSERVER", observer),
            },
            {
                "type": "TCB_PUBLICATION",
                "receipt": publication_receipt,
                "verification_source": self._verification_source(
                    profile, "PUBLISHER", publication_receipt
                ),
            },
            {
                "type": "PRE_COMMIT",
                "payload": pre_commit,
                "verification_source": self._verification_source(profile, "PUBLISHER", pre_commit),
            },
            {
                "type": "PRE_JOIN",
                "payload": pre_join,
                "verification_source": self._verification_source(profile, "PUBLISHER", pre_join),
            },
        ]
        state = {
            "record_version": "1.0.0",
            "phase": "PRE_RESTART_PASS",
            "identity": {
                "candidate": source["commit"],
                "environment": environment,
                "attempt": attempt,
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "guest": {},
                "source": source,
                "host_provenance": host_provenance,
            },
            "trust": {
                "profile_digest": profile_digest,
                "m4_apparmor_digest": self.module._digest_file(
                    ROOT / "profiles/m4-lx-a.apparmor", 1 << 20
                ),
                "m3_apparmor_digest": self.module._digest_file(
                    ROOT / "profiles/l0-lx-a.apparmor", 1 << 20
                ),
                "runtime_trust_digest": runtime_trust_digest,
                "key_admission": {
                    "admission_version": "1.0.0",
                    "mode": "HOST_ATTEMPT_LEDGER_PIN_BEFORE_WORKER_GATE",
                    "candidate": source["commit"],
                    "environment": environment,
                    "attempt": attempt,
                    "ledger_entry_digest": key_digest,
                    "receipt_public_key_digests": receipt_digests,
                    "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
                    "runtime_trust_digest": runtime_trust_digest,
                },
                "receipt_public_key_digests": receipt_digests,
                "supply_public_key_digest": self.keys["SUPPLY"]["digest"],
                "verifier": {
                    "backend": "OPENSSL_LIBCRYPTO_SHARED",
                    "code_digest": self.module._digest_file(
                        ROOT / "src/harness_product/verification.py", 1 << 20
                    ),
                    "libcrypto_path": str(self.module.LIBCRYPTO),
                    "libcrypto_digest": self.module._digest_file(
                        self.module.LIBCRYPTO.resolve(strict=True), 16 << 20
                    ),
                    "independent_cryptographic_implementations": False,
                },
                "revocation_epoch": 0,
                "fencing_epoch": 1,
            },
            "durable": {
                "m4_recovery": durable,
                "m3_runtime_session": {
                    "session_record_id": "session-record-1",
                    "transaction_id": durable["transaction_id"],
                    "claim_digest": digest,
                    "state": "STOPPED",
                    "fencing_epoch": 1,
                },
            },
            "publication": {
                "root": profile["publication"]["root"],
                "topology_digest": digest,
                "root_anchor": root_anchor,
                "target_binding": binding,
                "published_binding": binding,
                "artifact_digest": digest,
                "snapshot_digest": digest,
                "transport": "SEALED_FD_ONLY",
            },
            "execution": {
                "controller_facts": self._role_facts(profile, "CONTROLLER"),
                "publisher_facts": self._role_facts(profile, "PUBLISHER"),
                "executor_facts": [self._role_facts(profile, "EXECUTOR")],
                "observer_facts": [self._role_facts(profile, "OBSERVER")],
                "runtime_events": events,
                "denial_events": [
                    {
                        "point": "AFTER_PRE_REPLACE_CHECKS",
                        "errno": 13,
                        "principal": {
                            "role": "CONTROLLER",
                            "pid": 3201,
                            "uid": profile["roles"]["CONTROLLER"]["uid"],
                            "gid": profile["roles"]["CONTROLLER"]["gid"],
                            "session": 3201,
                            "label": profile["roles"]["CONTROLLER"]["security_label"],
                            "cgroup": "/harness/m4-relocation-replace",
                            "fd_inventory": [0, 1, 2],
                            "namespaces": {
                                name: name + ":[1]"
                                for name in ("user", "mnt", "pid", "ipc", "uts", "net", "cgroup")
                            },
                            "capabilities": {
                                name: "0000000000000000"
                                for name in ("CapInh", "CapPrm", "CapEff")
                            },
                            "no_new_privs": 1,
                        },
                        "root_device": 1,
                        "root_inode": 2,
                        "git_destination_absent": True,
                        "pause": {
                            "anchor_digest": root_anchor["anchor_digest"],
                            "binding_digest": binding["composite_binding_digest"],
                        },
                    },
                    {
                        "point": "AFTER_PRE_JOIN",
                        "errno": 13,
                        "principal": {
                            "role": "CONTROLLER",
                            "pid": 3202,
                            "uid": profile["roles"]["CONTROLLER"]["uid"],
                            "gid": profile["roles"]["CONTROLLER"]["gid"],
                            "session": 3202,
                            "label": profile["roles"]["CONTROLLER"]["security_label"],
                            "cgroup": "/harness/m4-relocation-join",
                            "fd_inventory": [0, 1, 2],
                            "namespaces": {
                                name: name + ":[2]"
                                for name in ("user", "mnt", "pid", "ipc", "uts", "net", "cgroup")
                            },
                            "capabilities": {
                                name: "0000000000000000"
                                for name in ("CapInh", "CapPrm", "CapEff")
                            },
                            "no_new_privs": 1,
                        },
                        "root_device": 1,
                        "root_inode": 2,
                        "git_destination_absent": True,
                        "pause": {},
                    },
                ],
                "role_seccomp_digests": {},
                "m3_role_seccomp": {},
                "cleanup": {},
            },
        }
        recovery = {
            "recovery_version": "1.0.0",
            "previous_boot_id": state["identity"]["boot_id"],
            "current_boot_id": "87654321-4321-4321-4321-cba987654321",
            "durable": {
                "m4_recovery": durable,
                "m3_runtime_session": state["durable"]["m3_runtime_session"],
                "old_session_resumed": False,
                "retry_created": False,
            },
            "survival": {
                "recorded_process_ids": [3101, 3102, 3201, 3202],
                "live_process_ids": [],
                "recorded_cgroups": sorted({
                    state["execution"]["controller_facts"]["cgroup"],
                    state["execution"]["publisher_facts"]["cgroup"],
                    state["execution"]["executor_facts"][0]["cgroup"],
                    state["execution"]["observer_facts"][0]["cgroup"],
                    "/harness/m4-relocation-replace",
                    "/harness/m4-relocation-join",
                }),
                "surviving_cgroups": [],
            },
            "publication": {
                "descriptor_identity": {"root_device": 1, "root_inode": 2},
                "artifact_device": 1,
                "artifact_inode": 3,
                "artifact_size": 16,
                "artifact_digest": digest,
                "git_destination_absent": True,
            },
            "controller_facts": self._role_facts(profile, "CONTROLLER"),
            "source_reverified": True,
            "host_provenance_reverified": True,
            "trust_reverified": True,
        }
        evidence = {
            "evidence_version": "1.0.0",
            "claim": "M4_EXACT_DISPOSABLE_TEST_PROFILE_RUNTIME_CONFORMANCE",
            "scope": {
                "profile_id": "M4-LX-A",
                "assurance_scope": "DEPLOYMENT_ATTESTED",
                "environment": "DISPOSABLE_UBUNTU_24_04_QEMU_KVM",
                "data_class": "SYNTHETIC",
            },
            "run_state": state,
            "run_state_digest": _digest_bytes(_canonical(state)),
            "recovery": recovery,
            "public_keys": {
                "receipts": {
                    role: {"digest": self.keys[role]["digest"], "pem": self.keys[role]["pem"]}
                    for role in ("M4_AUTHORITY", "OBSERVER", "PUBLISHER")
                },
                "supply_attestor": {
                    "digest": self.keys["SUPPLY"]["digest"],
                    "pem": self.keys["SUPPLY"]["pem"],
                },
            },
            "residual_risk": self.module._RESIDUAL_RISK,
        }
        evidence_bytes = _canonical(evidence)
        manifest = {
            "bundle_version": "1.0.0",
            "claim": evidence["claim"],
            "outcome": "VERIFIED",
            "status": "NOT_ATTESTED",
            "candidate": source["commit"],
            "environment": environment,
            "attempt": attempt,
            "source": source,
            "host_provenance": host_provenance,
            "profile": {
                "path": "profiles/m4-lx-a.json",
                "digest": profile_digest,
                "apparmor_digest": state["trust"]["m4_apparmor_digest"],
                "runtime_trust_digest": runtime_trust_digest,
                "verifier": state["trust"]["verifier"],
            },
            "attempt_ledger": {
                "ledger_entry_digest": key_digest,
                "max_attempts": 2,
                "success_target": 1,
            },
            "durable": durable,
            "attestation": {
                "trust_root_id": profile["supply_trust"]["trust_root_id"],
                "signer_id": profile["supply_trust"]["signer_id"],
                "key_id": profile["supply_trust"]["key_id"],
                "algorithm": "ED25519",
                "public_key_digest": self.keys["SUPPLY"]["digest"],
                "issued_at": self.observed_at,
                "expires_at": self.expires_at,
                "revocation_epoch": 0,
                "fencing_epoch": 1,
                "rollback_floor": 1,
                "nonce": "m4-evidence-" + recovery["current_boot_id"].replace("-", ""),
            },
            "evidence": {
                "path": "evidence.json",
                "bytes": len(evidence_bytes),
                "digest": _digest_bytes(evidence_bytes),
            },
        }
        manifest_bytes = _canonical(manifest)
        manifest_signature = self._signature("SUPPLY", manifest)
        bundle_digest = _digest_bytes(
            _canonical({
                "manifest": _digest_bytes(manifest_bytes),
                "signature": _digest_bytes(manifest_signature),
                "evidence": _digest_bytes(evidence_bytes),
                "ledger_entry": key_digest,
            })
        )
        terminal = self._ledger_row(
            sequence=sequence + 2,
            previous=key_digest,
            entry_type="ATTEMPT_TERMINAL",
            candidate=source["commit"],
            tree=source["tree"],
            environment=environment,
            attempt=attempt,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
            extra={
                "attempt_start_digest": start_digest,
                "key_admission_digest": key_digest,
                "result": "BUNDLE_EXPORTED",
                "manifest_digest": _digest_bytes(manifest_bytes),
                "bundle_digest": bundle_digest,
                "qemu_phase_outcomes": {
                    phase: {
                        "argv_digest": _digest_bytes(
                            _canonical(self.module._qemu_argv(attempt, phase))
                        ),
                        "return_code": 0,
                    }
                    for phase in ("provision", "run", "recover")
                },
            },
        )
        ledger = workspace / "m4-attempt-ledger.jsonl"
        ledger.write_bytes(
            ledger_prefix
            + start_line
            + b"\n"
            + key_line
            + b"\n"
            + _canonical(terminal)
            + b"\n"
        )
        os.chmod(ledger, 0o600)
        bundle = workspace / "bundle"
        bundle.mkdir(mode=0o700)
        for name, raw in (
            ("manifest.json", manifest_bytes),
            ("manifest.sig", manifest_signature),
            ("evidence.json", evidence_bytes),
        ):
            path = bundle / name
            path.write_bytes(raw)
            os.chmod(path, 0o444)
        return bundle, ledger, source, goal_reference, goal_digest

    def _rewrite_bundle(
        self,
        bundle: Path,
        ledger: Path,
        change: object,
    ) -> None:
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        evidence = json.loads((bundle / "evidence.json").read_text(encoding="utf-8"))
        change(manifest, evidence)
        evidence["run_state_digest"] = _digest_bytes(_canonical(evidence["run_state"]))
        evidence_bytes = _canonical(evidence)
        manifest["evidence"] = {
            "path": "evidence.json",
            "bytes": len(evidence_bytes),
            "digest": _digest_bytes(evidence_bytes),
        }
        manifest_bytes = _canonical(manifest)
        signature = self._signature("SUPPLY", manifest)
        for path in bundle.iterdir():
            os.chmod(path, 0o600)
        (bundle / "evidence.json").write_bytes(evidence_bytes)
        (bundle / "manifest.json").write_bytes(manifest_bytes)
        (bundle / "manifest.sig").write_bytes(signature)
        for path in bundle.iterdir():
            os.chmod(path, 0o444)
        lines = [json.loads(line) for line in ledger.read_bytes().splitlines()]
        lines[-1]["manifest_digest"] = _digest_bytes(manifest_bytes)
        lines[-1]["bundle_digest"] = _digest_bytes(
            _canonical({
                "manifest": _digest_bytes(manifest_bytes),
                "signature": _digest_bytes(signature),
                "evidence": _digest_bytes(evidence_bytes),
                "ledger_entry": evidence["run_state"]["trust"]["key_admission"][
                    "ledger_entry_digest"
                ],
            })
        )
        ledger.write_bytes(b"".join(_canonical(row) + b"\n" for row in lines))

    def test_exact_signed_bundle_and_authoritative_attempt_ledger_verify(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()
        result = self.module._verify_bundle(
            bundle,
            ledger=ledger,
            source_state=source,
            now=self.now,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
        )
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertEqual(result["product_status"], "NOT_ATTESTED")
        self.assertEqual(result["attempt"], 1)

    def test_failed_first_attempt_consumes_slot_and_second_attempt_verifies(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture(
            attempt=2, prior_result="BLOCKED"
        )
        result = self.module._verify_bundle(
            bundle,
            ledger=ledger,
            source_state=source,
            now=self.now,
            goal_reference=goal_reference,
            goal_digest=goal_digest,
        )
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertEqual(result["attempt"], 2)

    def test_second_attempt_cannot_repeat_candidate_and_environment(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture(
            attempt=2,
            prior_result="BLOCKED",
            repeat_candidate_environment=True,
        )
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                ledger=ledger,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_missing_terminal_attempt_record_fails_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()
        lines = ledger.read_bytes().splitlines()
        ledger.write_bytes(b"\n".join(lines[:2]) + b"\n")
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                ledger=ledger,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_malformed_runtime_event_and_attestation_time_fail_closed(self) -> None:
        for name, change in (
            (
                "runtime-event",
                lambda _manifest, evidence: evidence["run_state"]["execution"][
                    "runtime_events"
                ].append(None),
            ),
            (
                "attestation-time",
                lambda manifest, _evidence: manifest["attestation"].__setitem__(
                    "expires_at", None
                ),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        ledger=ledger,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_host_provenance_constants_fail_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()

        def mutate(manifest: dict[str, object], evidence: dict[str, object]) -> None:
            manifest["host_provenance"]["vm"]["qemu_version"] = "QEMU emulator version 9.9.9"
            evidence["run_state"]["identity"]["host_provenance"]["vm"][
                "qemu_version"
            ] = "QEMU emulator version 9.9.9"

        self._rewrite_bundle(bundle, ledger, mutate)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                ledger=ledger,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_qemu_phase_outcomes_fail_closed(self) -> None:
        for name, mutate in (
            (
                "nonzero-return",
                lambda terminal: terminal["qemu_phase_outcomes"]["run"].__setitem__(
                    "return_code", 1
                ),
            ),
            (
                "wrong-argv",
                lambda terminal: terminal["qemu_phase_outcomes"]["recover"].__setitem__(
                    "argv_digest", "sha256:" + "0" * 64
                ),
            ),
            (
                "missing-phase",
                lambda terminal: terminal["qemu_phase_outcomes"].pop("provision"),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                rows = [json.loads(line) for line in ledger.read_bytes().splitlines()]
                mutate(rows[-1])
                ledger.write_bytes(b"".join(_canonical(row) + b"\n" for row in rows))
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        ledger=ledger,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_duplicate_physical_denial_event_fails_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()

        def duplicate(_manifest: dict[str, object], evidence: dict[str, object]) -> None:
            denials = evidence["run_state"]["execution"]["denial_events"]
            denials.append(dict(denials[0]))

        self._rewrite_bundle(bundle, ledger, duplicate)
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                ledger=ledger,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_durable_integer_alias_and_session_fence_mutations_fail_closed(self) -> None:
        for name, change in (
            (
                "boolean-attempt-cursor",
                lambda _manifest, evidence: evidence["run_state"]["durable"][
                    "m4_recovery"
                ].__setitem__("attempt_cursor", True),
            ),
            (
                "zero-journal-sequence",
                lambda _manifest, evidence: evidence["run_state"]["durable"][
                    "m4_recovery"
                ].__setitem__("journal_sequence", 0),
            ),
            (
                "session-fence",
                lambda _manifest, evidence: evidence["run_state"]["durable"][
                    "m3_runtime_session"
                ].__setitem__("fencing_epoch", 2),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        ledger=ledger,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_embedded_public_key_digest_mutations_fail_closed(self) -> None:
        for name, change in (
            (
                "receipt",
                lambda _manifest, evidence: evidence["public_keys"]["receipts"][
                    "OBSERVER"
                ].__setitem__("digest", "sha256:" + "0" * 64),
            ),
            (
                "supply",
                lambda _manifest, evidence: evidence["public_keys"][
                    "supply_attestor"
                ].__setitem__("digest", "sha256:" + "0" * 64),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        ledger=ledger,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_m3_apparmor_digest_mutation_fails_closed(self) -> None:
        bundle, ledger, source, goal_reference, goal_digest = self._fixture()
        self._rewrite_bundle(
            bundle,
            ledger,
            lambda _manifest, evidence: evidence["run_state"]["trust"].__setitem__(
                "m3_apparmor_digest", "sha256:" + "0" * 64
            ),
        )
        with self.assertRaises(self.module._InvalidEvidence):
            self.module._verify_bundle(
                bundle,
                ledger=ledger,
                source_state=source,
                now=self.now,
                goal_reference=goal_reference,
                goal_digest=goal_digest,
            )

    def test_recovery_type_and_principal_mutations_fail_closed(self) -> None:
        for name, change in (
            (
                "boolean-recorded-pid",
                lambda _manifest, evidence: evidence["recovery"]["survival"].__setitem__(
                    "recorded_process_ids", [True]
                ),
            ),
            (
                "boolean-artifact-size",
                lambda _manifest, evidence: evidence["recovery"]["publication"].__setitem__(
                    "artifact_size", True
                ),
            ),
            (
                "controller-label",
                lambda _manifest, evidence: evidence["recovery"]["controller_facts"].__setitem__(
                    "label", "unconfined"
                ),
            ),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        ledger=ledger,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_stage_execution_grant_mutations_fail_closed(self) -> None:
        def stage(evidence: dict[str, object]) -> dict[str, object]:
            return evidence["run_state"]["execution"]["runtime_events"][1]

        def mutate_nested(_manifest: dict[str, object], evidence: dict[str, object]) -> None:
            event = stage(evidence)
            event["grant_payload"]["consumption"]["session_id"] = "substituted-session"
            event["grant_payload_digest"] = _digest_bytes(_canonical(event["grant_payload"]))

        for name, change in (
            (
                "target-binding",
                lambda _manifest, evidence: stage(evidence).__setitem__(
                    "target_binding", {"substituted": True}
                ),
            ),
            (
                "authorization-digest",
                lambda _manifest, evidence: stage(evidence).__setitem__(
                    "stage_authorization_digest", "sha256:" + "0" * 64
                ),
            ),
            (
                "grant-verification-digest",
                lambda _manifest, evidence: stage(evidence).__setitem__(
                    "grant_verification_digest", "sha256:" + "0" * 64
                ),
            ),
            ("nested-grant-binding", mutate_nested),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                self._rewrite_bundle(bundle, ledger, change)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        ledger=ledger,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )

    def test_bundle_and_ledger_permissions_are_exact(self) -> None:
        for name, mutate in (
            ("bundle-directory", lambda bundle, _ledger: os.chmod(bundle, 0o755)),
            (
                "bundle-file",
                lambda bundle, _ledger: os.chmod(bundle / "manifest.json", 0o644),
            ),
            ("ledger-parent", lambda _bundle, ledger: os.chmod(ledger.parent, 0o755)),
        ):
            with self.subTest(name=name):
                bundle, ledger, source, goal_reference, goal_digest = self._fixture()
                mutate(bundle, ledger)
                with self.assertRaises(self.module._InvalidEvidence):
                    self.module._verify_bundle(
                        bundle,
                        ledger=ledger,
                        source_state=source,
                        now=self.now,
                        goal_reference=goal_reference,
                        goal_digest=goal_digest,
                    )


if __name__ == "__main__":
    unittest.main()
