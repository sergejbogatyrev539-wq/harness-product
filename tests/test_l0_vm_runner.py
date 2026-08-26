"""Safe host-side regressions for the one disposable VM runner."""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from datetime import UTC, datetime


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts/run_m3_vm_conformance.py"
SPEC = importlib.util.spec_from_file_location("harness_m3_vm_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class VMRunnerBoundaryTests(unittest.TestCase):
    @staticmethod
    def namespace_record(role: str = "AGENT_WORKER", descriptor: int = 9) -> dict[str, object]:
        uid_map, gid_map = RUNNER._namespace_maps(role)
        return {
            "role": role,
            "descriptor": descriptor,
            "device": 1,
            "inode": 2,
            "identity": "user:[2]",
            "uid_map": uid_map,
            "gid_map": gid_map,
            "setgroups": "deny",
            "max_user_namespaces": 0,
        }

    def test_unknown_or_missing_cli_is_nonzero_structured_stop(self) -> None:
        for argv in ([], ["--phase"], ["--phase", "verified=true"], ["--phase", "run", "--skip"]):
            with self.subTest(argv=argv):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = RUNNER.main(argv)
                self.assertNotEqual(code, 0)
                self.assertEqual(
                    json.loads(output.getvalue()),
                    {"outcome": "STOP", "reason": "UNKNOWN_OR_MISSING_ARGUMENT"},
                )

    def test_run_requires_exact_guest_marker_before_any_runtime_mutation(self) -> None:
        forbidden = AssertionError("runner crossed absent guest marker")
        output = io.StringIO()
        with (
            patch.object(RUNNER.os, "geteuid", return_value=0),
            patch.object(RUNNER, "_strict_json", side_effect=RUNNER.QualificationStop("GUEST_MARKER_ABSENT")),
            patch.object(RUNNER, "_load_apparmor", side_effect=forbidden) as policy,
            patch.object(RUNNER, "CgroupManager", side_effect=forbidden) as cgroup,
            patch.object(RUNNER.subprocess, "Popen", side_effect=forbidden) as popen,
            redirect_stdout(output),
        ):
            code = RUNNER.main(["--phase", "run"])
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["reason"], "GUEST_MARKER_ABSENT")
        policy.assert_not_called()
        cgroup.assert_not_called()
        popen.assert_not_called()

    def test_runner_has_one_backend_typed_argv_and_no_host_or_m4_surface(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertEqual(RUNNER.BWRAP, "/usr/bin/bwrap")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("--exec-label", source)
        self.assertIn("RUNTIME.mkdir(mode=0o711", source)
        self.assertIn("CONTROLLER.mkdir(mode=0o700", source)
        self.assertNotIn("attach_disconnected", source)
        for forbidden in ("docker", "podman", "libvirt", "terraform", "seal_workspace"):
            self.assertNotIn(forbidden, source.lower())

    def test_apparmor_policy_has_real_distinct_domains_without_unconfined_fallback(self) -> None:
        policy = (ROOT / "profiles/l0-lx-a.apparmor").read_text(encoding="utf-8")
        for label in RUNNER.PROFILE_LABELS.values():
            self.assertIn("profile " + label, policy)
        for unsafe in (" ux,", " pux,", " PUx,", "attach_disconnected"):
            self.assertNotIn(unsafe, policy)
        self.assertGreaterEqual(policy.count("audit deny change_profile"), 5)

    def test_recovery_reloads_only_the_exact_previously_measured_apparmor_policy(self) -> None:
        digest = "sha256:" + "a" * 64
        exact = {
            "digest": digest,
            "profiles": sorted(RUNNER.PROFILE_LABELS.values()),
        }
        with (
            patch.object(RUNNER, "_digest_file", return_value=digest),
            patch.object(RUNNER, "_load_apparmor", return_value=exact) as loader,
        ):
            self.assertEqual(RUNNER._reload_recovery_apparmor(exact), exact)
            loader.assert_called_once_with()

        for mutation in (
            {},
            {**exact, "extra": True},
            {**exact, "digest": "sha256:" + "b" * 64},
            {**exact, "profiles": exact["profiles"][:-1]},
        ):
            with (
                self.subTest(mutation=mutation),
                patch.object(RUNNER, "_digest_file", return_value=digest),
                patch.object(RUNNER, "_load_apparmor") as loader,
                self.assertRaisesRegex(
                    RUNNER.QualificationStop, "RECOVERY_POLICY_MISMATCH"
                ),
            ):
                RUNNER._reload_recovery_apparmor(mutation)
            loader.assert_not_called()

        with (
            patch.object(RUNNER, "_digest_file", return_value=digest),
            patch.object(
                RUNNER,
                "_load_apparmor",
                return_value={**exact, "profiles": exact["profiles"][:-1]},
            ),
            self.assertRaisesRegex(
                RUNNER.QualificationStop, "RECOVERY_POLICY_MISMATCH"
            ),
        ):
            RUNNER._reload_recovery_apparmor(exact)

    def test_controller_is_a_real_closed_principal_and_owns_live_m1_m2_mutations(self) -> None:
        policy = (ROOT / "profiles/l0-lx-a.apparmor").read_text(encoding="utf-8")
        controller_policy = policy.split(
            "profile harness-l0-lx-a.controller flags=(mediate_deleted) {", 1
        )[1].split("\n}", 1)[0]
        attestor_policy = policy.split(
            "profile harness-l0-lx-a.attestor flags=(mediate_deleted) {", 1
        )[1].split("\n}", 1)[0]
        self.assertNotIn("\n  unix,", controller_policy)
        self.assertNotIn("\n  unix,", attestor_policy)
        self.assertIn("/usr/bin/openssl ix,", controller_policy)
        for family in ("inet", "inet6", "netlink", "packet"):
            self.assertIn("audit deny network " + family + ",", controller_policy)

        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertIn('AA_EXEC, "--profile", PROFILE_LABELS["CONTROLLER"]', source)
        self.assertIn('ROLE_IDS["CONTROLLER"][0]', source)
        self.assertIn('facts["fd_inventory"] != [0, 1, 2, 3]', source)
        self.assertIn('"code_descriptor": code_descriptor', source)
        self.assertIn("code_flags & os.O_ACCMODE != os.O_RDONLY", source)
        self.assertIn('status_value.get("NoNewPrivs") != "1"', source)
        self.assertNotIn("shell=True", source)

        m2_source = source.split("def _m2_chain(", 1)[1].split("\ndef _load_apparmor(", 1)[0]
        for operation in (
            "controller.evaluate", "controller.bootstrap", "controller.issue",
            "controller.consume", "controller.claim_dispatch",
        ):
            self.assertIn(operation, m2_source)
        for bypass in (
            "bootstrapped = store.bootstrap", "issued = store.issue",
            "consumed = store.consume", "claimed = store.claim_dispatch",
        ):
            self.assertNotIn(bypass, m2_source)
        authority_source = source.split("def _authority_chain(", 1)[1].split(
            "\ndef _role_gate_prefix(", 1
        )[0]
        self.assertIn("controller.prepare_runtime_session", authority_source)
        self.assertNotIn('chain["store"].prepare_runtime_session', authority_source)

        unit = (ROOT / "profiles/harness-m3-controller@.service").read_text(encoding="utf-8")
        self.assertIn("User=root", unit)
        self.assertIn("Delegate=yes", unit)
        self.assertNotIn("User=controller", unit)

    def test_controller_result_boundary_is_closed_and_rejects_mutations(self) -> None:
        from harness_product import durable

        result = durable.DurableResult(
            durable.DurableOutcome.DENY,
            durable.DurableReason.REPLAY,
            transaction_id="transaction-1",
        )
        data = RUNNER._durable_result_data(result)
        self.assertEqual(RUNNER._durable_result_from_data(durable, data), result)
        with self.assertRaisesRegex(
            RUNNER.QualificationStop, "CONTROLLER_RESULT_MALFORMED"
        ):
            RUNNER._durable_result_data(
                durable.DurableResult(
                    durable.DurableOutcome.COMMITTED,
                    durable.DurableReason.M4_DISPATCH_BOUND,
                    transaction_id="transaction-1",
                    m4_state="DISPATCHED",
                )
            )
        mutations = []
        missing = dict(data)
        missing.pop("reason")
        mutations.append(missing)
        extra = dict(data)
        extra["verified"] = True
        mutations.append(extra)
        invalid = dict(data)
        invalid["outcome"] = "VERIFIED"
        mutations.append(invalid)
        malformed = dict(data)
        malformed["recovery_intents"] = [True]
        mutations.append(malformed)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                RUNNER.QualificationStop, "CONTROLLER_RESULT_MALFORMED"
            ):
                RUNNER._durable_result_from_data(durable, mutation)

    def test_worker_apparmor_ipc_is_only_the_preconnected_operation_pair(self) -> None:
        policy = (ROOT / "profiles/l0-lx-a.apparmor").read_text(encoding="utf-8")
        worker = policy.split(
            "profile harness-l0-lx-a.worker flags=(mediate_deleted) {", 1
        )[1].split("\n}", 1)[0]
        self.assertIn("unix (send) type=seqpacket addr=none", worker)
        self.assertIn("peer=(addr=none,label=harness-l0-lx-a.broker)", worker)
        for forbidden in ("/run/harness", "unix (create)", "unix (connect", "unix (bind", "unix (listen", "unix (accept"):
            self.assertNotIn(forbidden, worker)
        self.assertNotIn("audit deny network,", worker)
        self.assertNotIn("network unix", worker)
        self.assertNotIn("type=stream", worker)
        self.assertNotIn("type=dgram", worker)
        for family in ("inet", "inet6", "netlink", "packet"):
            self.assertIn("audit deny network " + family + ",", worker)

        broker = policy.split(
            "profile harness-l0-lx-a.broker flags=(mediate_deleted) {", 1
        )[1].split("\n}", 1)[0]
        self.assertIn("unix (getopt) type=seqpacket addr=none,", broker)
        self.assertIn("unix (receive) type=seqpacket addr=none", broker)
        self.assertIn("peer=(addr=none,label=harness-l0-lx-a.worker)", broker)
        for forbidden in ("/run/harness", "unix (create)", "unix (connect", "unix (bind", "unix (listen", "unix (accept", "unix (send"):
            self.assertNotIn(forbidden, broker)
        for family in ("inet", "inet6", "netlink", "packet"):
            self.assertIn("audit deny network " + family + ",", broker)

    def test_pathname_broker_variant_cannot_return_to_active_runtime_or_policy(self) -> None:
        runtime = RUNNER_PATH.read_text(encoding="utf-8")
        policy = (ROOT / "profiles/l0-lx-a.apparmor").read_text(encoding="utf-8")
        for forbidden in (
            "/run/harness/broker.sock",
            "broker.sock",
            "--broker-socket",
            "_prepare_broker_root",
            "_observe_broker_socket",
            "_launch_mediator_role",
            "_launch_role",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, runtime)
                self.assertNotIn(forbidden, policy)
        self.assertIn('"endpoint_mode": "UNIX_CONNECTED_PAIR"', runtime)
        self.assertIn('socket.socketpair(', runtime)

    def test_executor_staging_view_rejects_same_bytes_substitute_root(self) -> None:
        expected = {
            "root": {"device": 1, "inode": 10, "mode": 0o700, "uid": 3003, "gid": 4003},
            "target": {
                "device": 1, "inode": 11, "links": 1, "bytes": 4,
                "digest": RUNNER._digest_bytes(b"old\n"),
            },
        }
        substitute = json.loads(json.dumps(expected))
        substitute["root"]["inode"] = 12
        with self.assertRaisesRegex(
            RUNNER.QualificationStop,
            "^EXECUTOR_STAGING_ROOT_MISMATCH$",
        ):
            RUNNER._require_same_staging_view(expected, substitute)

    def test_executor_staging_view_rejects_replaced_final_object(self) -> None:
        expected = {
            "root": {"device": 1, "inode": 10, "mode": 0o700, "uid": 3003, "gid": 4003},
            "target": {
                "device": 1, "inode": 11, "links": 1, "bytes": 4,
                "digest": RUNNER._digest_bytes(b"old\n"),
            },
        }
        replaced = json.loads(json.dumps(expected))
        replaced["target"]["inode"] = 13
        with self.assertRaisesRegex(
            RUNNER.QualificationStop,
            "^EXECUTOR_STAGING_TARGET_MISMATCH$",
        ):
            RUNNER._require_same_staging_view(expected, replaced)
        RUNNER._require_same_staging_view(expected, json.loads(json.dumps(expected)))

    def test_external_canary_snapshot_is_closed_and_detects_byte_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-canaries-") as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir(mode=0o700)
            (checkout / "README.md").write_bytes(b"checkout-v1\n")
            paths = {"checkout": checkout}
            for name in ("home", "secret", "durable_db", "outside"):
                path = root / name
                path.write_bytes((name + "-v1\n").encode("ascii"))
                paths[name] = path
            before = RUNNER._external_canary_snapshot(paths)
            self.assertEqual(frozenset(before), frozenset(paths))
            paths["secret"].write_bytes(b"secret-v2\n")
            after = RUNNER._external_canary_snapshot(paths)
            self.assertNotEqual(before["secret"], after["secret"])
            self.assertEqual(before["checkout"], after["checkout"])
            with self.assertRaisesRegex(RUNNER.QualificationStop, "^CANARY_SET_MISMATCH$"):
                RUNNER._external_canary_snapshot({key: value for key, value in paths.items() if key != "outside"})

    def test_io_limit_and_device_counter_oracles_are_closed(self) -> None:
        self.assertTrue(RUNNER._io_limit_is_unbounded("", "253:0"))
        self.assertTrue(
            RUNNER._io_limit_is_unbounded(
                "253:0 rbps=max wbps=max riops=max wiops=max",
                "253:0",
            )
        )
        self.assertFalse(
            RUNNER._io_limit_is_unbounded(
                "253:0 rbps=409600 wbps=409600 riops=100 wiops=100",
                "253:0",
            )
        )
        self.assertFalse(RUNNER._io_limit_is_unbounded("253:0 rbps=max rbps=max", "253:0"))
        with tempfile.TemporaryDirectory(prefix="harness-m3-io-stat-") as directory:
            cgroup = Path(directory)
            (cgroup / "io.stat").write_text(
                "253:0 rbytes=4096 wbytes=8192 rios=1 wios=2 dbytes=0 dios=0\n",
                encoding="ascii",
            )
            self.assertEqual(
                RUNNER._io_stat_device(cgroup, "253:0")["wbytes"],
                8192,
            )
            self.assertEqual(RUNNER._io_stat_device(cgroup, "8:0")["rbytes"], 0)
            (cgroup / "io.stat").write_text("253:0\n", encoding="ascii")
            self.assertEqual(RUNNER._io_stat_device(cgroup, "253:0")["wios"], 0)
            (cgroup / "io.stat").write_text(
                "253:0 rbytes=1 wbytes=1 rios=1 wios=1\n253:0 rbytes=2 wbytes=2 rios=2 wios=2\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(RUNNER.QualificationStop, "^IO_STAT_DEVICE_DUPLICATE$"):
                RUNNER._io_stat_device(cgroup, "253:0")

    def test_cpu_time_oracle_requires_threshold_kill_and_empty_tree(self) -> None:
        self.assertTrue(RUNNER._cpu_time_oracle_valid(2_010_000, 2_000_000, -9, []))
        for mutation in (
            (1_999_999, 2_000_000, -9, []),
            (2_250_001, 2_000_000, -9, []),
            (2_010_000, 2_000_000, 0, []),
            (2_010_000, 2_000_000, -9, ["123"]),
            (True, 2_000_000, -9, []),
        ):
            with self.subTest(mutation=mutation):
                self.assertFalse(RUNNER._cpu_time_oracle_valid(*mutation))

    def test_io_probe_is_fixed_direct_bounded_and_has_no_socket_or_fork_surface(self) -> None:
        program_bytes = RUNNER._io_probe_program()
        compile(program_bytes, "<harness-m3-io-probe>", "exec")
        program = program_bytes.decode("utf-8")
        self.assertIn("os.O_DIRECT", program)
        self.assertEqual(program.count("range(96)"), 2)
        self.assertIn("/staging/io-scratch", program)
        for forbidden in ("socket", "fork(", "subprocess", "os.system", "shell=True"):
            self.assertNotIn(forbidden, program)

    def test_io_scratch_is_exactly_owned_by_executor_and_substitution_stops(self) -> None:
        executor = (os.getuid(), os.getgid(), 1003, 2003)
        device = {
            "backing_device": "8:0",
            "controller_device": "8:0",
            "binding_digest": "sha256:" + "1" * 64,
        }
        manager = SimpleNamespace(io_device=device)
        with (
            tempfile.TemporaryDirectory(prefix="harness-m3-io-scratch-") as directory,
            patch.dict(RUNNER.ROLE_IDS, {"EXECUTOR": executor}),
            patch.object(RUNNER, "_io_controller_device", return_value=device),
        ):
            path = Path(directory) / "scratch"
            record = RUNNER._create_io_scratch(path, manager)
            self.assertEqual((record["uid"], record["gid"], record["mode"]), (*executor[:2], 0o600))
            self.assertEqual(record["bytes"], 1 << 20)
            self.assertEqual(record["initialized_read_bytes"], 96 * 4096)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                self.assertEqual(os.pread(descriptor, 4096, 0), b"R" * 4096)
                self.assertEqual(os.pread(descriptor, 4096, 4096), b"\0" * 4096)
            finally:
                os.close(descriptor)

        substituted = (os.getuid() + 1, os.getgid() + 1, 1003, 2003)
        with (
            tempfile.TemporaryDirectory(prefix="harness-m3-io-scratch-mutation-") as directory,
            patch.dict(RUNNER.ROLE_IDS, {"EXECUTOR": substituted}),
            patch.object(RUNNER, "_io_controller_device", return_value=device),
            patch.object(RUNNER.os, "fchown"),
            self.assertRaisesRegex(RUNNER.QualificationStop, "^IO_SCRATCH_IDENTITY_MISMATCH$"),
        ):
            RUNNER._create_io_scratch(Path(directory) / "scratch", manager)

    def test_quota_probe_is_fixed_and_closed_to_one_executor_staging_root(self) -> None:
        program_bytes = RUNNER._quota_probe_program()
        compile(program_bytes, "<harness-m3-quota-probe>", "exec")
        program = program_bytes.decode("utf-8")
        self.assertIn("range(15)", program)
        self.assertIn("/staging/quota-%02d", program)
        self.assertIn("os.pwrite(descriptor,b'X',4096)", program)
        for forbidden in (
            "socket", "subprocess", "fork(", "os.system", "shell=True",
            "/run/harness", "broker.sock", "/home/", "/opt/harness",
        ):
            self.assertNotIn(forbidden, program)

    def test_quota_oracle_rejects_every_bound_and_identity_mutation(self) -> None:
        result = {
            "files": 16,
            "inodes": 17,
            "logical_bytes": 4096,
            "allocated_bytes": 4096,
            "create_errno": 28,
            "append_errno": 28,
        }
        host = {
            **result,
            "entries": ["artifact.txt", *(f"quota-{index:02d}" for index in range(15))],
            "owners_match": True,
            "modes_match": True,
            "links_match": True,
            "statvfs_files": 17,
            "statvfs_free": 0,
        }
        self.assertTrue(
            RUNNER._quota_oracle_valid(
                result, host, files=16, inodes=17, output_bytes=4096
            )
        )
        mutations: list[tuple[object, object, object, object, object]] = []
        for key in result:
            changed = dict(result)
            changed[key] = True if key == "files" else result[key] + 1
            mutations.append((changed, host, 16, 17, 4096))
        for key in host:
            changed = dict(host)
            if key == "entries":
                changed[key] = list(reversed(host[key]))
            elif type(host[key]) is bool:
                changed[key] = False
            else:
                changed[key] = host[key] + 1
            mutations.append((result, changed, 16, 17, 4096))
        mutations.extend(
            (
                (result, host, 15, 17, 4096),
                (result, host, 16, 18, 4096),
                (result, host, 16, 17, 8192),
                ({**result, "verified": True}, host, 16, 17, 4096),
                (result, {**host, "verified": True}, 16, 17, 4096),
            )
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertFalse(
                    RUNNER._quota_oracle_valid(
                        mutation[0], mutation[1],
                        files=mutation[2], inodes=mutation[3], output_bytes=mutation[4],
                    )
                )

    def test_run_and_recovery_test_event_sets_are_exact_closed_and_phase_bound(self) -> None:
        tests = []
        events = []
        for test_id in RUNNER.TEST_MATRIX:
            event = RUNNER._event(
                test_id,
                "TCB_RECOVERY" if test_id == "T-M3-RESTART-CLEANUP-NO-RESUME" else "TCB_DENY",
                "subject",
                {"test": test_id},
                {"expected": True},
            )
            events.append(event)
            tests.append(
                RUNNER._test_row(
                    test_id,
                    "closed exact oracle",
                    event["event_id"],
                    phase="recover" if test_id == "T-M3-RESTART-CLEANUP-NO-RESUME" else "run",
                )
            )
        RUNNER._validate_test_event_set(tests, events, frozenset(RUNNER.TEST_MATRIX))
        mutations = []
        mutations.append((tests[:-1], events[:-1]))
        mutations.append(([*tests, tests[0]], [*events, events[0]]))
        wrong_phase = [dict(row) for row in tests]
        restart_index = next(
            index
            for index, row in enumerate(wrong_phase)
            if row["id"] == "T-M3-RESTART-CLEANUP-NO-RESUME"
        )
        wrong_phase[restart_index]["command"] = [
            RUNNER.PYTHON,
            str(RUNNER.SOURCE / "scripts/run_m3_vm_conformance.py"),
            "--phase",
            "run",
        ]
        mutations.append((wrong_phase, events))
        wrong_digest = [dict(row) for row in events]
        wrong_digest[0]["observed_digest"] = "sha256:" + "0" * 63
        mutations.append((tests, wrong_digest))
        extra = [dict(row) for row in tests]
        extra[0]["verified"] = True
        mutations.append((extra, events))
        orphan = [dict(row) for row in events]
        orphan[0]["test_id"] = tests[1]["id"]
        mutations.append((tests, orphan))
        for mutated_tests, mutated_events in mutations:
            with self.subTest(
                tests=len(mutated_tests), events=len(mutated_events)
            ), self.assertRaises(RUNNER.QualificationStop):
                RUNNER._validate_test_event_set(
                    mutated_tests, mutated_events, frozenset(RUNNER.TEST_MATRIX)
                )

    def test_recovery_state_is_outside_deleted_runtime_and_cleanup_is_explicit(self) -> None:
        source = (ROOT / "scripts/run_m3_vm_conformance.py").read_text(encoding="utf-8")
        self.assertEqual(RUNNER.RUN_STATE, RUNNER.CONTROLLER / "run-state.json")
        self.assertIn("shutil.rmtree(RUNTIME)", source)
        self.assertIn("_close_non_stdio_descriptors()", source)
        self.assertIn("_validate_test_event_set(tests, events, frozenset(TEST_MATRIX))", source)
        self.assertNotIn('RUN_STATE = RUNTIME / "run-state.json"', source)
        self.assertNotIn('_replace_exact(RUNTIME / "last-failure.json"', source)

    def test_descriptor_cleanup_ignores_only_the_closed_proc_inventory_fd(self) -> None:
        closed = OSError(9, "bad descriptor")
        with (
            patch.object(RUNNER.os, "listdir", return_value=["0", "1", "2", "3"]),
            patch.object(RUNNER.os, "fstat", side_effect=closed),
            patch.object(RUNNER.os, "close") as close,
        ):
            result = RUNNER._close_non_stdio_descriptors()
        self.assertEqual(result["closed_count"], 0)
        self.assertEqual(result["remaining_non_stdio"], [])
        close.assert_not_called()

        with (
            patch.object(RUNNER.os, "listdir", side_effect=[["9"], []]),
            patch.object(RUNNER.os, "fstat", return_value=SimpleNamespace()),
            patch.object(RUNNER.os, "readlink", return_value="pipe:[9]"),
            patch.object(RUNNER.os, "close") as close,
        ):
            result = RUNNER._close_non_stdio_descriptors()
        self.assertEqual(result["closed_count"], 1)
        self.assertEqual(result["remaining_non_stdio"], [])
        close.assert_called_once_with(9)

    def test_role_seccomp_extensions_do_not_widen_worker_filter(self) -> None:
        base = json.loads((ROOT / "profiles/l0-lx-a-seccomp.json").read_bytes())
        expected = {
            "BROKER": (
                "l0-lx-a-broker-seccomp.json",
                (47, 55),
                "sha256:e369172f90805d26e64eb39f0617bb5763f6a2998cb3d89dd8aa4c93b4c343c5",
            ),
            "EXECUTOR": (
                "l0-lx-a-executor-seccomp.json",
                (18, 73, 77, 437),
                "sha256:a10478b8d8380358334c518eade819489dc4739aea98d71f6fd82a3d3a83044a",
            ),
        }
        for role, (filename, additions, digest) in expected.items():
            raw = json.loads((ROOT / "profiles" / filename).read_bytes())
            with self.subTest(role=role):
                self.assertEqual(tuple(raw["additional_syscalls"]), additions)
                self.assertTrue(set(additions).isdisjoint(base["syscalls"]))
                program = RUNNER._compile_role_seccomp(raw, base, role)
                self.assertEqual(RUNNER._digest_bytes(program), digest)

                for key, value in (
                    ("role", "AGENT_WORKER"),
                    ("base_profile_digest", "sha256:" + "0" * 64),
                    ("additional_syscalls", list(reversed(additions))),
                ):
                    mutation = dict(raw)
                    mutation[key] = value
                    with self.assertRaisesRegex(RUNNER.QualificationStop, "SECCOMP_POLICY_MALFORMED"):
                        RUNNER._compile_role_seccomp(mutation, base, role)

        for server_syscall in (41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288):
            self.assertNotIn(server_syscall, base["syscalls"])

    def test_resource_vector_is_finite_and_matches_runtime_readbacks(self) -> None:
        raw = json.loads((ROOT / "profiles/l0-lx-a.json").read_bytes())
        resources = {row["resource"]: row["limit"] for row in raw["resources"]}
        self.assertEqual(
            resources,
            {
                "CPU_TIME": 2000,
                "CPU_RATE": 500,
                "WALL_TIME": 3000,
                "MEMORY": 128,
                "SWAP": 0,
                "PIDS": 8,
                "BLOCK_IO_READ": 100,
                "BLOCK_IO_WRITE": 100,
                "FILES": 16,
                "INODES": 17,
                "OPEN_FDS": 32,
                "OUTPUT_BYTES": 4096,
                "GPU_TIME": 0,
                "GPU_MEMORY": 0,
            },
        )
        self.assertFalse(any(row["limit"] == "max" for row in raw["resources"]))

    def test_cgroup_counter_parser_is_closed_and_accepts_kernel_dotted_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-counters-") as directory:
            root = Path(directory)
            (root / "cpu.stat").write_text(
                "usage_usec 12\ncore_sched.force_idle_usec 0\nnr_throttled 1\n",
                encoding="ascii",
            )
            self.assertEqual(
                RUNNER._cgroup_values(root, "cpu.stat"),
                {"usage_usec": 12, "core_sched.force_idle_usec": 0, "nr_throttled": 1},
            )
            for content in (
                "usage_usec -1\n",
                "usage_usec 1 extra\n",
                "usage_usec 1\nusage_usec 2\n",
                "bad/key 1\n",
                "",
            ):
                (root / "cpu.stat").write_text(content, encoding="ascii")
                with self.subTest(content=content), self.assertRaises(RUNNER.QualificationStop):
                    RUNNER._cgroup_values(root, "cpu.stat")

    def test_exact_runner_m1_request_allows_only_the_bound_stage_write(self) -> None:
        from harness_product import Outcome, evaluate

        times = RUNNER._qualification_times(datetime(2026, 8, 26, 12, 0, tzinfo=UTC))
        request = RUNNER._m1_request(times, "qualified-stage\n")
        result = evaluate(request)
        self.assertIs(result.decision.outcome, Outcome.ALLOW)
        self.assertTrue(result.transition.accepted)
        self.assertEqual(len(result.transition.proposals), 1)
        self.assertEqual(result.transition.proposals[0].authority.value, "NONE")

        for field, value in (
            ("operation_id", "other-operation"),
            ("material_digest", RUNNER._digest_bytes(b"substituted")),
        ):
            subject = json.loads(json.dumps(request))
            subject["proposal"][field] = value
            self.assertIsNot(evaluate(subject).decision.outcome, Outcome.ALLOW)
        unbounded = json.loads(json.dumps(request))
        unbounded["proposal"]["authority"]["max_quantity"] = "unbounded"
        self.assertIsNot(evaluate(unbounded).decision.outcome, Outcome.ALLOW)

    def test_authoritative_transition_times_are_observed_not_predeclared_future(self) -> None:
        fixed = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
        times = RUNNER._qualification_times(fixed)
        for key in ("consume_at", "claim_at", "prepare_at", "terminal_at"):
            self.assertEqual(times[key], "2026-08-26T12:00:00Z")
        self.assertEqual(
            RUNNER._transition_time(
                times["issued_at"],
                datetime(2026, 8, 26, 12, 0, 1, tzinfo=UTC),
            ),
            "2026-08-26T12:00:01Z",
        )
        with self.assertRaisesRegex(RUNNER.QualificationStop, "CLOCK_ROLLBACK"):
            RUNNER._transition_time(
                "2026-08-26T12:00:01Z",
                datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC),
            )
        with self.assertRaisesRegex(RUNNER.QualificationStop, "TIME_MALFORMED"):
            RUNNER._transition_time("not-a-time", fixed)

    def test_capability_lifetime_is_bounded_by_trusted_facts_before_verifier(self) -> None:
        import harness_product.l0 as l0
        from harness_product.durable import (
            DurableOutcome,
            DurableReason,
            DurableStore,
            canonical_digest,
        )

        times = RUNNER._qualification_times(datetime(2026, 8, 26, 12, 0, tzinfo=UTC))
        self.assertLess(times["expires_at"], times["facts_expires_at"])
        profile = l0.compile_profile(json.loads((ROOT / "profiles/l0-lx-a.json").read_bytes())).profile
        self.assertIsNotNone(profile)
        lineage = RUNNER._digest_bytes(RUNNER._canonical({"lineage": "l0-vm-test"}))
        scope = canonical_digest({"kind": "PATH_EXACT", "value": "/staging/artifact.txt"})

        def issue(database: Path, facts_expiry: str) -> tuple[object, RUNNER.CaptureVerifier]:
            capture = RUNNER.CaptureVerifier()
            store = DurableStore(str(database), capture)
            self.assertIs(
                store.bootstrap(
                    {
                        "lineage_root": lineage,
                        "revocation_epoch": 0,
                        "fencing_epoch": 1,
                        "budgets": [
                            {
                                "name": "writes",
                                "unit": "FILES",
                                "scope_digest": scope,
                                "lineage_root": lineage,
                                "limit": 1,
                            }
                        ],
                    }
                ).outcome,
                DurableOutcome.COMMITTED,
            )
            request = RUNNER._m1_request(times, "qualified-stage\n")
            request["trusted_facts"]["expires_at"] = facts_expiry
            result = store.issue(
                {
                    "request": request,
                    "audience_id": "executor-3",
                    "purpose": "stageable-local-write",
                    "contract_digest": RUNNER._digest_bytes(b"contract"),
                    "registry_digest": RUNNER._digest_bytes(b"registry"),
                    "profile_digest": profile.profile_digest,
                    "placement_digest": RUNNER._digest_bytes(b"placement"),
                    "session_id": "session-1",
                    "lineage_root": lineage,
                    "nonce": "nonce-m3-runtime-1",
                    "issued_at": times["issued_at"],
                    "not_before": times["not_before"],
                    "expires_at": times["expires_at"],
                    "revocation_epoch": 0,
                    "fencing_epoch": 1,
                    "idempotency_key_digest": RUNNER._digest_bytes(b"attempt"),
                    "budget": [
                        {
                            "name": "writes",
                            "unit": "FILES",
                            "scope_digest": scope,
                            "lineage_root": lineage,
                            "amount": 1,
                        }
                    ],
                    "verification": RUNNER._verification_source(),
                }
            )
            return result, capture

        with tempfile.TemporaryDirectory(prefix="harness-m3-lifetime-") as directory:
            valid, valid_capture = issue(Path(directory) / "valid.sqlite3", times["facts_expires_at"])
            self.assertIs(valid.outcome, DurableOutcome.DENY)
            self.assertIs(valid.reason, DurableReason.CAPABILITY_INVALID)
            self.assertIsNotNone(valid_capture.payload)

            stale, stale_capture = issue(
                Path(directory) / "stale.sqlite3", "2026-08-26T12:10:00Z"
            )
            self.assertIs(stale.outcome, DurableOutcome.DENY)
            self.assertIs(stale.reason, DurableReason.EXPIRED)
            self.assertIsNone(stale_capture.payload)

    def test_worker_ipc_stays_bounded_and_cannot_supply_authority_sources(self) -> None:
        import harness_product.l0 as l0
        from harness_product import Outcome, evaluate

        profile = l0.compile_profile(json.loads((ROOT / "profiles/l0-lx-a.json").read_bytes())).profile
        self.assertIsNotNone(profile)
        trusted = RUNNER._m1_request(
            RUNNER._qualification_times(datetime(2026, 8, 26, 12, 0, tzinfo=UTC)),
            "qualified-stage\n",
        )
        packet = RUNNER._worker_packet(profile, trusted)
        self.assertLessEqual(len(packet), 1024)
        value = json.loads(packet)
        contribution = value["proposal"]
        self.assertEqual(
            {name: contribution[name] for name in ("manifest", "policy", "physical_ceiling", "trusted_facts")},
            {"manifest": {}, "policy": {}, "physical_ceiling": {}, "trusted_facts": {}},
        )
        self.assertIsNot(evaluate(contribution).decision.outcome, Outcome.ALLOW)
        self.assertEqual(contribution["proposal"], trusted["proposal"])
        with self.assertRaises(RUNNER.QualificationStop):
            RUNNER._worker_program(b"x" * 1025)

    def test_io_controller_is_bound_to_measured_backing_partition_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-sysfs-") as directory:
            sysfs = Path(directory)
            partition = sysfs / "devices/block/vda/vda1"
            partition.mkdir(parents=True)
            (partition / "partition").write_text("1\n", encoding="ascii")
            (partition.parent / "dev").write_text("253:0\n", encoding="ascii")
            links = sysfs / "dev/block"
            links.mkdir(parents=True)
            (links / "253:1").symlink_to(partition)
            (links / "253:0").symlink_to(partition.parent)
            binding = RUNNER._io_controller_device(
                Path("/measured/staging"), sysfs, device_number=os.makedev(253, 1)
            )
            self.assertEqual(
                {key: binding[key] for key in ("backing_device", "controller_device", "partition")},
                {"backing_device": "253:1", "controller_device": "253:0", "partition": True},
            )
            self.assertRegex(binding["binding_digest"], r"^sha256:[0-9a-f]{64}$")

            (partition.parent / "dev").write_text("8:0\n", encoding="ascii")
            with self.assertRaises(RUNNER.QualificationStop):
                RUNNER._io_controller_device(
                    Path("/measured/staging"), sysfs, device_number=os.makedev(253, 1)
                )

    def test_delegated_measurement_binds_empty_parent_not_supervisor_leaf(self) -> None:
        import harness_product.l0 as l0

        profile = l0.compile_profile(json.loads((ROOT / "profiles/l0-lx-a.json").read_bytes())).profile
        self.assertIsNotNone(profile)
        with tempfile.TemporaryDirectory(prefix="harness-m3-delegated-") as directory:
            parent = Path(directory) / "unit"
            supervisor = parent / "manager"
            supervisor.mkdir(parents=True)
            (parent / "cgroup.controllers").write_text("cpu io memory pids\n", encoding="ascii")
            (parent / "cgroup.subtree_control").write_text("cpu io memory pids\n", encoding="ascii")
            (parent / "cgroup.procs").write_text("", encoding="ascii")
            (supervisor / "cgroup.procs").write_text(str(os.getpid()) + "\n", encoding="ascii")
            parent_path = str(parent)
            fields = {
                "backend_path": profile.backend_path,
                "backend_version": profile.backend_version,
                "backend_digest": profile.backend_digest,
                "aa_exec_path": l0.AA_EXEC_PATH,
                "aa_exec_digest": l0.AA_EXEC_DIGEST,
                "architecture": "x86_64",
                "kernel_release": "6.8.0-test",
                "kernel_features": tuple(sorted(l0._KERNEL_FEATURES)),
                "cgroup_path": parent_path,
                "cgroup_controllers": ("cpu", "io", "memory", "pids"),
                "lsm_stack": ("apparmor",),
                "lsm_policy_name": "harness-l0-lx-a",
                "apparmor_profiles": tuple(sorted(l0._APPARMOR_PROFILES)),
                "openat2": True,
                "user_namespaces": True,
            }
            digest_data = {**fields, "kernel_features": list(fields["kernel_features"]), "cgroup_controllers": list(fields["cgroup_controllers"]), "lsm_stack": list(fields["lsm_stack"]), "apparmor_profiles": list(fields["apparmor_profiles"]), "profile_digest": profile.profile_digest}
            measurement = l0.HostMeasurement(
                **fields, measurement_digest=l0._hash_text(l0._canonical(digest_data))
            )
            manager = SimpleNamespace(root=parent, manager=supervisor)
            bound = RUNNER._delegated_measurement(profile, measurement, manager)
            self.assertEqual(bound.cgroup_path, str(parent))
            self.assertTrue(l0._measurement_is_valid(profile, bound))

            (parent / "cgroup.procs").write_text("999\n", encoding="ascii")
            with self.assertRaises(RUNNER.QualificationStop):
                RUNNER._delegated_measurement(profile, measurement, manager)

    def test_supervisor_user_namespace_record_is_closed_exact_and_zero_limited(self) -> None:
        valid = self.namespace_record()
        self.assertEqual(RUNNER._validate_user_namespace_record("AGENT_WORKER", valid), valid)
        procfs_formatted = dict(valid)
        procfs_formatted["uid_map"] = "         0     100000          1\n      1001       3001          1\n"
        procfs_formatted["gid_map"] = "         0     200000          1\n      2001       4001          1\n"
        self.assertEqual(RUNNER._validate_user_namespace_record("AGENT_WORKER", procfs_formatted), valid)
        mutations = []
        for field, value in (
            ("max_user_namespaces", 1),
            ("uid_map", "0 0 1\n"),
            ("gid_map", "0 0 1\n"),
            ("setgroups", "allow"),
            ("identity", "user:[3]"),
            ("descriptor", True),
        ):
            subject = dict(valid)
            subject[field] = value
            mutations.append(subject)
        extra = dict(valid)
        extra["verified"] = True
        mutations.append(extra)
        for subject in mutations:
            with self.subTest(subject=subject), self.assertRaises(RUNNER.QualificationStop):
                RUNNER._validate_user_namespace_record("AGENT_WORKER", subject)

    def test_namespace_fd_substitution_is_detected_from_kernel_identity(self) -> None:
        descriptor = os.open("/proc/self/ns/user", os.O_RDONLY | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            subject = self.namespace_record(descriptor=descriptor)
            subject.update(
                device=info.st_dev,
                inode=info.st_ino,
                identity=os.readlink(f"/proc/self/fd/{descriptor}"),
            )
            self.assertEqual(RUNNER._verify_user_namespace_fd(descriptor, subject), subject)
            substituted = dict(subject)
            substituted["inode"] += 1
            substituted["identity"] = f"user:[{substituted['inode']}]"
            with self.assertRaises(RUNNER.QualificationStop):
                RUNNER._verify_user_namespace_fd(descriptor, substituted)
        finally:
            os.close(descriptor)

    def test_runtime_argv_requires_userns_fd_assertion_and_single_operation_fd(self) -> None:
        valid = [
            RUNNER.BWRAP,
            "--userns", "9",
            "--assert-userns-disabled",
            "--block-fd", "21",
            "--json-status-fd", "22",
            "--sync-fd", "20",
        ]
        self.assertEqual(RUNNER._validate_runtime_argv(valid, 9), tuple(valid))
        prepared = valid[:-2]
        self.assertEqual(
            RUNNER._validate_runtime_argv(prepared, 9, prepared=True), tuple(prepared)
        )
        with self.assertRaises(RUNNER.QualificationStop):
            RUNNER._validate_runtime_argv(valid, 9, prepared=True)
        mutations = (
            [item for item in valid if item != "--assert-userns-disabled"],
            [RUNNER.BWRAP, "--userns", "8", "--assert-userns-disabled", "--block-fd", "21", "--json-status-fd", "22", "--sync-fd", "20"],
            [RUNNER.BWRAP, "--userns", "9", "--assert-userns-disabled", "--block-fd", "21", "--json-status-fd", "22", "--sync-fd", "3"],
            [*valid, "--disable-userns"],
            [*valid, "--unshare-user"],
            [*valid, "--uid", "1001"],
            [*valid, "--gid", "2001"],
            [*valid, "--sync-fd", "4"],
        )
        for subject in mutations:
            with self.subTest(subject=subject), self.assertRaises(RUNNER.QualificationStop):
                RUNNER._validate_runtime_argv(subject, 9)

    def test_role_gate_remaps_preserved_stdin_closes_every_other_fd_before_start(self) -> None:
        program = RUNNER._role_gate_prefix()
        self.assertIn(b"sys.argv[1:]!=['--broker-fd', '1'", program)
        self.assertIn(b"os.listdir('/proc/self/fd')", program)
        self.assertIn(b"if descriptor not in (0,1)", program)
        self.assertIn(b"if os.read(0,5)!=b'START'", program)
        self.assertIn(b"os.close(0)", program)
        self.assertNotIn(b"broker.sock", program)
        self.assertNotIn(b"shell", program)

    def test_negative_probe_contract_has_only_a_closed_pipe_start_gate(self) -> None:
        program = RUNNER._probe_program("direct-write")
        self.assertIn(b"pids_sessions=tuple('probe-pids-hold-'", program)
        self.assertIn(b"session!='probe-'+kind", program)
        self.assertIn(b"kind=sys.argv[2]", program)
        self.assertIn(b"if descriptor!=0", program)
        self.assertIn(b"if os.read(0,5)!=b'START'", program)
        self.assertIn(b"os.close(0)", program)
        for forbidden in (
            b"socket.socketpair", b".connect(", b"sendmsg", b"recvmsg",
            b"SCM_RIGHTS", b"--sync-fd", b"broker.sock",
        ):
            self.assertNotIn(forbidden, program)
        for kind in ("network", "kernel", "fd-limit", "cpu-rate", "cpu-time", "memory", "pids-hold", "timeout"):
            self.assertEqual(RUNNER._probe_program(kind), program)
        with self.assertRaisesRegex(RUNNER.QualificationStop, "UNKNOWN_PROBE"):
            RUNNER._probe_program("unknown")

    def test_preexec_attaches_and_reads_back_cgroup_before_exact_identity_drop(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-cgroup-") as directory:
            cgroup = Path(directory)
            (cgroup / "cgroup.procs").write_text("", encoding="ascii")
            calls: list[str] = []
            with (
                patch.object(RUNNER.os, "getpid", return_value=123),
                patch.object(RUNNER.os, "setgroups", side_effect=lambda groups: calls.append(f"groups:{groups}")),
                patch.object(RUNNER.os, "setgid", side_effect=lambda value: calls.append(f"gid:{value}")),
                patch.object(RUNNER.os, "setuid", side_effect=lambda value: calls.append(f"uid:{value}")),
                patch.object(RUNNER.os, "setsid", side_effect=lambda: calls.append("setsid")),
                patch.object(RUNNER.resource, "setrlimit", side_effect=lambda *_: calls.append("rlimit")),
                patch.object(RUNNER.os, "dup2", side_effect=lambda source, target, **_: calls.append(f"dup2:{source}:{target}")),
            ):
                RUNNER._preexec("AGENT_WORKER", ((20, 0),), 32, cgroup)()
            self.assertEqual((cgroup / "cgroup.procs").read_text(encoding="ascii"), "123")
            self.assertEqual(
                calls,
                ["setsid", "dup2:20:0", "groups:[]", "gid:4001", "uid:3001", "rlimit"],
            )

    def test_trusted_principal_snapshot_retries_proc_fd_race_and_stops_boundedly(self) -> None:
        process = SimpleNamespace(pid=123, poll=lambda: None)
        observation = {"process_id": 123, "fd_inventory": [0, 1, 2, 3]}
        with (
            patch.object(
                RUNNER,
                "_trusted_domain_observation",
                side_effect=[FileNotFoundError("closed fd"), observation],
            ) as snapshot,
            patch.object(RUNNER.time, "monotonic", side_effect=[0.0, 0.1, 0.2]),
            patch.object(RUNNER.time, "sleep"),
        ):
            self.assertEqual(
                RUNNER._wait_trusted_domain(
                    process, "CONTROLLER", Path("/sys/fs/cgroup/test"), uid=3000, gid=4000
                ),
                observation,
            )
            self.assertEqual(snapshot.call_count, 2)

        with (
            patch.object(
                RUNNER,
                "_trusted_domain_observation",
                side_effect=FileNotFoundError("closed fd"),
            ),
            patch.object(RUNNER.time, "monotonic", side_effect=[0.0, 2.0]),
            patch.object(RUNNER.time, "sleep"),
            self.assertRaisesRegex(
                RUNNER.QualificationStop, "TRUSTED_DOMAIN_TRANSITION_ABSENT"
            ),
        ):
            RUNNER._wait_trusted_domain(
                process,
                "CONTROLLER",
                Path("/sys/fs/cgroup/test"),
                uid=3000,
                gid=4000,
                timeout=1,
            )

    def test_successful_preexec_diagnostic_cleanup_is_exact_and_mutation_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            diagnostic = runtime / "preexec-failure.txt"
            with patch.object(RUNNER, "RUNTIME", runtime):
                diagnostic.write_bytes(b"")
                diagnostic.chmod(0o600)
                RUNNER._consume_empty_preexec_diagnostic()
                self.assertFalse(diagnostic.exists())

                for mutation in ("missing", "nonempty", "mode", "symlink"):
                    with self.subTest(mutation=mutation):
                        diagnostic.unlink(missing_ok=True)
                        target = runtime / "target"
                        target.unlink(missing_ok=True)
                        if mutation == "nonempty":
                            diagnostic.write_bytes(b"failure")
                            diagnostic.chmod(0o600)
                        elif mutation == "mode":
                            diagnostic.write_bytes(b"")
                            diagnostic.chmod(0o644)
                        elif mutation == "symlink":
                            target.write_bytes(b"")
                            diagnostic.symlink_to(target)
                        with self.assertRaisesRegex(
                            RUNNER.QualificationStop, "PREEXEC_DIAGNOSTIC_MISMATCH"
                        ):
                            RUNNER._consume_empty_preexec_diagnostic()
                        if mutation != "missing":
                            self.assertTrue(diagnostic.exists() or diagnostic.is_symlink())

    def test_signing_runtime_consumes_marker_after_final_manager_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o711)
            diagnostic = runtime / "preexec-failure.txt"

            class Manager:
                def cleanup(self) -> None:
                    diagnostic.write_bytes(b"")
                    diagnostic.chmod(0o600)

            with patch.object(RUNNER, "RUNTIME", runtime):
                RUNNER._cleanup_signing_runtime(Manager(), True)
            self.assertFalse(runtime.exists())

            runtime.mkdir(mode=0o711)
            with patch.object(RUNNER, "RUNTIME", runtime):
                RUNNER._cleanup_signing_runtime(Manager(), False)
            self.assertFalse(runtime.exists())

            runtime.mkdir(mode=0o711)

            class FailedManager:
                def cleanup(self) -> None:
                    diagnostic.write_bytes(b"preexec failed")
                    diagnostic.chmod(0o600)

            with (
                patch.object(RUNNER, "RUNTIME", runtime),
                self.assertRaisesRegex(
                    RUNNER.QualificationStop, "PREEXEC_DIAGNOSTIC_MISMATCH"
                ),
            ):
                RUNNER._cleanup_signing_runtime(FailedManager(), True)
            self.assertTrue(diagnostic.exists())

    def test_preexec_enters_exact_user_namespace_before_namespace_root_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-cgroup-userns-") as directory:
            cgroup = Path(directory)
            (cgroup / "cgroup.procs").write_text("", encoding="ascii")
            calls: list[str] = []
            libc = SimpleNamespace(setns=lambda descriptor, kind: calls.append(f"setns:{descriptor}:{kind}") or 0)
            target_info = SimpleNamespace(st_dev=4, st_ino=41)
            parent_info = SimpleNamespace(st_dev=4, st_ino=40)
            host_info = SimpleNamespace(st_dev=4, st_ino=1)
            with (
                patch.object(RUNNER.os, "getpid", return_value=123),
                patch.object(RUNNER.os, "getuid", return_value=1001),
                patch.object(RUNNER.os, "getgid", return_value=2001),
                patch.object(RUNNER.os, "setgroups", side_effect=lambda groups: calls.append(f"groups:{groups}")),
                patch.object(RUNNER.os, "setgid", side_effect=lambda value: calls.append(f"gid:{value}")),
                patch.object(RUNNER.os, "setuid", side_effect=lambda value: calls.append(f"uid:{value}")),
                patch.object(RUNNER.os, "setsid", side_effect=lambda: calls.append("setsid")),
                patch.object(RUNNER.resource, "setrlimit", side_effect=lambda *_: calls.append("rlimit")),
                patch.object(RUNNER.ctypes, "CDLL", return_value=libc),
                patch.object(RUNNER.fcntl, "ioctl", return_value=10),
                patch.object(
                    RUNNER.os, "fstat",
                    side_effect=lambda descriptor: target_info if descriptor == 9 else parent_info,
                ),
                patch.object(RUNNER.os, "stat", return_value=host_info),
                patch.object(RUNNER.os, "close", side_effect=lambda descriptor: calls.append(f"close:{descriptor}")),
            ):
                RUNNER._preexec(
                    "AGENT_WORKER", (), 32, cgroup, user_namespace_fd=9
                )()
            self.assertEqual(
                calls,
                [
                    "setsid", "groups:[]", f"setns:10:{RUNNER.CLONE_NEWUSER}",
                    "close:10", "gid:2001", "uid:1001", "rlimit",
                ],
            )

    def test_preexec_rejects_host_or_target_namespace_as_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-cgroup-userns-parent-") as directory:
            cgroup = Path(directory)
            (cgroup / "cgroup.procs").write_text("", encoding="ascii")
            info = SimpleNamespace(st_dev=4, st_ino=41)
            libc = SimpleNamespace(setns=lambda *_: self.fail("setns must not run") or 0)
            with (
                patch.object(RUNNER.os, "getpid", return_value=123),
                patch.object(RUNNER.os, "setgroups"),
                patch.object(RUNNER.os, "setsid"),
                patch.object(RUNNER.resource, "setrlimit"),
                patch.object(RUNNER.ctypes, "CDLL", return_value=libc),
                patch.object(RUNNER.fcntl, "ioctl", return_value=10),
                patch.object(RUNNER.os, "fstat", return_value=info),
                patch.object(RUNNER.os, "stat", return_value=SimpleNamespace(st_dev=4, st_ino=1)),
                patch.object(RUNNER.os, "close"),
                self.assertRaises(OSError),
            ):
                RUNNER._preexec(
                    "AGENT_WORKER", (), 32, cgroup, user_namespace_fd=9
                )()

    def test_bwrap_control_fd_is_duplicated_above_reserved_operation_fd(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            protected = RUNNER._duplicate_high(read_fd)
            try:
                self.assertGreaterEqual(protected, 20)
                self.assertNotEqual(protected, 3)
                self.assertTrue(os.get_inheritable(protected) is False)
            finally:
                os.close(protected)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_dependency_closure_preserves_loader_alias_and_closes_bad_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-loader-") as directory:
            root = Path(directory)
            target = root / "libffi.so.8.1.2"
            alias = root / "libffi.so.8"
            target.write_bytes(b"measured-library")
            alias.symlink_to(target.name)
            completed = RUNNER.subprocess.CompletedProcess(
                ["/usr/bin/ldd", "/measured/tool"], 0,
                stdout=f"libffi.so.8 => {alias} (0x1)\n".encode("utf-8"),
                stderr=b"",
            )
            with patch.object(RUNNER, "_run", return_value=completed):
                self.assertEqual(RUNNER._dynamic_dependencies([Path("/measured/tool")]), [alias])

            target.unlink()
            target.mkdir()
            with (
                patch.object(RUNNER, "_run", return_value=completed),
                self.assertRaises(RUNNER.QualificationStop),
            ):
                RUNNER._dynamic_dependencies([Path("/measured/tool")])

            alias.unlink()
            target.rmdir()
            with (
                patch.object(RUNNER, "_run", return_value=completed),
                self.assertRaises(RUNNER.QualificationStop),
            ):
                RUNNER._dynamic_dependencies([Path("/measured/tool")])

    def test_dependency_package_is_bound_to_resolved_bytes_not_diversion_alias(self) -> None:
        with tempfile.TemporaryDirectory(prefix="harness-m3-package-") as directory:
            root = Path(directory)
            resolved = root / "ld-linux-x86-64.so.2"
            alias = root / "loader"
            resolved.write_bytes(b"measured-loader")
            alias.symlink_to(resolved.name)

            def exact_owner(argv: list[str], **_: object) -> object:
                if "--search" in argv:
                    self.assertEqual(argv[-1], str(resolved))
                    return RUNNER.subprocess.CompletedProcess(
                        argv, 0, stdout=(f"libc6:amd64: {resolved}\n").encode(), stderr=b""
                    )
                self.assertEqual(argv[-1], "libc6:amd64")
                return RUNNER.subprocess.CompletedProcess(
                    argv, 0, stdout=b"libc6:amd64\t2.39-0ubuntu8.6", stderr=b""
                )

            with patch.object(RUNNER, "_run", side_effect=exact_owner):
                self.assertEqual(
                    RUNNER._package_metadata(alias),
                    ("libc6:amd64", "2.39-0ubuntu8.6"),
                )

            ambiguous = RUNNER.subprocess.CompletedProcess(
                ["/usr/bin/dpkg-query", "--search", str(resolved)],
                0,
                stdout=(
                    f"libc6:amd64: {resolved}\n"
                    f"other-package: {resolved}\n"
                ).encode(),
                stderr=b"",
            )
            with (
                patch.object(RUNNER, "_run", return_value=ambiguous),
                self.assertRaises(RUNNER.QualificationStop),
            ):
                RUNNER._package_metadata(alias)

    def test_exact_writer_retries_partial_writes_and_stops_on_zero_progress(self) -> None:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        real_write = os.write
        try:
            with patch.object(
                RUNNER.os,
                "write",
                side_effect=lambda descriptor, data: real_write(descriptor, bytes(data[:2])),
            ):
                RUNNER._write_all(write_fd, b"abcdef", "TEST_SHORT_WRITE")
            os.close(write_fd)
            write_fd = -1
            self.assertEqual(os.read(read_fd, 16), b"abcdef")
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

        with (
            patch.object(RUNNER.os, "write", return_value=0),
            self.assertRaisesRegex(RUNNER.QualificationStop, "TEST_SHORT_WRITE"),
        ):
            RUNNER._write_all(9, b"x", "TEST_SHORT_WRITE")

    def test_controller_and_executor_share_the_same_full_fail_closed_verifier_matrix(self) -> None:
        from harness_product.durable import VerificationStatus
        from harness_product.verification import OpenSSLEd25519Verifier

        with tempfile.TemporaryDirectory(prefix="harness-m3-ed25519-") as directory:
            root = Path(directory)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            payload_path = root / "payload.json"
            subprocess.run(
                ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
                check=True, shell=False, capture_output=True, timeout=5,
            )
            subprocess.run(
                ["/usr/bin/openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
                check=True, shell=False, capture_output=True, timeout=5,
            )
            fixed_now = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
            valid_payload = {
                "binding": {"audience": "executor-3", "profile": "L0-LX-A"},
                "issued_at": "2026-08-26T11:59:00Z",
                "observed_at": "2026-08-26T12:00:00Z",
                "expires_at": "2026-08-26T12:05:00Z",
                "revocation_epoch": 0,
                "fencing_epoch": 1,
            }

            def signed(value: dict[str, object]) -> tuple[bytes, dict[str, object], bytes]:
                payload = RUNNER._canonical(value)
                payload_path.write_bytes(payload)
                signature = subprocess.run(
                    [
                        "/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(private_key),
                        "-rawin", "-in", str(payload_path),
                    ],
                    check=True, shell=False, capture_output=True, timeout=5,
                ).stdout
                record_value = {
                    "verification_version": 3,
                    "verifier_id": "harness-m3-external-verifier/v1",
                    "issuer_id": RUNNER.SIGNER_ID,
                    "key_id": RUNNER.KEY_ID,
                    "payload_digest": RUNNER._digest_bytes(payload),
                    "bindings": value,
                    "proof": "ed25519:" + signature.hex(),
                }
                return payload, record_value, RUNNER._canonical(record_value)

            payload, record_value, record = signed(valid_payload)
            code_path = ROOT / "src/harness_product/verification.py"
            code_digest = RUNNER._digest_file(code_path)
            key_digest = RUNNER._digest_file(public_key)
            host_libcrypto_digest = RUNNER._digest_file(Path(RUNNER.LIBCRYPTO))
            with (
                patch.object(RUNNER, "PUBLIC_KEY", public_key),
                patch.object(RUNNER, "PUBLIC_KEY_DIGEST", key_digest),
                patch.object(RUNNER, "VERIFIER_CODE", code_path),
                patch.object(RUNNER, "VERIFIER_CODE_DIGEST", code_digest),
                patch.object(RUNNER, "LIBCRYPTO_DIGEST", host_libcrypto_digest),
            ):
                controller = RUNNER.Ed25519PayloadVerifier(clock=lambda: fixed_now)
                executor = OpenSSLEd25519Verifier(
                    verifier_id="harness-m3-external-verifier/v1",
                    issuer_id=RUNNER.SIGNER_ID,
                    key_id=RUNNER.KEY_ID,
                    public_key_path=str(public_key),
                    public_key_digest=key_digest,
                    libcrypto_path=RUNNER.LIBCRYPTO,
                    libcrypto_digest=host_libcrypto_digest,
                    verifier_code_path=str(code_path),
                    verifier_code_digest=code_digest,
                    expected_revocation_epoch=0,
                    expected_fencing_epoch=1,
                    clock=lambda: fixed_now,
                )
                boundaries = {"controller": controller, "executor": executor}
                for name, verifier in boundaries.items():
                    with self.subTest(boundary=name, mutation="valid"):
                        self.assertIs(
                            verifier.verify(payload, record, valid_payload["observed_at"]).status,
                            VerificationStatus.VERIFIED,
                        )

                mutations: dict[str, tuple[bytes, bytes]] = {
                    "payload": (payload + b" ", record),
                    "signature": (
                        payload,
                        RUNNER._canonical(
                            {
                                **record_value,
                                "proof": record_value["proof"][:-2]
                                + ("00" if record_value["proof"][-2:] != "00" else "01"),
                            }
                        ),
                    ),
                    "key": (payload, RUNNER._canonical({**record_value, "key_id": "other-key"})),
                    "bindings": (
                        payload,
                        RUNNER._canonical(
                            {**record_value, "bindings": {**valid_payload, "fencing_epoch": 2}}
                        ),
                    ),
                    "boolean": (payload, RUNNER._canonical({**record_value, "verified": True})),
                }
                for field, replacement in (
                    ("expires_at", "2026-08-26T11:59:59Z"),
                    ("observed_at", "2026-08-26T12:00:01Z"),
                    ("issued_at", "2026-08-26T12:00:01Z"),
                    ("revocation_epoch", 1),
                    ("fencing_epoch", 2),
                ):
                    changed = {**valid_payload, field: replacement}
                    mutated_payload, _, mutated_record = signed(changed)
                    mutations[field] = (mutated_payload, mutated_record)
                for boundary, verifier in boundaries.items():
                    for mutation, (tested_payload, tested_record) in mutations.items():
                        with self.subTest(boundary=boundary, mutation=mutation):
                            self.assertIs(
                                verifier.verify(
                                    tested_payload,
                                    tested_record,
                                    valid_payload["observed_at"],
                                ).status,
                                VerificationStatus.REJECTED,
                            )

                verifier_arguments = {
                    "verifier_id": "harness-m3-external-verifier/v1",
                    "issuer_id": RUNNER.SIGNER_ID,
                    "key_id": RUNNER.KEY_ID,
                    "public_key_path": str(public_key),
                    "public_key_digest": key_digest,
                    "libcrypto_path": RUNNER.LIBCRYPTO,
                    "libcrypto_digest": host_libcrypto_digest,
                    "verifier_code_path": str(code_path),
                    "verifier_code_digest": code_digest,
                    "expected_revocation_epoch": 0,
                    "expected_fencing_epoch": 1,
                    "clock": lambda: fixed_now,
                }
                with self.assertRaises(TypeError):
                    OpenSSLEd25519Verifier(
                        **verifier_arguments,
                        enforce_freshness=False,
                    )

                from harness_product import verification as verification_module

                libcrypto_copy = root / "libcrypto.so.3"
                libcrypto_copy.write_bytes(Path(RUNNER.LIBCRYPTO).read_bytes())
                os.chmod(libcrypto_copy, 0o444)
                copy_digest = RUNNER._digest_file(libcrypto_copy)
                original_open = verification_module._open_regular
                swapped = False

                def replace_after_open(
                    path: Path, expected_digest: str, maximum: int
                ) -> tuple[int, bytes]:
                    nonlocal swapped
                    descriptor, image = original_open(path, expected_digest, maximum)
                    if path == libcrypto_copy and not swapped:
                        replacement = root / "replacement-libcrypto"
                        replacement.write_bytes(b"not-a-shared-library")
                        os.chmod(replacement, 0o444)
                        os.replace(replacement, libcrypto_copy)
                        swapped = True
                    return descriptor, image

                fd_bound = OpenSSLEd25519Verifier(
                    **{
                        **verifier_arguments,
                        "libcrypto_path": str(libcrypto_copy),
                        "libcrypto_digest": copy_digest,
                    }
                )
                with patch.object(
                    verification_module,
                    "_open_regular",
                    side_effect=replace_after_open,
                ):
                    self.assertIs(
                        fd_bound.verify(
                            payload, record, valid_payload["observed_at"]
                        ).status,
                        VerificationStatus.VERIFIED,
                    )
                self.assertTrue(swapped)

            executor_source = RUNNER._executor_program(RUNNER.LIBCRYPTO_DIGEST).decode("utf-8")
            self.assertIn("from harness_product.verification import OpenSSLEd25519Verifier", executor_source)
            self.assertIn("executor_claim_verifier=Verifier()", executor_source)
            self.assertIn("supply_verifier=Verifier()", executor_source)
            self.assertNotIn("EVP_DigestVerify", executor_source)

            profile = json.loads((ROOT / "profiles/l0-lx-a.json").read_text(encoding="utf-8"))
            bindings = profile["measurement_bindings"]
            self.assertEqual(bindings["verifier_code_digest"], code_digest)
            self.assertEqual(bindings["verifier_public_key_digest"], RUNNER.PUBLIC_KEY_DIGEST)
            self.assertEqual(bindings["verifier_libcrypto_digest"], RUNNER.LIBCRYPTO_DIGEST)

if __name__ == "__main__":
    unittest.main()
