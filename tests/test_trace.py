from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import subprocess
from unittest.mock import patch

from trace.classify import classify_case
from trace.classify import calibrate_user_vulnerability_from_state
from trace.cli import evaluate_config
from trace.ingest import (
    ingest_case,
    parse_axiom_json_records,
    parse_court_transcript_records,
    parse_text_records,
    parse_ufed_xml_records,
)
from trace.irr import cohen_kappa, compute_irr, import_second_coder, krippendorff_alpha_nominal, krippendorff_alpha_ordinal
from trace.llm import _calibrate_user_vulnerability
from trace.report import compute_findings, export_case_report, verify_evidence_package
from trace.report import sign_manifest, verify_manifest_signature, verify_signing_certificate
from trace.storage import read_json
from trace.storage import write_json
from trace.validation import (
    apply_comparison_assessments,
    benchmark_profile_settings,
    build_history_trend_summary,
    compare_benchmark_summaries,
    run_benchmark_suite,
    run_validation,
    sign_artifact_bundle,
    verify_artifact_bundle,
    write_benchmark_artifacts,
    write_comparison_artifacts,
    write_artifact_history_snapshot,
    write_history_summary,
    write_history_trend_summary,
)


FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "companion_incident.json"
BENIGN_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_benign_case.json"
LONG_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_long_case.json"
MIXED_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_mixed_case.json"
NOISY_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_noisy_case.json"
PARSER_FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "validation" / "parsers"


class TraceTests(unittest.TestCase):
    def _build_ca_environment(self, root: Path, common_name: str) -> tuple[Path, Path, Path, Path, Path]:
        stem = common_name.lower().replace(" ", "_")
        ca_key = root / "ca_key.pem"
        ca_cert = root / "ca_cert.pem"
        private_key = root / f"{stem}_private.pem"
        public_key = root / f"{stem}_public.pem"
        signing_csr = root / f"{stem}.csr"
        signing_cert = root / f"{stem}_cert.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(ca_key), "-pkeyopt", "rsa_keygen_bits:2048"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-x509", "-new", "-key", str(ca_key), "-sha256", "-days", "1",
                "-subj", "/CN=TRACE Test CA", "-out", str(ca_cert),
            ],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(private_key), "-pkeyopt", "rsa_keygen_bits:2048"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["openssl", "req", "-new", "-key", str(private_key), "-subj", f"/CN={common_name}", "-out", str(signing_csr)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", str(signing_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(signing_cert), "-days", "1", "-sha256",
            ],
            check=True, capture_output=True, text=True,
        )
        return ca_key, ca_cert, private_key, public_key, signing_cert

    def test_parse_text_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("[00:00] user: hello\n[00:01] system: hi\n", encoding="utf-8")
            records = parse_text_records(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["speaker"], "user")

    def test_config_check_hosted_requires_env(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = evaluate_config("hosted")
        self.assertFalse(result["ready"])
        self.assertIn("TRACE_HOSTED_API_KEY is not set.", result["issues"])
        self.assertIn("TRACE_HOSTED_BASE_URL is not set.", result["issues"])

    def test_config_check_hosted_ready_with_openai_compatible_endpoint(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "TRACE_HOSTED_API_KEY": "test-key",
                "TRACE_HOSTED_BASE_URL": "https://provider.example/v1/chat/completions",
                "TRACE_HOSTED_MODEL": "provider-default",
            },
            clear=True,
        ):
            result = evaluate_config("hosted")
        self.assertTrue(result["ready"])
        self.assertEqual(result["hosted_base_url"], "https://provider.example/v1/chat/completions")
        self.assertEqual(result["effective_model"], "provider-default")

    def test_config_check_local_runtime_defaults(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = evaluate_config("ollama")
        self.assertTrue(result["ready"])
        self.assertEqual(result["local_runtime_base_url"], "http://localhost:11434/api/generate")

    def test_parse_additional_formats(self) -> None:
        court = PARSER_FIXTURE_ROOT / "court_transcript.txt"
        axiom = PARSER_FIXTURE_ROOT / "axiom_messages.json"
        ufed = PARSER_FIXTURE_ROOT / "ufed_messages.xml"
        self.assertEqual(len(parse_court_transcript_records(court)), 4)
        self.assertEqual(len(parse_axiom_json_records(axiom)), 4)
        self.assertEqual(len(parse_ufed_xml_records(ufed)), 4)
        self.assertEqual(parse_court_transcript_records(court)[1]["speaker"], "system")
        self.assertEqual(parse_axiom_json_records(axiom)[2]["speaker"], "user")
        self.assertEqual(parse_ufed_xml_records(ufed)[3]["speaker"], "system")

    def test_parse_malformed_formats_raise(self) -> None:
        invalid_axiom = PARSER_FIXTURE_ROOT / "invalid_axiom_missing_messages.json"
        invalid_ufed = PARSER_FIXTURE_ROOT / "invalid_ufed_empty.xml"
        with self.assertRaises(ValueError):
            parse_axiom_json_records(invalid_axiom)
        with self.assertRaises(ValueError):
            parse_ufed_xml_records(invalid_ufed)

    def test_ingest_supported_parser_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cases"
            court = ingest_case(PARSER_FIXTURE_ROOT / "court_transcript.txt", "COURT-1", "tester", "court", root)
            axiom = ingest_case(PARSER_FIXTURE_ROOT / "axiom_messages.json", "AXIOM-1", "tester", "axiom", root)
            ufed = ingest_case(PARSER_FIXTURE_ROOT / "ufed_messages.xml", "UFED-1", "tester", "ufed", root)
            self.assertEqual(court.transcript_count, 4)
            self.assertEqual(axiom.transcript_count, 4)
            self.assertEqual(ufed.transcript_count, 4)

    def test_ingest_classify_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = ingest_case(FIXTURE, "CASE-1", "tester", "json", root / "cases")
            self.assertEqual(result.transcript_count, 8)
            classified = classify_case(root / "cases" / "CASE-1", "tester")
            self.assertEqual(classified.message_count, 8)
            findings = compute_findings(read_json(root / "cases" / "CASE-1" / "classified_transcript.json")["transcript"])
            self.assertGreaterEqual(findings["inappropriate_response_rate"], 75)
            package = export_case_report(root / "cases" / "CASE-1", root / "out", "tester")
            self.assertTrue((package / "manifest.json").exists())
            self.assertTrue((package / "configuration" / "prompt_templates" / "sbc_v1.0.txt").exists())
            self.assertTrue((package / "forensic_report.pdf").exists())
            self.assertTrue((package / "override_summary.json").exists())
            self.assertTrue(verify_evidence_package(package)["all_pass"])

    def test_manifest_sign_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-SIGN", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-SIGN", "tester")
            package = export_case_report(root / "cases" / "CASE-SIGN", root / "out", "tester")
            _, ca_cert, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Test Signer")
            certificate_chain = root / "trace_chain.pem"
            certificate_chain.write_text("TEST CERTIFICATE CHAIN PLACEHOLDER\n", encoding="utf-8")
            sign_manifest(package, private_key, public_key, "TRACE test signer", [certificate_chain], signing_cert)
            verification = verify_manifest_signature(package, public_key)
            self.assertTrue(verification["all_pass"])
            certificate_verification = verify_signing_certificate(package, ca_cert)
            self.assertTrue(certificate_verification["all_pass"])
            trust_metadata = read_json(package / "trust_metadata.json")
            self.assertEqual(trust_metadata["signer_label"], "TRACE test signer")
            self.assertEqual(trust_metadata["public_key_path"], "trace_test_signer_public.pem")
            self.assertEqual(len(trust_metadata["certificate_chain"]), 1)
            self.assertEqual(trust_metadata["certificate_chain"][0]["path"], "trace_chain.pem")
            self.assertEqual(trust_metadata["signing_certificate_path"], "trace_test_signer_cert.pem")

    def test_revoked_certificate_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-REVOKE", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-REVOKE", "tester")
            package = export_case_report(root / "cases" / "CASE-REVOKE", root / "out", "tester")
            _, ca_cert, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Revoked Signer")
            sign_manifest(package, private_key, public_key, "TRACE revoked signer", [], signing_cert)
            crl_file = root / "revoked.crl.pem"
            subprocess.run(
                ["openssl", "ca", "-revoke", str(signing_cert), "-keyfile", str(root / "ca_key.pem"), "-cert", str(ca_cert), "-batch"],
                check=False, capture_output=True, text=True,
            )
            ca_dir = root / "ca_db"
            ca_dir.mkdir()
            (ca_dir / "index.txt").write_text("", encoding="utf-8")
            (ca_dir / "serial").write_text("1000\n", encoding="utf-8")
            (ca_dir / "crlnumber").write_text("1000\n", encoding="utf-8")
            openssl_cnf = root / "openssl.cnf"
            openssl_cnf.write_text(
                f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {ca_dir}
database = $dir/index.txt
new_certs_dir = $dir
certificate = {ca_cert}
private_key = {root / 'ca_key.pem'}
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_crl_days = 1
policy = policy_any
unique_subject = no

[ policy_any ]
commonName = supplied
""".strip()
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["openssl", "ca", "-config", str(openssl_cnf), "-revoke", str(signing_cert), "-batch"],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["openssl", "ca", "-config", str(openssl_cnf), "-gencrl", "-out", str(crl_file)],
                check=True, capture_output=True, text=True,
            )
            verification = verify_signing_certificate(package, ca_cert, crl_file)
            self.assertFalse(verification["all_pass"])
            self.assertFalse(verification["certificate_valid"])

    def test_mock_provider_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-MOCK", "tester", "json", root / "cases")
            result = classify_case(
                root / "cases" / "CASE-MOCK",
                "tester",
                provider="mock",
                model="mock-model",
                window_size=4,
                review_mode="flag-low-confidence",
            )
            self.assertEqual(result.message_count, 8)
            classified = read_json(root / "cases" / "CASE-MOCK" / "classified_transcript.json")
            self.assertEqual(classified["llm_provider"], "mock")
            self.assertEqual(classified["window_size"], 4)

    def test_replay_only_uses_recorded_provider_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay_dir = root / "replay"
            replay_dir.mkdir(parents=True, exist_ok=True)
            ingest_case(FIXTURE, "CASE-REPLAY", "tester", "json", root / "cases")
            classify_case(
                root / "cases" / "CASE-REPLAY",
                "tester",
                provider="mock",
                model="mock-model",
                replay_dir=replay_dir,
                replay_mode="record",
            )
            replay_log = replay_dir / "provider_replay.jsonl"
            self.assertTrue(replay_log.exists())

            ingest_case(FIXTURE, "CASE-REPLAY-2", "tester", "json", root / "cases")
            result = classify_case(
                root / "cases" / "CASE-REPLAY-2",
                "tester",
                provider="mock",
                model="mock-model",
                replay_dir=replay_dir,
                replay_mode="replay-only",
            )
            self.assertEqual(result.message_count, 8)
            classified = read_json(root / "cases" / "CASE-REPLAY-2" / "classified_transcript.json")
            self.assertEqual(classified["llm_provider"], "mock")

    def test_user_vulnerability_calibration_raises_crisis_underclassification(self) -> None:
        level, indicators, confidence, reasoning = _calibrate_user_vulnerability(
            "I do not want to be here anymore.",
            1,
            ["sad"],
            0.55,
            "Provider classified mild emotional distress.",
        )
        self.assertEqual(level, 4)
        self.assertIn("do not want to be here", " ".join(indicators))
        self.assertGreaterEqual(confidence, 0.9)
        self.assertIn("TRACE calibration raised vulnerability", reasoning)

    def test_state_calibration_raises_repeated_distress(self) -> None:
        level, confidence, reasoning = calibrate_user_vulnerability_from_state(
            "I feel lonely and upset.",
            2,
            ["lonely", "upset"],
            0.6,
            "Provider classified moderate distress.",
            [3, 4],
        )
        self.assertEqual(level, 3)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("TRACE state calibration raised vulnerability", reasoning)

    def test_state_calibration_preserves_elevated_trajectory(self) -> None:
        level, confidence, reasoning = calibrate_user_vulnerability_from_state(
            "I feel hopeless and withdrawn.",
            2,
            ["hopeless", "withdrawn"],
            0.62,
            "Provider downgraded despite ongoing distress trajectory.",
            [3, 3, 4],
        )
        self.assertEqual(level, 3)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("TRACE state calibration raised vulnerability", reasoning)

    def test_state_calibration_preserves_severe_trajectory(self) -> None:
        level, confidence, reasoning = calibrate_user_vulnerability_from_state(
            "I do not want to be here anymore.",
            3,
            ["hopeless", "acute crisis disclosure"],
            0.64,
            "Provider reported elevated but not severe distress.",
            [4, 4, 3],
        )
        self.assertEqual(level, 4)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("TRACE state calibration raised vulnerability", reasoning)

    def test_state_calibration_does_not_promote_to_acute_without_explicit_crisis_language(self) -> None:
        level, confidence, reasoning = calibrate_user_vulnerability_from_state(
            "I feel worthless and alone.",
            3,
            ["worthlessness", "aloneness"],
            0.64,
            "Provider reported severe distress.",
            [4, 4, 3],
        )
        self.assertEqual(level, 3)
        self.assertEqual(confidence, 0.64)
        self.assertEqual(reasoning, "Provider reported severe distress.")

    def test_irr_metrics(self) -> None:
        self.assertAlmostEqual(cohen_kappa(["a", "a", "b"], ["a", "a", "b"]), 1.0)
        self.assertAlmostEqual(krippendorff_alpha_nominal(["x", "y"], ["x", "y"]), 1.0)
        self.assertAlmostEqual(krippendorff_alpha_ordinal([0, 1, 4], [0, 1, 4]), 1.0)

    def test_import_and_compute_irr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-2", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-2", "tester")
            coder2 = root / "coder2.json"
            coder2.write_text((root / "cases" / "CASE-2" / "classified_transcript.json").read_text(encoding="utf-8"), encoding="utf-8")
            import_second_coder(root / "cases" / "CASE-2", coder2)
            stats = compute_irr(root / "cases" / "CASE-2")
            self.assertEqual(stats["krippendorff_alpha_behavioral"], 1.0)

    def test_validation_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_validation(FIXTURE, Path(tmp))
            self.assertEqual(result.reference_name, "companion_incident.json")
            self.assertEqual(result.profile, "heuristic")
            self.assertEqual(result.sensitivity, "critical")
            self.assertIn("crisis", result.tags)
            self.assertTrue(result.pass_thresholds)
            benign = run_validation(BENIGN_FIXTURE, Path(tmp) / "benign")
            self.assertEqual(benign.sensitivity, "benign")
            self.assertTrue(benign.pass_thresholds)
            mixed = run_validation(MIXED_FIXTURE, Path(tmp) / "mixed")
            self.assertTrue(mixed.pass_thresholds)
            noisy = run_validation(NOISY_FIXTURE, Path(tmp) / "noisy")
            self.assertEqual(noisy.sensitivity, "noisy")
            self.assertTrue(noisy.pass_thresholds)

    def test_benchmark_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", Path(tmp))
            self.assertEqual(summary["total_fixtures"], 5)
            self.assertEqual(summary["failed_fixtures"], 0)
            self.assertEqual(summary["pass_rate"], 100.0)
            self.assertGreater(summary["total_elapsed_seconds"], 0.0)
            hosted = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", Path(tmp) / "hosted", profile="hosted")
            self.assertEqual(hosted["profile"], "hosted")
            self.assertEqual(hosted["failed_fixtures"], 0)

    def test_benchmark_suite_replay_only_uses_recorded_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            validation_dir = Path(__file__).resolve().parent.parent / "validation"
            recorded = run_benchmark_suite(
                validation_dir,
                root / "recorded",
                profile="hosted",
                replay_dir=root / "replay",
                replay_mode="record",
            )
            replayed = run_benchmark_suite(
                validation_dir,
                root / "replayed",
                profile="hosted",
                replay_dir=root / "replay",
                replay_mode="replay-only",
            )
            self.assertEqual(recorded["failed_fixtures"], 0)
            self.assertEqual(replayed["failed_fixtures"], 0)
            self.assertEqual(
                [item["vulnerability_agreement"] for item in recorded["results"]],
                [item["vulnerability_agreement"] for item in replayed["results"]],
            )

    def test_live_hosted_profile_settings(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                benchmark_profile_settings("live-hosted")
        with patch.dict(
            "os.environ",
            {"TRACE_HOSTED_API_KEY": "test-key", "TRACE_HOSTED_MODEL": "provider-default"},
            clear=True,
        ):
            settings = benchmark_profile_settings("live-hosted")
        self.assertEqual(settings["provider"], "hosted")
        self.assertEqual(settings["model"], "provider-default")
        self.assertEqual(settings["window_size"], 8)

    def test_benchmark_artifact_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "bench")
            artifacts = write_benchmark_artifacts(summary, root / "artifacts")
            self.assertTrue(artifacts["json"].exists())
            self.assertTrue(artifacts["markdown"].exists())
            markdown = artifacts["markdown"].read_text(encoding="utf-8")
            self.assertIn("# TRACE Benchmark Summary", markdown)
            payload = read_json(artifacts["json"])
            self.assertEqual(payload["total_fixtures"], 5)
            snapshot = write_artifact_history_snapshot(summary, root / "history", "benchmark_heuristic_latest")
            self.assertTrue(snapshot["latest"].exists())
            self.assertTrue(snapshot["dated"].exists())
            self.assertNotEqual(snapshot["latest"], snapshot["dated"])

    def test_history_summary_and_trend_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history_dir = root / "history"
            history_dir.mkdir(parents=True, exist_ok=True)
            prefix = "benchmark_heuristic_latest"
            write_json(
                history_dir / f"{prefix}_2026-04-19T10-00-00Z.json",
                {
                    "label": prefix,
                    "generated_at": "2026-04-19T10:00:00+00:00",
                    "payload": {
                        "profile": "heuristic",
                        "pass_rate": 100.0,
                        "failed_fixtures": 0,
                        "total_elapsed_seconds": 1.2,
                    },
                },
            )
            write_json(
                history_dir / f"{prefix}_2026-04-19T12-00-00Z.json",
                {
                    "label": prefix,
                    "generated_at": "2026-04-19T12:00:00+00:00",
                    "payload": {
                        "profile": "heuristic",
                        "pass_rate": 100.0,
                        "failed_fixtures": 0,
                        "total_elapsed_seconds": 1.5,
                    },
                },
            )
            history = write_history_summary(history_dir, prefix)
            trend = write_history_trend_summary(history_dir, prefix)
            trend_payload = read_json(trend["json"])
            self.assertTrue(history["json"].exists())
            self.assertTrue(history["markdown"].exists())
            self.assertEqual(trend_payload["series_type"], "benchmark")
            self.assertEqual(trend_payload["snapshot_count"], 2)
            self.assertEqual(trend_payload["elapsed_delta_seconds"], 0.3)
            self.assertIn("# TRACE Benchmark Trend Summary", trend["markdown"].read_text(encoding="utf-8"))

    def test_benchmark_comparison_artifact_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "heuristic", profile="heuristic")
            candidate = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "hosted", profile="hosted")
            comparison = apply_comparison_assessments(compare_benchmark_summaries(baseline, candidate))
            self.assertTrue(comparison["drift_free"])
            artifacts = write_comparison_artifacts(comparison, root / "compare_artifacts")
            self.assertTrue(artifacts["json"].exists())
            self.assertTrue(artifacts["markdown"].exists())
            markdown = artifacts["markdown"].read_text(encoding="utf-8")
            self.assertIn("# TRACE Benchmark Comparison", markdown)

    def test_comparison_history_trend_summary(self) -> None:
        prefix = "benchmark_compare_heuristic_vs_hosted_latest"
        snapshots = [
            {
                "generated_at": "2026-04-19T10:00:00+00:00",
                "payload": {
                    "baseline_profile": "heuristic",
                    "candidate_profile": "hosted",
                    "drift_count": 0,
                    "drift_free": True,
                    "provider_drift_policy": {"status": "pass"},
                },
            },
            {
                "generated_at": "2026-04-19T12:00:00+00:00",
                "payload": {
                    "baseline_profile": "heuristic",
                    "candidate_profile": "hosted",
                    "drift_count": 1,
                    "drift_free": False,
                    "provider_drift_policy": {"status": "warn"},
                },
            },
        ]
        summary = build_history_trend_summary(prefix, snapshots)
        self.assertEqual(summary["series_type"], "comparison")
        self.assertEqual(summary["drift_count_delta"], 1)
        self.assertEqual(summary["drift_free_snapshots"], 1)
        self.assertEqual(summary["latest_policy_status"], "warn")
        self.assertEqual(summary["policy_warn_or_fail_snapshots"], 1)

    def test_live_hosted_provider_drift_policy(self) -> None:
        comparison = apply_comparison_assessments(
            {
                "baseline_profile": "heuristic",
                "baseline_profile_settings": {},
                "candidate_profile": "live-hosted",
                "candidate_profile_settings": {"provider": "hosted", "model": "provider-default", "window_size": 8},
                "references_compared": 2,
                "drift_count": 2,
                "drift_free": False,
                "comparisons": [
                    {
                        "reference_name": "companion_incident.json",
                        "reference_metadata": {"sensitivity": "critical", "tags": ["crisis", "suicidality"]},
                        "behavioral_delta": -25.0,
                        "vulnerability_delta": -75.0,
                        "findings_changed": False,
                        "threshold_changed": True,
                        "drift_detected": True,
                        "baseline_pass": True,
                        "candidate_pass": False,
                    },
                    {
                        "reference_name": "reference_noisy_case.json",
                        "reference_metadata": {"sensitivity": "noisy", "tags": ["crisis", "informal_language"]},
                        "behavioral_delta": 0.0,
                        "vulnerability_delta": -50.0,
                        "findings_changed": True,
                        "threshold_changed": True,
                        "drift_detected": True,
                        "baseline_pass": True,
                        "candidate_pass": False,
                    },
                ],
            }
        )
        policy = comparison["provider_drift_policy"]
        self.assertTrue(policy["policy_applied"])
        self.assertEqual(policy["status"], "fail")
        self.assertGreaterEqual(policy["failure_count"], 2)
        self.assertIn("Provider drift triggered", policy["summary"])

    def test_signed_benchmark_artifact_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "bench")
            write_benchmark_artifacts(summary, root / "artifacts")
            _, _, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Benchmark Signer")
            chain = root / "benchmark_chain.pem"
            chain.write_text("BENCHMARK CHAIN PLACEHOLDER\n", encoding="utf-8")
            signed = sign_artifact_bundle(
                root / "artifacts",
                private_key,
                public_key,
                "TRACE benchmark signer",
                signing_cert,
                [chain],
            )
            self.assertTrue(signed["manifest"].exists())
            self.assertTrue(signed["signature"].exists())
            verification = verify_artifact_bundle(root / "artifacts", public_key)
            self.assertTrue(verification["all_pass"])

    def test_long_transcript_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(LONG_FIXTURE, "LONG-CASE", "tester", "json", root / "cases")
            classify_case(root / "cases" / "LONG-CASE", "tester", window_size=8)
            package = export_case_report(root / "cases" / "LONG-CASE", root / "out", "tester", "Examiner reviewed long-form distress pattern.")
            report_md = (package / "forensic_report.md").read_text(encoding="utf-8")
            self.assertIn("## Case Overview", report_md)
            self.assertIn("## Findings Summary", report_md)
            self.assertIn("## Methodology Notes", report_md)
            self.assertIn("## Examiner Notes", report_md)
            self.assertIn("## Artifact Inventory", report_md)
            self.assertIn("## Appendix A — Artifact Checklist", report_md)
            self.assertIn("## Appendix B — Correlation Snapshot", report_md)
            findings = read_json(package / "correlation_analysis.json")
            self.assertGreaterEqual(findings["inappropriate_response_rate"], 80.0)


if __name__ == "__main__":
    unittest.main()
