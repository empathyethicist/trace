# TRACE Live-Provider Hardening Notes

This document records the live-provider hardening work performed against TRACE's `live-hosted` benchmark profile and explains the current operational posture.

## Scope

As of April 19, 2026, TRACE has been hardened against the main failure mode observed in live-provider benchmarking: instability in hosted user-vulnerability classification under crisis-sensitive conversational conditions.

This hardening work was performed against the `provider-default` routing path and evaluated through TRACE's replay-based benchmark workflow rather than by repeatedly calling a live provider for every iteration.

## Why replay-first analysis was required

Direct live-provider runs were not stable enough to support fast calibration work. Two separate variables were getting mixed together:

- hosted-model behavior drift
- provider and network execution instability

TRACE's replay harness separates those variables by recording raw provider responses once and then replaying them locally through the same calibration and benchmark pipeline. That makes downstream tuning repeatable.

## Hardening sequence

The live-provider hardening sequence addressed the following failure modes in order:

1. **Direct crisis under-classification**
   - Hosted outputs that under-classified explicit crisis language were raised to TRACE's deterministic lexical baseline.

2. **State-aware under-classification across repeated elevated turns**
   - Hosted outputs that attempted to step down too quickly after recent elevated-risk user turns were conservatively raised through a trajectory check.

3. **Over-escalation on long-form distress**
   - TRACE's trajectory logic was tightened so that `3 -> 4` promotion now requires explicit acute-crisis language in the current user turn, rather than severe context alone.

This sequence preserved the beneficial parts of hosted calibration while reducing false promotion in long-form crisis narratives.

## Evaluation method

The most informative replay set was the crisis-sensitive subset:

- `validation/companion_incident.json`
- `validation/reference_long_case.json`
- `validation/reference_noisy_case.json`

The analysis flow used:

```bash
trace benchmark-replay \
  --validation-dir ./validation \
  --profile live-hosted \
  --replay-dir ./replay_artifacts \
  --output-dir ./benchmark_artifacts_replay

trace benchmark-compare \
  --validation-dir ./validation \
  --baseline-profile heuristic \
  --candidate-profile live-hosted \
  --replay-dir ./replay_artifacts_profiles \
  --replay-mode replay-only \
  --output-dir ./benchmark_comparison_live
```

## Result snapshot

The replay-driven hardening work produced the following benchmark comparison outcome on April 19, 2026:

| Reference fixture | Behavioral delta | Vulnerability delta | Findings changed | Threshold changed |
|---|---:|---:|---|---|
| `companion_incident.json` | `0.0` | `0.0` | `false` | `false` |
| `reference_long_case.json` | `0.0` | `-12.5` | `false` | `false` |
| `reference_noisy_case.json` | `0.0` | `0.0` | `false` | `false` |

Provider drift policy result for that run:

- `status: pass`
- `summary: Provider drift remains within configured bounds.`

Committed example artifacts for that hardened replay state are available at:

- `examples/benchmark_artifacts/live_hosted_hardened/benchmark_summary.json`
- `examples/benchmark_artifacts/live_hosted_hardened/benchmark_summary.md`
- `examples/benchmark_artifacts/live_hosted_hardened/artifact_manifest.json`
- `examples/benchmark_artifacts/live_hosted_hardened/artifact_manifest.sig`
- `examples/benchmark_comparison_live_hosted_hardened/benchmark_comparison.json`
- `examples/benchmark_comparison_live_hosted_hardened/benchmark_comparison.md`
- `examples/benchmark_comparison_live_hosted_hardened/artifact_manifest.json`
- `examples/benchmark_comparison_live_hosted_hardened/artifact_manifest.sig`

The remaining live-provider disagreement is therefore narrow:

- no observed behavioral classification drift on the crisis-sensitive replay set
- no findings drift on the crisis-sensitive replay set
- one residual vulnerability-agreement delta on the long-form crisis fixture

## Interpretation

This is the correct current forensic posture:

- TRACE's deterministic `heuristic` profile remains the release-stable benchmark baseline.
- TRACE's `live-hosted` profile is acceptable as a bounded comparison and augmentation path.
- Replay artifacts remain the preferred mechanism for calibration work and benchmark review because they preserve the exact upstream responses under analysis.

The key result is not that live-provider drift has disappeared. It has not. The key result is that TRACE now keeps that drift within policy bounds on the current crisis-sensitive replay set and does so with explicit, test-backed calibration rules.

## Remaining gap

The current residual gap is concentrated in long-form crisis trajectories where:

- the user remains in sustained severe distress
- the current turn may be high-risk without being an explicit acute-crisis disclosure
- hosted outputs may still differ modestly from the deterministic baseline on vulnerability level

That residual difference is materially smaller than the earlier live-provider failures and no longer changes findings or benchmark policy status, but it remains worth tracking.

## Operational guidance

For forensic review and release decision-making:

- treat `heuristic` as the baseline of record
- treat `live-hosted` as drift-observation evidence
- preserve replay captures for any meaningful live-provider benchmark run
- require explicit review of crisis-sensitive benchmark drift, even when policy status passes

## Related documents

- `docs/VALIDATION.md`
- `docs/PROVIDER_DRIFT_POLICY.md`
- `docs/BENCHMARK_GOVERNANCE.md`
- `docs/RELEASE_CHECKLIST.md`
