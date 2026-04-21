# TRACE Lab Deployment Notes

This document describes how a forensic lab or DFIR company should run TRACE in a controlled environment.

## Purpose

TRACE handles conversational evidence, classification artifacts, replay captures, and signing materials that may later be reviewed adversarially. A lab deployment should therefore optimize for:

- evidence integrity
- operational clarity
- bounded hosted-model risk
- reproducibility
- controlled retention of artifacts

The goal is not merely to make TRACE run. The goal is to run TRACE in a way that a serious forensic organization can defend.

## Recommended deployment posture

For most labs, the safest current posture is:

- run TRACE locally on controlled workstations or lab systems
- use the deterministic `heuristic` profile as the baseline of record
- treat hosted or live-hosted classification as optional augmentation
- preserve replay captures whenever a hosted provider is used
- sign exported artifacts or benchmark bundles that matter for review

This is the correct posture for TRACE's current maturity level.

## Environment classes

## 1. Baseline offline-capable environment

Recommended for:

- internal workflow trial
- bounded forensic review
- environments with strict network controls

Characteristics:

- TRACE installed locally
- deterministic `heuristic` classification path available
- no live-provider dependence
- local artifact generation and package verification

This is the lowest-risk way to operate TRACE today.

## 2. Controlled hosted-augmentation environment

Recommended for:

- replay capture
- hosted drift observation
- limited provider-assisted classification testing

Characteristics:

- TRACE installed locally
- hosted access explicitly enabled
- provider credentials injected at runtime
- replay capture required for any meaningful hosted run
- live-provider outputs treated as reviewable inputs, not silent truth

## 3. Evaluation or partner-demo environment

Recommended for:

- partner review
- pilot evaluation
- external demonstration with signed benchmark evidence

Characteristics:

- benchmark artifacts exported and signed
- example evidence packages preserved
- replay-hardened comparison artifacts available
- exact benchmark profile and provider metadata retained

## Hosted-provider access guidance

If a lab enables hosted-provider use:

- prefer explicit environment-variable injection at runtime
- do not persist API secrets in repo files
- do not include secrets in evidence packages
- record exact provider and model metadata in benchmark or package outputs
- capture replay artifacts whenever the hosted path is used for evaluation or review
- run `trace config-check --provider hosted` before first hosted use

TRACE’s current hosted interface expects:

- `TRACE_HOSTED_API_KEY`
- `TRACE_HOSTED_BASE_URL`
- `TRACE_HOSTED_MODEL` (optional)
- `TRACE_HOSTED_ADAPTER` (optional)

The hosted path currently supports explicit adapter contracts rather than a single implicit provider assumption. See `docs/HOSTED_PROVIDER_SETUP.md`.

Current TRACE posture assumes:

- hosted providers may drift
- hosted providers may stall or rate-limit
- hosted output may require normalization
- hosted output must remain secondary to deterministic and examiner-controlled review paths

## Replay capture guidance

Replay capture should be treated as standard practice for hosted evaluation work.

Why:

- it separates provider behavior from local pipeline behavior
- it makes calibration and benchmark analysis repeatable
- it preserves the exact upstream output under review

Recommended usage:

```bash
trace classify \
  --case-id CASE-001 \
  --provider hosted \
  --model provider-default \
  --replay-dir ./replay_artifacts \
  --replay-mode record

trace classify \
  --case-id CASE-001 \
  --provider hosted \
  --model provider-default \
  --replay-dir ./replay_artifacts \
  --replay-mode replay-only
```

For labs, the practical rule should be:

- if a hosted result may matter later, capture replay artifacts

## Signing-key guidance

TRACE supports signing of evidence packages and benchmark artifacts. Labs should treat signing materials as operational security assets.

Recommended controls:

- keep private keys outside the repo
- store them in a controlled secrets or key-management workflow
- use separate keys for benchmark artifacts and case evidence if possible
- retain public keys, signing certificates, and chain files alongside exported signed artifacts

The repo's example bundles include public verification materials only. That is the correct public posture.

## Artifact retention guidance

Labs evaluating TRACE should explicitly decide what to retain.

Minimum recommended retention for meaningful review:

- source transcript
- classified transcript
- audit log
- correlation analysis
- report outputs
- manifest and verification outputs
- replay captures for hosted runs
- benchmark summaries and comparison artifacts for any validation cycle used in decision-making

For signed benchmark or example review material, retain:

- manifest
- detached signature
- trust metadata
- public verification key
- certificate and chain files when used

## Directory and workflow discipline

A lab should avoid mixing:

- real case material
- benchmark fixtures
- replay artifacts
- example artifacts

Recommended pattern:

- keep real casework in a dedicated case root
- keep replay artifacts in a separate replay root
- keep benchmark artifacts in a dedicated validation root
- keep public example artifacts separate from any internal pilot outputs

This reduces accidental reuse or confusion during later review.

## Evidence-handling cautions

Labs should not assume that TRACE outputs are self-authenticating merely because they are structured.

Operational cautions:

- package verification should be run and preserved
- signed artifacts should be verified before relying on them
- examiner notes and override rationales should be treated as reviewable, not hidden
- hosted-model reasoning should not be mistaken for expert opinion

TRACE is strongest when it is treated as a transparent forensic workflow layer, not an automated conclusion engine.

## Recommended deployment checklist

Before using TRACE in a lab context, confirm:

- installation is reproducible
- the local test suite passes
- the heuristic benchmark profile passes
- signing and verification commands work in the target environment
- replay capture locations are defined
- retention locations are defined
- provider credentials, if used, are handled outside the repo
- personnel understand that hosted outputs are bounded by drift policy and replay review

## Current best-practice profile

For a cautious lab today, the best-practice configuration is:

- `heuristic` as baseline operational profile
- `hosted` or `live-hosted` only for bounded comparison or augmentation
- replay capture enabled for hosted work
- signed benchmark or evidence artifacts for reviewable milestones
- explicit retention of benchmark and comparison outputs tied to evaluation decisions

## Related documents

- `docs/ADOPTION_READINESS.md`
- `docs/PILOT_EVALUATION.md`
- `docs/VALIDATION.md`
- `docs/PROVIDER_DRIFT_POLICY.md`
- `docs/LIVE_PROVIDER_HARDENING.md`
- `docs/EVIDENCE_PACKAGE_SPEC.md`
- `docs/THREAT_MODEL.md`
