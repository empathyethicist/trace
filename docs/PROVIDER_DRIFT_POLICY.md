# TRACE Provider Drift Policy

This document defines how TRACE should treat externally hosted model variance over time.

## Purpose

Externally hosted models are useful for coverage and qualitative comparison, but they are not stable enough to serve as TRACE's primary forensic baseline. Provider drift policy exists to keep that variance visible, bounded, and operationally safe.

## Core position

TRACE future-proofs against provider drift by separating:

- the deterministic baseline used for repeatable release validation
- the hosted-provider path used for observational comparison and augmentation
- the examiner review layer that remains authoritative when disagreement occurs

The objective is not to eliminate drift. The objective is to detect it quickly, record it faithfully, and prevent it from silently changing TRACE's effective behavior.

## Current controls

TRACE currently applies the following controls:

- exact provider/model/window metadata recorded in benchmark artifacts
- fixture-level benchmark metadata (`sensitivity`, `tags`) recorded in validation fixtures
- hosted vulnerability calibration against direct lexical crisis indicators
- hosted response capture and replay for provider-stable re-analysis
- deterministic `heuristic` benchmark baseline
- mock-hosted benchmark path for workflow stability
- live-hosted benchmark path for real provider observation
- signed benchmark artifact bundles
- dated history snapshots and trend summaries
- provider drift comparison artifacts against the heuristic baseline

## Current live-hosted drift policy

For `live-hosted`, TRACE currently applies a warning-mode policy with these bounds:

- global `drift_count` target: `<= 1`
- default behavioral agreement delta: `<= 10.0`
- default vulnerability agreement delta: `<= 15.0`
- findings drift: not allowed by default

More conservative thresholds apply to:

- fixtures marked `critical`
- fixtures marked `noisy`
- fixtures tagged `crisis`

These cases are treated as higher-sensitivity references because they include crisis-language or noisier language patterns where under-classification is operationally significant.

## Interpretation

When live-provider drift exceeds policy bounds:

- the result should be surfaced as a policy warning or failure
- the benchmark artifacts should still be preserved
- the release process should not silently promote hosted behavior to baseline behavior
- crisis-sensitive disagreements should trigger examiner review rather than automatic trust

When a critical or crisis-tagged reference shows negative vulnerability drift beyond threshold, TRACE escalates that violation to `failure` severity rather than leaving it as a generic warning.

## What the latest live run showed

The latest committed `openrouter/free` benchmark artifacts showed three concrete issues:

- vulnerability agreement drift was materially worse than behavioral drift
- crisis-oriented fixtures drifted more than benign fixtures
- the noisy-case fixture produced a findings change, which is the most operationally significant failure mode in the current run

This means the current hosted-provider risk is primarily under-classification or unstable classification of user vulnerability, not wholesale collapse of system-behavior labeling.

The current committed policy therefore treats crisis-linked vulnerability under-classification and crisis/noisy findings changes as escalation conditions rather than ordinary drift.

## Future-proofing direction

The next defensive upgrades should be:

- provider-specific drift thresholds rather than one global threshold set
- fixture tagging for `critical`, `high-noise`, and `benign` sensitivity levels
- automatic benchmark warnings on vulnerability under-classification in crisis references
- calibration rules for hosted-provider outputs before final TRACE schema mapping
- multi-provider comparison so no single provider becomes the de facto benchmark truth
- stronger response caching and reproducibility controls for hosted paths
- examiner-review escalation when hosted-provider output disagrees with deterministic baseline on critical references

## Release posture

Until live-provider variance is reduced and acceptance criteria are validated over time:

- `heuristic` remains the release-stable benchmark baseline
- `hosted` remains the workflow-comparison profile
- `live-hosted` remains a drift-observation profile

That is the correct forensic posture. It preserves repeatability while still measuring how hosted models behave in practice.

## Current calibration note

TRACE now applies a conservative calibration layer to hosted user-vulnerability outputs before final schema mapping. If the hosted provider under-classifies a message that contains direct lexical crisis indicators already recognized by TRACE's deterministic baseline, TRACE raises the vulnerability level to the higher deterministic value and records that calibration in the reasoning string.

TRACE also applies a state-aware escalation rule. When recent user turns already indicate elevated risk, a later hosted-provider output that still shows distress indicators cannot silently drop back to a low-risk label without passing through a conservative trajectory check.
