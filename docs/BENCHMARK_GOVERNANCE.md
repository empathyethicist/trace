# TRACE Benchmark Governance

This document defines how TRACE benchmark artifacts should be interpreted, signed, retained, and reviewed.

## Purpose

The benchmark workflow exists to provide a stable, inspectable record of TRACE validation posture across bundled reference fixtures and benchmark profiles.

It is intended to support:

- release readiness review
- regression detection
- cross-profile drift inspection
- artifact integrity verification
- external reviewer confidence

## Benchmark profiles

TRACE currently maintains two benchmark profiles:

- `heuristic`
- `hosted`

The `heuristic` profile is the baseline release profile because it is deterministic and locally reproducible.

The current `hosted` profile is a controlled mock-hosted benchmark path. It is useful for workflow comparison, timing instrumentation, and drift plumbing, but it is **not yet** a substitute for benchmarking against live provider responses.

## Acceptance thresholds

A benchmark run is acceptable only when all of the following are true:

- bundled fixtures complete without execution failure
- `failed_fixtures == 0`
- `pass_rate == 100.0`
- artifact manifest verification passes when signing is enabled
- comparison drift count remains `0` unless an intentional methodology change is under review

If any of those conditions fail, the benchmark output should be treated as a regression candidate requiring review.

## Release criteria

Before treating a TRACE revision as release-ready for public demonstration or external review, the project should retain:

- a passing heuristic benchmark summary
- a passing hosted-profile benchmark summary
- a heuristic-vs-hosted comparison artifact
- signed artifact bundles for each emitted benchmark output set
- latest history snapshots for the benchmark run set

## Required review questions

For each benchmark cycle, reviewers should ask:

- Did any fixture fall below threshold?
- Did any profile introduce drift relative to the heuristic baseline?
- Did any artifact verification or signature validation fail?
- Did timing change materially from the previous baseline?
- Was the benchmark corpus changed, and if so, was that intentional and documented?

## Artifact verification workflow

Recommended review flow:

1. Verify the benchmark summary contents.
2. Verify the artifact manifest signature.
3. Verify the file hashes listed in the artifact manifest.
4. Review any comparison artifact for drift.
5. Archive the current history snapshot.

## Current limitations

This governance process still has three important limitations:

- the hosted profile currently uses a mock-hosted path rather than live provider benchmarking
- benchmark history uses latest-snapshot naming rather than immutable dated series by default
- timing thresholds are recorded but not yet enforced by policy

## Immediate next governance upgrades

The next governance improvements should be:

- immutable dated benchmark history snapshots
- explicit timing regression thresholds
- live-provider hosted benchmark criteria separate from mock-hosted criteria
