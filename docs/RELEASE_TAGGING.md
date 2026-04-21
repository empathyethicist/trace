# TRACE Release Tagging

This document defines how a public TRACE release should be tied to benchmark artifacts, signatures, and dated history snapshots.

## Purpose

Release tags are only useful to external reviewers if they point to a stable, verifiable validation state. TRACE release tagging therefore links:

- a Git tag
- signed benchmark artifacts
- dated benchmark history snapshots
- benchmark comparison artifacts
- the exact hosted model identifier used for any live-provider benchmark run

## Minimum tagging record

For a public release tag, retain all of the following:

- the Git tag name
- the Git commit SHA
- the heuristic benchmark artifact bundle
- the hosted benchmark artifact bundle
- the heuristic-vs-hosted comparison artifact bundle
- the dated benchmark history snapshots referenced by the release
- the trend summaries generated from those dated snapshots

If a release includes live-provider benchmarking, also retain:

- the live-hosted benchmark artifact bundle
- the heuristic-vs-live-hosted comparison artifact bundle
- the exact `TRACE_HOSTED_MODEL` value used during the run

## Recommended tag naming

Recommended public tag format:

- `v0.1.0`
- `v0.2.0`
- `v1.0.0`

Pre-release tag examples:

- `v0.2.0-rc1`
- `v0.2.0-beta1`

## Release artifact layout

Recommended release evidence structure:

```text
release-artifacts/
  v0.2.0/
    benchmark_heuristic/
    benchmark_hosted/
    benchmark_compare_heuristic_vs_hosted/
    benchmark_history/
    release_notes.md
```

If live-provider benchmarking is included:

```text
release-artifacts/
  v0.2.0/
    benchmark_live_hosted/
    benchmark_compare_heuristic_vs_live_hosted/
```

## Release note requirements

Each tagged release should record:

- release date
- release commit SHA
- heuristic benchmark pass/fail status
- hosted benchmark pass/fail status
- live-hosted benchmark pass/fail status, if run
- whether comparison artifacts were drift-free
- whether benchmark bundles were signed and verified
- the exact hosted-provider model identifiers used

## Verification workflow

Before publishing a release tag:

1. Confirm the release commit is clean and matches the intended tag target.
2. Run the release checklist in `docs/RELEASE_CHECKLIST.md`.
3. Generate signed benchmark artifacts and dated history snapshots.
4. Generate benchmark trend summaries from the history directory.
5. Verify signatures and file hashes for all release benchmark bundles.
6. Attach or archive the resulting artifact set alongside the release tag.

## Current limitation

TRACE does not yet automate Git tag creation or release attachment. The current process defines the required release evidence, but publication and hosting of the signed artifact set remain operator steps.
