# TRACE Packaging and Demo

This document covers the current release-build path and the fastest full demo path.

## Release build

TRACE now ships with a release build helper:

```bash
./scripts/build_release.sh
```

What it does:

- runs the test suite
- builds an sdist
- builds a wheel
- writes `SHA256SUMS.txt` in `dist/`

Prerequisite:

- `python -m build` must be available in the active environment

## Release artifact contents

The source distribution includes:

- package source
- docs
- examples
- validation fixtures
- `.env.example`

This is controlled through `MANIFEST.in`.

## Demo workflow

TRACE now ships with a one-command local demo script:

```bash
./scripts/demo_trace.sh
```

By default it creates:

- `./demo-workspace/`

You can also supply a target path:

```bash
./scripts/demo_trace.sh /tmp/trace-demo
```

What it does:

- initializes a workspace
- runs validation on the companion incident fixture
- ingests the companion incident as a case
- classifies it with the heuristic path
- exports an evidence package

## Operational note

The demo script is intended for first-run evaluation, partner walkthroughs, and local smoke testing. It is not a substitute for the fuller validation and benchmark workflows documented elsewhere in the repo.
