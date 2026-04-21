# TRACE Install and Release Notes

This document covers practical install and release posture for external users.

## Local install

TRACE currently ships as a Python package with a console entry point.

Recommended install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This is the supported path for:

- local evaluation
- pilot deployment
- development work

## Workspace bootstrap

After installation, initialize a workspace:

```bash
trace init --root ./trace-workspace
```

## Release posture

TRACE is not yet a packaged binary release. Current external use should assume:

- Python 3.11+
- a virtual environment or equivalent isolated Python install
- explicit workspace creation with `trace init`
- explicit config validation with `trace config-check`

## What a future release should include

For stronger out-of-the-box adoption, future releases should add:

- tagged release bundles
- wheel distribution artifacts
- signed release notes
- sample workspace tarball or template
- reproducible installer instructions pinned to the release

## Current recommendation

For external evaluation today, the correct operational flow is:

1. install in a clean virtual environment
2. run `trace init`
3. run `trace config-check`
4. run validation fixtures
5. then move into local or hosted evaluation as needed
