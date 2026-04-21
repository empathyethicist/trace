# TRACE Adapter Registry

This document defines TRACE’s current adapter surface and the standard for adding new adapters.

## Purpose

TRACE should not blur provider-specific behavior into a vague hosted abstraction. The correct pattern is:

- stable public configuration surface
- explicit adapter contracts
- provider-specific translation isolated behind the adapter layer

That keeps external use predictable and keeps drift analysis attributable to a concrete contract.

## Current adapters

### `openai-compatible`

Use when the provider exposes a chat-completions style API.

Expected request shape:

- `model`
- `temperature`
- `messages`

Expected response shape:

- `choices[0].message.content`

### `anthropic-messages`

Use when the provider exposes an Anthropic-style messages API.

Expected request shape:

- `model`
- `temperature`
- `system`
- `messages`

Expected response shape:

- `content[]` text blocks

## Public configuration contract

TRACE exposes these hosted settings:

- `TRACE_HOSTED_API_KEY`
- `TRACE_HOSTED_BASE_URL`
- `TRACE_HOSTED_MODEL`
- `TRACE_HOSTED_ADAPTER`

These may be supplied either by environment variables or by per-run CLI overrides on commands that support hosted execution.

## Per-run override posture

TRACE supports per-run hosted overrides so a lab can:

- switch providers without rewriting environment state
- test alternate adapters during evaluation
- keep scripted runs explicit and auditable

This is the intended operational pattern for partner evaluation and benchmark work.

## Criteria for adding a new adapter

A new adapter should be added only when:

- the provider contract is materially different from existing adapters
- the request/response normalization can be stated clearly
- the adapter can be tested deterministically
- the adapter does not weaken replay, provenance, or drift-review behavior

## Adapter implementation rules

New adapters should:

- declare a stable adapter name
- build request payloads in one dedicated function
- build headers in one dedicated function
- extract text output in one dedicated function
- leave downstream TRACE normalization unchanged where possible

Do not overload an existing adapter with vendor-specific branching if the upstream contract is substantively different.

## Current boundary

TRACE is now portable across supported hosted contracts, but it is not yet a universal provider SDK. The adapter layer is the deliberate boundary between TRACE’s forensic workflow and provider-specific API variance.
