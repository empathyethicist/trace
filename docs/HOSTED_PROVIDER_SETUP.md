# TRACE Hosted Provider Setup

This document defines the supported public interface for TRACE hosted-provider use.

## Stable environment variables

TRACE uses these environment variables for hosted execution:

- `TRACE_HOSTED_API_KEY`
- `TRACE_HOSTED_BASE_URL`
- `TRACE_HOSTED_MODEL` (optional)
- `TRACE_HOSTED_ADAPTER` (optional, defaults to `openai-compatible`)

The recommended starting point is the repo-root `.env.example`.

## Expected API contract

TRACE currently supports these hosted adapters:

- `openai-compatible`
- `anthropic-messages`

### `openai-compatible`

This adapter expects:

- the request is sent as JSON
- the request body includes:
  - `model`
  - `temperature`
  - `messages`
- the response should include a chat-completions style assistant message payload that TRACE can normalize into its classification schema

### `anthropic-messages`

This adapter expects:

- the request is sent as JSON
- the request body includes:
  - `model`
  - `temperature`
  - `system`
  - `messages`
- the response should include `content` blocks with text segments that TRACE can normalize into its classification schema

TRACE does not require a specific vendor. It requires a provider that matches one of the supported adapter contracts.

## Minimal hosted configuration

Example:

```bash
export TRACE_HOSTED_API_KEY=replace-with-provider-api-key
export TRACE_HOSTED_BASE_URL=https://provider.example/v1/chat/completions
export TRACE_HOSTED_MODEL=provider-default
export TRACE_HOSTED_ADAPTER=openai-compatible
```

Then verify the configuration:

```bash
trace config-check --provider hosted
```

## Minimal hosted classification run

```bash
trace classify \
  --case-id CASE-001 \
  --provider hosted \
  --model provider-default
```

## Replay-first hosted evaluation

For evaluation or partner testing, replay capture should be the default posture:

```bash
trace classify \
  --case-id CASE-001 \
  --provider hosted \
  --model provider-default \
  --replay-dir ./replay_artifacts \
  --replay-mode record
```

Then rerun locally:

```bash
trace classify \
  --case-id CASE-001 \
  --provider hosted \
  --model provider-default \
  --replay-dir ./replay_artifacts \
  --replay-mode replay-only
```

## Provider selection guidance

Good hosted targets for TRACE share these characteristics:

- stable support for one of the supported adapter contracts
- explicit model identifiers
- operationally acceptable latency
- predictable authentication
- low schema drift under repeated runs

If a provider does not expose a supported contract, it should be integrated through an adapter layer rather than by changing TRACE’s public environment-variable contract.

## Current limitation

TRACE is provider-agnostic at the configuration surface, but it currently supports only the adapter contracts listed above. Additional providers should be added as explicit adapters rather than by overloading the current hosted interface.
