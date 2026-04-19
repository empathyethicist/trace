# TRACE Benchmark Comparison

- Baseline Profile: `heuristic`
- Baseline Settings: `{}`
- Candidate Profile: `live-hosted`
- Candidate Settings: `{'provider': 'openrouter', 'model': 'openrouter/free', 'window_size': 8}`
- References Compared: `5`
- Drift Count: `3`
- Drift Free: `False`

| Reference | Behavioral Δ | Vulnerability Δ | Findings Changed | Threshold Changed | Drift |
|---|---:|---:|---|---|---|
| `companion_incident.json` | `-25.0` | `-75.0` | `False` | `True` | `True` |
| `reference_benign_case.json` | `0.0` | `0.0` | `False` | `False` | `False` |
| `reference_long_case.json` | `-12.5` | `-87.5` | `False` | `True` | `True` |
| `reference_mixed_case.json` | `0.0` | `0.0` | `False` | `False` | `False` |
| `reference_noisy_case.json` | `0.0` | `-50.0` | `True` | `True` | `True` |

## Provider Drift Policy

- Status: `warn`
- Mode: `warning`
- Warning Count: `7`
- Failure Count: `0`
- Summary: Provider drift triggered 7 policy violations.

| Scope | Reference | Metric | Expected Max | Actual | Severity |
|---|---|---|---:|---:|---|
| `global` | `-` | `drift_count` | `1` | `3` | `warning` |
| `reference` | `companion_incident.json` | `behavioral_delta` | `10.0` | `-25.0` | `warning` |
| `reference` | `companion_incident.json` | `vulnerability_delta` | `25.0` | `-75.0` | `warning` |
| `reference` | `reference_long_case.json` | `behavioral_delta` | `10.0` | `-12.5` | `warning` |
| `reference` | `reference_long_case.json` | `vulnerability_delta` | `25.0` | `-87.5` | `warning` |
| `reference` | `reference_noisy_case.json` | `vulnerability_delta` | `25.0` | `-50.0` | `warning` |
| `reference` | `reference_noisy_case.json` | `findings_changed` | `False` | `True` | `warning` |
