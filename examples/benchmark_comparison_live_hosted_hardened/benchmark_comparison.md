# TRACE Benchmark Comparison

- Baseline Profile: `heuristic`
- Baseline Settings: `{}`
- Candidate Profile: `live-hosted`
- Candidate Settings: `{'provider': 'hosted', 'model': 'provider-default', 'adapter': 'openai-compatible', 'window_size': 8}`
- References Compared: `3`
- Drift Count: `1`
- Drift Free: `False`

| Reference | Sensitivity | Behavioral Δ | Vulnerability Δ | Findings Changed | Threshold Changed | Drift |
|---|---|---:|---:|---|---|---|
| `companion_incident.json` | `critical` | `0.0` | `0.0` | `False` | `False` | `False` |
| `reference_long_case.json` | `critical` | `0.0` | `-12.5` | `False` | `False` | `True` |
| `reference_noisy_case.json` | `noisy` | `0.0` | `0.0` | `False` | `False` | `False` |

## Provider Drift Policy

- Status: `pass`
- Mode: `warning`
- Warning Count: `0`
- Failure Count: `0`
- Summary: Provider drift remains within configured bounds.
