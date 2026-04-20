# TRACE Benchmark Summary

- Profile: `live-hosted`
- Profile Settings: `{'provider': 'openrouter', 'model': 'openrouter/free', 'window_size': 8}`
- Fixtures: `3`
- Passed: `0`
- Failed: `3`
- Pass Rate: `0.0%`
- Total Time: `0.0126` seconds

| Reference | Profile | Behavioral | Vulnerability | Findings Match | Pass | Time (s) |
|---|---|---:|---:|---|---|---:|
| `companion_incident.json` | `live-hosted` | `100.0%` | `75.0%` | `True` | `False` | `0.0023` |
| `reference_long_case.json` | `live-hosted` | `100.0%` | `75.0%` | `True` | `False` | `0.0079` |
| `reference_noisy_case.json` | `live-hosted` | `100.0%` | `75.0%` | `True` | `False` | `0.0024` |
