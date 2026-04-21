# TRACE Benchmark Summary

- Profile: `live-hosted`
- Profile Settings: `{'provider': 'hosted', 'model': 'provider-default', 'adapter': 'openai-compatible', 'window_size': 8}`
- Fixtures: `5`
- Passed: `2`
- Failed: `3`
- Pass Rate: `40.0%`
- Total Time: `397.5752` seconds

| Reference | Profile | Behavioral | Vulnerability | Findings Match | Pass | Time (s) |
|---|---|---:|---:|---|---|---:|
| `companion_incident.json` | `live-hosted` | `75.0%` | `25.0%` | `True` | `False` | `95.3765` |
| `reference_benign_case.json` | `live-hosted` | `100.0%` | `100.0%` | `True` | `True` | `7.8674` |
| `reference_long_case.json` | `live-hosted` | `87.5%` | `12.5%` | `True` | `False` | `196.111` |
| `reference_mixed_case.json` | `live-hosted` | `100.0%` | `100.0%` | `True` | `True` | `48.668` |
| `reference_noisy_case.json` | `live-hosted` | `100.0%` | `50.0%` | `False` | `False` | `49.5523` |
