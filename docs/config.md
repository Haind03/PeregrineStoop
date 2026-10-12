# Config profiles

Keep per-engagement defaults in a TOML file (stdlib `tomllib`):

```toml
[scope]
include = ["*.target.com"]
exclude = ["admin.target.com"]

[http]
rate = 2
budget = 600
timeout = 20
```

Pass `--config stoop.toml`. Explicit CLI flags override the config, which
overrides the built-in defaults.
