# Overview

PeregrineStoop is an authorized blackbox-recon accelerator. It reduces friction
between recon steps rather than adding another raw scanner. Four CLI modules
share one state layer, and every HTTP request passes a scope gate + audit log.

Subcommands: `fingerprint`, `crawl`, `diff`, `run`, `probe`, `report`, `resume`.
