# Safe active probes

GET/OPTIONS only, non-destructive, scope-gated. Each reports a *candidate* to
verify, never a confirmation:

- reflected-input (DOM-context aware via stdlib `html.parser`)
- open-redirect
- CORS reflection (with/without credentials)
- dangerous HTTP methods (OPTIONS enumeration)
