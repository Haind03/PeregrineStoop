# Safe active probes

GET/OPTIONS only, non-destructive, scope-gated. Each reports a *candidate* to
verify, never a confirmation:

- reflected-input (DOM-context aware via stdlib `html.parser`)
- open-redirect
- CORS reflection (with/without credentials)
- dangerous HTTP methods (OPTIONS enumeration)

## Reflection stability and quote context

The reflected-input probe now confirms a hit by reproducing it with a second
fresh marker. A reflection that does not reproduce is treated as noise (for
example a cache or a one off echo) and reported at low severity as
"unconfirmed". A reproducible reflection in an exploitable context is raised to
high confidence. For the attribute context the probe also reports which quote
(single, double, or both) survived unencoded, since that is what an attribute
breakout needs.

## Deeper CORS checks

The CORS probe tests several crafted Origins, not just one, each a single benign
GET with an Origin header:

* arbitrary origin reflection
* the `null` origin
* a weak suffix pattern (`https://host.attacker.example`)
* a weak prefix pattern (`https://attacker-host`)

For each origin the server trusts via ACAO it reports a candidate, raised to high
severity and confidence when credentials are also allowed.
