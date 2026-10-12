# Practice targets

Small, intentionally fingerprintable apps you can run on your own machine to try
PeregrineStoop against. They are for **authorized self testing** only (they run
on localhost, which is in your control).

> These demo targets reflect input and redirect on purpose so the probes have
> something to find. Do not deploy them on a public host.

## PHP target

```bash
php -S 127.0.0.1:8000 -t examples/targets/php
stoop run http://127.0.0.1:8000/ --scope 127.0.0.1 --crawl --session-dir out/
```

## Node.js target

```bash
node examples/targets/node/server.js
stoop run http://127.0.0.1:8001/ --scope 127.0.0.1 --crawl
```

Things to look for in the output: the reflected `q` parameter, the open redirect
on `/go?next=`, the discovered `/api/v1/users` and `/internal/debug` endpoints,
and the tech fingerprint from the Server header and cookies.
