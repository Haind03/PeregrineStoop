"""Config-profile tests (TOML) + its effect through the CLI. No network."""
from __future__ import annotations

import json

from peregrinestoop import cli
from peregrinestoop.common import StoopHTTP
from peregrinestoop.config import cfg_http, cfg_scope, load_config
from conftest import FakeSession, make_response


def _write(tmp_path, text):
    p = tmp_path / "stoop.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_load_config_parses(tmp_path):
    path = _write(tmp_path, '[scope]\ninclude=["*.target.com"]\nexclude=["x.target.com"]\n'
                            '[http]\nrate=2\nbudget=600\ntimeout=20\n')
    cfg = load_config(path)
    assert cfg_scope(cfg) == (["*.target.com"], ["x.target.com"])
    assert cfg_http(cfg, "rate", 3) == 2
    assert cfg_http(cfg, "budget", 300) == 600


def test_load_config_missing_is_empty(tmp_path):
    assert load_config(str(tmp_path / "nope.toml")) == {}


def test_load_config_invalid_is_empty(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml", encoding="utf-8")
    assert load_config(str(bad)) == {}


def test_cli_uses_config_scope(monkeypatch, tmp_path):
    # no --scope on the CLI; scope comes entirely from the config file
    path = _write(tmp_path, '[scope]\ninclude=["*.target.com"]\n')

    def fake_build(args, scope, sid):
        return StoopHTTP(scope, rate=0, session=FakeSession(
            lambda m, u, kw: make_response(200, {"Server": "nginx"}, b"")))
    monkeypatch.setattr(cli, "_build_http", fake_build)

    out = tmp_path / "fp.json"
    rc = cli.main(["fingerprint", "https://a.target.com/", "--config", path,
                   "--state-db", str(tmp_path / "s.sqlite"),
                   "--audit-log", str(tmp_path / "a.jsonl"), "--json", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())["server"] == "nginx"


def test_cli_flag_overrides_config_rate(monkeypatch, tmp_path):
    path = _write(tmp_path, '[scope]\ninclude=["*.target.com"]\n[http]\nrate=1\n')
    captured = {}

    def fake_build(args, scope, sid):
        # mirror real resolution: CLI --rate wins over config
        from peregrinestoop.config import cfg_http
        rate = args.rate if args.rate is not None else cfg_http(cli._cfg(args), "rate", 3.0)
        captured["rate"] = rate
        return StoopHTTP(scope, rate=0, session=FakeSession(
            lambda m, u, kw: make_response(200, {}, b"")))
    monkeypatch.setattr(cli, "_build_http", fake_build)

    cli.main(["fingerprint", "https://a.target.com/", "--config", path,
              "--rate", "5", "--state-db", str(tmp_path / "s.sqlite"),
              "--audit-log", str(tmp_path / "a.jsonl"), "--json", str(tmp_path / "o.json")])
    assert captured["rate"] == 5      # explicit flag beat config's rate=1
