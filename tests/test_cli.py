"""CLI wiring tests: parser builds, help works, empty scope refused."""
from __future__ import annotations

import pytest

from peregrinestoop.cli import build_parser, main


def test_parser_has_all_subcommands():
    p = build_parser()
    # argparse exits on --help; just confirm subparsers exist via parse
    for cmd in ("fingerprint", "diff", "run", "resume"):
        ns = p.parse_args([cmd] + (["http://x"] if cmd in ("fingerprint", "run") else []))
        assert ns.command == cmd


def test_main_help_exits_zero():
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0


@pytest.mark.parametrize("cmd", ["fingerprint", "diff", "run", "resume"])
def test_each_subcommand_help(cmd):
    with pytest.raises(SystemExit) as e:
        main([cmd, "--help"])
    assert e.value.code == 0


def test_run_refuses_empty_scope():
    with pytest.raises(SystemExit) as e:
        main(["run", "https://a.target.com"])  # no --scope
    assert e.value.code == 2
