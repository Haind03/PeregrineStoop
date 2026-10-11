"""Shared test fakes. No real network is ever used.

Builds genuine ``requests.Response`` objects whose ``.raw`` is a tiny
file-like supporting ``read(amt, decode_content=...)`` and a ``get_all``
headers shim, so :class:`StoopHTTP`'s streaming/body-cap path is exercised
faithfully.
"""
from __future__ import annotations

import io

import pytest
from requests.models import Response
from requests.structures import CaseInsensitiveDict


class FakeHeaders:
    """urllib3-style headers supporting get_all for multiple Set-Cookie."""

    def __init__(self, headers: dict) -> None:
        self._h = headers

    def get_all(self, key, default=None):
        for k, v in self._h.items():
            if k.lower() == key.lower():
                return v if isinstance(v, list) else [v]
        return default


class FakeRaw:
    def __init__(self, body: bytes, headers: dict) -> None:
        self._buf = io.BytesIO(body)
        self.headers = FakeHeaders(headers)

    def read(self, amt=None, decode_content=False):  # mimic urllib3 signature
        return self._buf.read(amt)


def make_response(status=200, headers=None, body=b"", url="https://x/") -> Response:
    headers = headers or {}
    r = Response()
    r.status_code = status
    flat = {k: (", ".join(v) if isinstance(v, list) else v)
            for k, v in headers.items()}
    r.headers = CaseInsensitiveDict(flat)
    r.url = url
    r.raw = FakeRaw(body, headers)
    return r


class FakeSession:
    """Drop-in for requests.Session that never touches the network."""

    def __init__(self, handler=None) -> None:
        self.headers: dict = {}
        self.sent: list = []
        self.handler = handler or (lambda m, u, kw: make_response(200, {}, b"ok"))

    def request(self, method, url, **kw):
        self.sent.append((method, url, kw))
        return self.handler(method, url, kw)


@pytest.fixture
def fake_session_factory():
    return lambda handler=None: FakeSession(handler)
