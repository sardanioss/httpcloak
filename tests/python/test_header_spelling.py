"""
Locks for header spellings the caller chose.

The transport sends one spelling of a header name and prefers the canonical
one, so anything the binding or the session adds beside a caller's lowercase
spelling must not replace the caller's value. Runs against a local HTTP
server; nothing leaves the machine.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, "bindings/python")

import pytest

import httpcloak


class _Echo(BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        elif "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                self.rfile.read(size + 2)
                if size == 0:
                    break
        body = json.dumps({
            "cookie": self.headers.get_all("Cookie") or [],
            "content_type": self.headers.get_all("Content-Type") or [],
            "authorization": self.headers.get_all("Authorization") or [],
            "x": [v for k, v in self.headers.items() if k.lower().startswith("x-")],
        }).encode()
        self.send_response(200)
        self.send_header("Set-Cookie", "jar=1; Path=/")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def url():
    srv = HTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


@pytest.fixture
def session():
    s = httpcloak.Session(preset="chrome-latest", http_version="h1")
    yield s
    s.close()


def test_lowercase_cookie_survives_a_full_jar(session, url):
    session.get(url)  # the jar now holds jar=1
    for _ in range(5):
        got = session.get(url, headers={"cookie": "mine=1"}, cookies={"c": "3"}).json()
        assert len(got["cookie"]) == 1
        for part in ("mine=1", "c=3", "jar=1"):
            assert part in got["cookie"][0], got


def test_lowercase_content_type_beats_the_json_default(session, url):
    for _ in range(5):
        got = session.post(url, json={"a": 1}, headers={"content-type": "application/vnd.api+json"}).json()
        assert got["content_type"] == ["application/vnd.api+json"], got


def test_auth_replaces_any_authorization_spelling(session, url):
    got = session.get(url, auth=("u", "p"), headers={"authorization": "Bearer mine"}).json()
    assert got["authorization"] == ["Basic dTpw"], got


def test_headers_as_pairs(session, url):
    session.headers = {"X-S": "s"}
    try:
        got = session.get(url, headers=[("X-A", "1")]).json()
        assert sorted(got["x"]) == ["1", "s"], got
        got = session.get(url, headers=(("X-B", "2"),)).json()
        assert sorted(got["x"]) == ["2", "s"], got
    finally:
        session.headers = {}


@pytest.mark.parametrize("call", ["post_fast", "request_fast"])
@pytest.mark.parametrize("kw", [{"json": {"a": 1}}, {"data": {"a": "1"}}])
def test_fast_paths_keep_a_lowercase_content_type(session, url, call, kw):
    send = getattr(session, call)
    args = (url,) if call == "post_fast" else ("POST", url)
    got = send(*args, headers={"content-type": "text/x-mine"}, **kw).json()
    assert got["content_type"] == ["text/x-mine"], got


@pytest.mark.parametrize("call", ["post_fast", "request_fast"])
def test_fast_form_body_needs_no_headers(session, url, call):
    send = getattr(session, call)
    args = (url,) if call == "post_fast" else ("POST", url)
    got = send(*args, data={"a": "1"}).json()
    assert got["content_type"] == ["application/x-www-form-urlencoded"], got


def test_streaming_upload_keeps_a_lowercase_content_type(session, url):
    got = session.post(url, data=iter([b"ab", b"cd"]), headers={"content-type": "text/plain"}).json()
    assert got["content_type"] == ["text/plain"], got


@pytest.mark.parametrize("bad", [True, "90", [90]])
def test_http2_max_conn_age_rejects_non_numbers(bad):
    with pytest.raises(TypeError):
        httpcloak.Session(http2_max_conn_age=bad)


def test_http2_max_conn_age_takes_a_float():
    s = httpcloak.Session(http2_max_conn_age=1.5)
    s.close()


@pytest.mark.parametrize("bad", [float("inf"), float("nan")])
def test_http2_max_conn_age_rejects_non_finite(bad):
    with pytest.raises(ValueError):
        httpcloak.Session(http2_max_conn_age=bad)
