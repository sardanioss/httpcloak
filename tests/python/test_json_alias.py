"""
Locks for the json / json_data parameter split and the fast-path JSON body.

Offline: everything here is signature inspection or an argument-validation
error raised before any socket is opened, so it needs no network.
"""

import inspect
import sys
import warnings

sys.path.insert(0, "bindings/python")

import pytest

import httpcloak
from httpcloak.client import Session

# The async, fast and streaming methods took json_data while the sync ones
# took json, so the same argument had a different name depending on which
# method you reached for.
SPLIT_METHODS = [
    "post_async", "request_async",
    "post_fast", "request_fast", "put_fast", "patch_fast",
    "post_stream", "put_stream", "patch_stream",
]


@pytest.mark.parametrize("name", SPLIT_METHODS)
def test_json_is_accepted_everywhere(name):
    params = inspect.signature(getattr(Session, name)).parameters
    assert "json" in params, f"{name} still only accepts json_data"
    assert "json_data" in params, f"{name} dropped the json_data alias, which breaks callers"


def test_passing_both_raises():
    s = httpcloak.Session(preset="chrome-146")
    try:
        with pytest.raises(TypeError, match="not both"):
            s.post_fast("https://example.com", json={"a": 1}, json_data={"b": 2})
    finally:
        s.close()


def test_json_data_still_works_and_warns():
    s = httpcloak.Session(preset="chrome-146")
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            # Reaches the alias resolution, then fails on the bad host. The
            # warning is what this asserts; the request outcome is irrelevant.
            try:
                s.post_fast("https://no-such-host.invalid", json_data={"a": 1})
            except Exception:
                pass
        assert any(issubclass(w.category, DeprecationWarning) for w in caught), \
            "json_data no longer warns, so nobody will migrate off it"
    finally:
        s.close()


def test_fast_json_body_without_headers_does_not_crash():
    """
    _apply_cookies returns None when there are neither headers nor cookies, so
    the fast methods raised TypeError on merged_headers["content-type"] and a
    JSON body with no headers could not be sent at all. The failure was in
    argument handling, before any connection, so an unreachable host still
    exercises it.
    """
    s = httpcloak.Session(preset="chrome-146")
    try:
        with pytest.raises(Exception) as exc:
            s.post_fast("https://no-such-host.invalid", json={"a": 1})
        assert "does not support item assignment" not in str(exc.value), \
            "fast path still crashes on a JSON body with no headers"
    finally:
        s.close()
