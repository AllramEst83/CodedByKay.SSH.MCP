"""Offline tests: path jail, fingerprint format, fail-closed configuration. No network."""
import base64
import hashlib

import pytest

import server


def test_resolve_inside_root():
    assert server.resolve_path("/", "/assets/images") == "/assets/images"
    assert server.resolve_path("/www", "assets") == "/www/assets"
    assert server.resolve_path("/www", "/") == "/www"
    assert server.resolve_path("/www", "") == "/www"


@pytest.mark.parametrize("bad", ["../etc/passwd", "a/../../etc", "/../..", "..\\..\\x"])
def test_resolve_refuses_escape(bad):
    with pytest.raises(server.PathError):
        server.resolve_path("/www", bad)


def test_resolve_refuses_nul():
    with pytest.raises(server.PathError):
        server.resolve_path("/www", "a\x00b")


def test_sibling_prefix_is_not_inside_root():
    assert not server.within_root("/www", "/www2/x")
    assert server.within_root("/www", "/www/x")
    assert server.within_root("/www", "/www")


def test_display_path():
    assert server.display_path("/www", "/www/assets/a.jpg") == "/assets/a.jpg"
    assert server.display_path("/www", "/www") == "/"
    assert server.display_path("/", "/a") == "/a"


def test_fingerprint_format():
    blob = b"example key blob"
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert server.fingerprint_sha256(blob) == expected
    assert "=" not in expected


def test_connect_fails_closed_without_pinned_key(monkeypatch):
    monkeypatch.setenv("SFTP_HOST", "example.invalid")
    monkeypatch.setenv("SFTP_USER", "u")
    monkeypatch.delenv("SFTP_HOST_KEY_SHA256", raising=False)
    with pytest.raises(server.ConfigError):
        with server._sftp():
            pass


def test_only_three_tools_are_exposed():
    import asyncio

    tools = asyncio.run(server.mcp.list_tools())
    assert sorted(t.name for t in tools) == ["list_dir", "read_text", "stat"]


def test_kind_and_iso():
    import stat as s

    assert server.kind_of(s.S_IFDIR | 0o755) == "dir"
    assert server.kind_of(s.S_IFREG | 0o644) == "file"
    assert server.kind_of(None) == "unknown"
    assert server.iso(0) == "1970-01-01T00:00:00Z"
    assert server.iso(None) is None
