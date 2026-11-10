"""Read-only SFTP MCP server.

Three tools and nothing else: list_dir, stat, read_text. There is no upload, delete, rename or
command execution, so the server cannot change anything on the remote host by construction.

Configuration comes from environment variables (set them in the MCP registration, never in tool arguments):

    SFTP_HOST                 required, e.g. ssh.example.com
    SFTP_PORT                 default 22
    SFTP_USER                 required
    SFTP_HOST_KEY_SHA256      required, "SHA256:..." fingerprint of the server host key (see print_host_key.py)
    SFTP_KEY_FILE             path to a private key (preferred), or
    SFTP_PASSWORD             password (fallback)
    SFTP_KEY_PASSPHRASE       optional, for an encrypted key file
    SFTP_ROOT                 remote folder the tools may see; every tool path is relative to it (default "/")
    SFTP_MAX_READ_BYTES       upper limit for read_text (default 200000)
    SFTP_MAX_LIST_ENTRIES     upper limit for list_dir (default 2000)
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import os
import posixpath
import stat as statmod
from typing import Any, Iterator

import paramiko
from fastmcp import FastMCP

mcp = FastMCP("CodedByKay SSH MCP (read-only SFTP)")

CONNECT_TIMEOUT = 20


class ConfigError(RuntimeError):
    pass


class PathError(ValueError):
    pass


# ---------------------------------------------------------------- pure helpers (unit-tested)

def fingerprint_sha256(key_blob: bytes) -> str:
    """OpenSSH-style fingerprint: SHA256:<base64 without padding>."""
    digest = hashlib.sha256(key_blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def normalize_root(root: str) -> str:
    # posixpath.normpath keeps a leading "//", so strip all leading slashes first.
    return posixpath.normpath("/" + (root or "/").strip().lstrip("/"))


def resolve_path(root: str, path: str) -> str:
    """Map a tool path (relative to `root`) to an absolute remote path, refusing anything outside `root`."""
    root = normalize_root(root)
    rel = (path or "/").replace("\\", "/")
    if "\x00" in rel:
        raise PathError("Invalid path.")
    full = posixpath.normpath(posixpath.join(root, rel.lstrip("/")))
    if not within_root(root, full):
        raise PathError("Path is outside the allowed root.")
    return full


def within_root(root: str, full: str) -> bool:
    root = normalize_root(root)
    return full == root or root == "/" or full.startswith(root.rstrip("/") + "/")


def display_path(root: str, full: str) -> str:
    root = normalize_root(root)
    if root == "/":
        return full
    rel = full[len(root):]
    return rel if rel.startswith("/") else "/" + rel


def iso(ts: int | None) -> str | None:
    if ts is None:
        return None
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def kind_of(mode: int | None) -> str:
    if mode is None:
        return "unknown"
    if statmod.S_ISDIR(mode):
        return "dir"
    if statmod.S_ISLNK(mode):
        return "symlink"
    if statmod.S_ISREG(mode):
        return "file"
    return "other"


# ---------------------------------------------------------------- configuration and connection

def _env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.environ.get(name, default)
    if required and not value:
        raise ConfigError(f"Environment variable {name} is not set.")
    return value


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number.") from exc


def _authenticate(transport: paramiko.Transport, user: str) -> None:
    key_file = _env("SFTP_KEY_FILE")
    password = _env("SFTP_PASSWORD")
    if key_file:
        passphrase = _env("SFTP_KEY_PASSPHRASE")
        pkey = paramiko.PKey.from_path(key_file, passphrase=passphrase.encode() if passphrase else None)
        transport.auth_publickey(user, pkey)
        return
    if not password:
        raise ConfigError("Set SFTP_KEY_FILE (preferred) or SFTP_PASSWORD.")
    try:
        transport.auth_password(user, password)
    except paramiko.BadAuthenticationType as exc:
        # Some hosts only offer keyboard-interactive for passwords.
        if "keyboard-interactive" not in exc.allowed_types:
            raise
        transport.auth_interactive(user, lambda title, instructions, prompts: [password for _ in prompts])


@contextlib.contextmanager
def _sftp() -> Iterator[paramiko.SFTPClient]:
    """Open an SFTP session after verifying the pinned host key; fail closed on any mismatch."""
    host = _env("SFTP_HOST", required=True)
    user = _env("SFTP_USER", required=True)
    pinned = _env("SFTP_HOST_KEY_SHA256", required=True)
    port = _int_env("SFTP_PORT", 22)
    transport = paramiko.Transport((host, port))
    try:
        transport.banner_timeout = CONNECT_TIMEOUT
        transport.start_client(timeout=CONNECT_TIMEOUT)
        seen = fingerprint_sha256(transport.get_remote_server_key().asbytes())
        if not hmac.compare_digest(seen, pinned.strip()):
            raise PermissionError(f"Host key mismatch: server presented {seen}. Refusing to connect.")
        _authenticate(transport, user)
        client = paramiko.SFTPClient.from_transport(transport)
        client.get_channel().settimeout(CONNECT_TIMEOUT)
        try:
            yield client
        finally:
            client.close()
    finally:
        transport.close()


def _root() -> str:
    return normalize_root(_env("SFTP_ROOT", "/") or "/")


def _checked_real_path(client: paramiko.SFTPClient, root: str, full: str) -> str:
    """Resolve symlinks on the server and make sure the real target is still inside the root."""
    try:
        real = client.normalize(full)
    except OSError:
        return full  # does not exist; callers report that
    if not within_root(root, real):
        raise PathError("Path resolves outside the allowed root.")
    return real


def _entry(attr: paramiko.SFTPAttributes, name: str | None = None) -> dict[str, Any]:
    return {
        **({"name": name} if name is not None else {}),
        "type": kind_of(attr.st_mode),
        "size": attr.st_size,
        "modified": iso(attr.st_mtime),
    }


# ---------------------------------------------------------------- tools

@mcp.tool()
def list_dir(path: str = "/") -> dict[str, Any]:
    """List a remote directory: names, types, sizes (bytes) and modification times (UTC). Read-only."""
    root = _root()
    full = resolve_path(root, path)
    limit = _int_env("SFTP_MAX_LIST_ENTRIES", 2000)
    with _sftp() as client:
        real = _checked_real_path(client, root, full)
        attrs = sorted(client.listdir_attr(real), key=lambda a: a.filename.lower())
        entries = [_entry(a, a.filename) for a in attrs[:limit]]
    return {"path": display_path(root, full), "count": len(attrs), "truncated": len(attrs) > limit, "entries": entries}


@mcp.tool()
def stat(path: str) -> dict[str, Any]:
    """Say whether a remote path exists and, if so, its type, size (bytes) and modification time. Read-only."""
    root = _root()
    full = resolve_path(root, path)
    with _sftp() as client:
        real = _checked_real_path(client, root, full)
        try:
            attr = client.stat(real)
        except FileNotFoundError:
            return {"path": display_path(root, full), "exists": False}
    return {"path": display_path(root, full), "exists": True, **_entry(attr)}


@mcp.tool()
def read_text(path: str, max_bytes: int = 20000) -> dict[str, Any]:
    """Read the start of a small text file (for example .htaccess). Returns at most max_bytes bytes, decoded as UTF-8."""
    root = _root()
    full = resolve_path(root, path)
    cap = _int_env("SFTP_MAX_READ_BYTES", 200000)
    max_bytes = max(1, min(int(max_bytes), cap))
    with _sftp() as client:
        real = _checked_real_path(client, root, full)
        attr = client.stat(real)
        if statmod.S_ISDIR(attr.st_mode or 0):
            raise PathError("That path is a directory; use list_dir.")
        with client.open(real, "rb") as handle:
            data = handle.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    text = data[:max_bytes].decode("utf-8", errors="replace")
    return {"path": display_path(root, full), "size": attr.st_size, "truncated": truncated, "text": text}


if __name__ == "__main__":
    mcp.run()  # stdio transport: nothing listens on the network
