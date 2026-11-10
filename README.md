# CodedByKay SSH MCP (read-only SFTP)

A small MCP server that lets Claude look at a remote server over SFTP, and nothing more.

| Tool | What it does |
|---|---|
| `list_dir(path)` | names, types, sizes (bytes) and modification times (UTC) of a folder |
| `stat(path)` | whether a path exists, and its type, size and modification time |
| `read_text(path, max_bytes)` | the start of a small text file, for example `.htaccess` |

There is no upload, delete, rename or command tool, so the server cannot change the remote host. It runs
over `stdio` (nothing listens on the network) and fails closed: it refuses to connect unless the server's
host key matches the fingerprint you pinned.

## Safety design

- **Read-only by construction.** Only the three tools above exist (a test asserts this).
- **Pinned host key.** `SFTP_HOST_KEY_SHA256` is required; a different key aborts the connection before any login.
- **Path jail.** Every path is relative to `SFTP_ROOT`; `..` and symlinks that leave it are refused.
- **Limits.** `read_text` returns at most 200,000 bytes, `list_dir` at most 2,000 entries (both configurable).
- **Credentials from the environment only**, never from tool arguments, so they never pass through the chat.

## Setup

1. Install the dependencies (needs [uv](https://docs.astral.sh/uv/)):
   ```powershell
   cd path\to\CodedByKay.SSH.MCP
   uv sync
   uv run pytest          # offline tests, no network
   ```
2. Find the host key fingerprint and compare it with WinSCP:
   ```powershell
   uv run print_host_key.py ssh.example.com 22
   ```
   In WinSCP, connect first, then the same fingerprint is under *Session > Server/Protocol Information* (use the SHA-256 one).
   Only continue if they match. Copy the `SHA256:...` value.
3. Register the server with Claude Code. **Type this yourself in your own terminal; do not paste your
   password into a chat.** Replace the two placeholders:
   ```powershell
   claude mcp add ssh-readonly `
     -e SFTP_HOST=ssh.example.com `
     -e SFTP_PORT=22 `
     -e SFTP_USER=YOUR_USERNAME `
     -e SFTP_PASSWORD=YOUR_PASSWORD `
     -e SFTP_HOST_KEY_SHA256=SHA256:PASTE_FINGERPRINT_HERE `
     -e SFTP_ROOT=/ `
     -- uv run --directory path\to\CodedByKay.SSH.MCP server.py
   ```
   `claude mcp add` stores these values in plain text in your Claude config on this machine. That is the
   same level of protection as a saved WinSCP password without a master password, but prefer a key if
   your host lets you add one: replace `SFTP_PASSWORD` with `-e SFTP_KEY_FILE=path\to\your\private-key`.
4. Restart Claude Code. Ask it to run `list_dir` on `/`. If the site files are in a subfolder, set
   `SFTP_ROOT` to that folder and re-register (`claude mcp remove ssh-readonly` first).

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `SFTP_HOST` | yes | host name, for example `ssh.example.com` |
| `SFTP_PORT` | no | default 22 |
| `SFTP_USER` | yes | login name |
| `SFTP_HOST_KEY_SHA256` | yes | pinned host key fingerprint, `SHA256:...` |
| `SFTP_KEY_FILE` | one of | private key path (preferred) |
| `SFTP_PASSWORD` | one of | password; tries `password`, then `keyboard-interactive` |
| `SFTP_KEY_PASSPHRASE` | no | passphrase for an encrypted key file |
| `SFTP_ROOT` | no | folder the tools may see, default `/` |
| `SFTP_MAX_READ_BYTES` | no | default 200000 |
| `SFTP_MAX_LIST_ENTRIES` | no | default 2000 |

## Limits

- It cannot fix anything on the server; deleting or uploading stays in WinSCP.
- `read_text` decodes as UTF-8 with replacement characters, so it is for text, not images or archives.
- The server account can still do more than this tool allows. For a hard guarantee use an account or key
  that has read-only rights on the host.
