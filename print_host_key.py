"""Print the SHA256 fingerprint of an SSH server's host key, without logging in.

Usage:  uv run print_host_key.py ssh.example.com [port]

Compare the output with the fingerprint your SFTP client (for example WinSCP) shows for the same host,
then put it into SFTP_HOST_KEY_SHA256. Only trust the value after that comparison.
"""
import sys

import paramiko

from server import fingerprint_sha256


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=20)
        key = transport.get_remote_server_key()
        print(f"{host}:{port}")
        print(f"  key type:    {key.get_name()}")
        print(f"  fingerprint: {fingerprint_sha256(key.asbytes())}")
    finally:
        transport.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
