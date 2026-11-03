"""Best-effort metrics; see docs/rules.md."""
import socket


def emit(name, value):
    try:
        sock = socket.create_connection(("metrics.internal", 8125), timeout=0.05)
        sock.sendall(f"{name}:{value}".encode())
        sock.close()
    except Exception:
        pass
