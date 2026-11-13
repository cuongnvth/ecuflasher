"""Entry point 32-bit cho Seed-Key bridge."""
import sys

if __name__ == "__main__":
    from uds_core import _seedkey_cli
    if len(sys.argv) > 1 and sys.argv[1] == "--seedkey-once":
        sys.exit(_seedkey_cli(sys.argv[2:]))
    sys.stderr.write("Usage: ECUFlasher32.exe --seedkey-once <dll> <export> <level> <seedhex>\n")
    sys.exit(1)
