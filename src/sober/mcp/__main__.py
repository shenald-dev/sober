"""Standalone MCP server entrypoint: ``python -m sober.mcp [--path ROOT]``."""

import argparse
from pathlib import Path

from sober.mcp.server import run


def main():
    parser = argparse.ArgumentParser(prog="sober.mcp", description="SOBER MCP stdio server")
    parser.add_argument("--path", default=".", help="Project root to confine tool access to.")
    args = parser.parse_args()
    run(Path(args.path))


if __name__ == "__main__":
    main()
