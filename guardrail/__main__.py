# AI-Author: Codex (OpenAI model not exposed by runtime)
import argparse
import json
from pathlib import Path
import yaml

from . import api, audit, controller
from .discovery import discover


def main():
    parser = argparse.ArgumentParser(description="Network Guardrail; no persistent NNCP writes")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("serve", "controller", "collect"):
        sub.add_parser(command)
    offline = sub.add_parser("discover", help="Generate review candidates from exported JSON snapshots")
    offline.add_argument("--nodes", required=True)
    offline.add_argument("--states", required=True)
    args = parser.parse_args()
    if args.command == "discover":
        _, parameters = discover(json.loads(Path(args.nodes).read_text())["items"], json.loads(Path(args.states).read_text())["items"])
        print(yaml.safe_dump(parameters, sort_keys=False))
    else:
        {"serve": api.run, "controller": controller.run, "collect": audit.run}[args.command]()


if __name__ == "__main__":
    main()
