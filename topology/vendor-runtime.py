#!/usr/bin/env python3
# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Copy only the architecture renderer dependency closure, preserving upstream bytes."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('source', type=Path, help='Installed Archify package directory')
source = parser.parse_args().source.resolve()
target = Path(__file__).resolve().parent / 'vendor' / 'archify'
pending = [Path('renderers/architecture/render-architecture.mjs'), Path('scripts/check-render-output.mjs')]
seen = set()
while pending:
    relative = pending.pop()
    if relative in seen:
        continue
    seen.add(relative)
    text = (source / relative).read_text()
    for dependency in re.findall(r"(?:from\s+|import\s*)['\"](\.[^'\"]+)['\"]", text):
        path = ((source / relative).parent / dependency).resolve().relative_to(source)
        pending.append(path)
seen.update(map(Path, ['assets/template.html', 'assets/JetBrainsMono-OFL.txt', 'LICENSE', 'THIRD_PARTY_NOTICES.md']))
manifest = []
for relative in sorted(seen):
    destination = target / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / relative, destination)
    manifest.append({'path': str(relative), 'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(), 'bytes': destination.stat().st_size})
(target.parent / 'manifest.json').write_text(json.dumps({'upstream': 'https://github.com/tt-a1i/archify', 'version': '2.17.0-dev.1', 'files': manifest}, indent=2) + '\n')
print(f'Copied {len(manifest)} runtime/license files, {sum(x["bytes"] for x in manifest)} bytes')
