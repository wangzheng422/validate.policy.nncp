# AI-Author: Codex (OpenAI model not exposed by runtime)
"""Render a caller-authorized inventory snapshot using the bundled Archify runtime."""
import json
import os
from pathlib import Path
import subprocess
import threading

from .kube import APIError, GROUP

_RENDER_SLOTS = threading.BoundedSemaphore(2)
_RENDERER = Path(__file__).resolve().parent.parent / 'topology' / 'render.mjs'


def render_topology(kube, node_name, language='en'):
    if language not in ('en', 'zh-CN', 'zh-TW') or not isinstance(node_name, str) or len(node_name) > 253:
        raise APIError(400, {'message': 'Unsupported topology node or language'})
    # Authenticate every request, including repeats: never share authorization via a cache.
    snapshot = kube.get(GROUP + '/primarynetworkinventories/cluster').get('status', {})
    node = next((n for n in snapshot.get('nodes', []) if n.get('name') == node_name), None)
    if node is None:
        raise APIError(404, {'message': 'Node is not present in the observed inventory'})
    payload = json.dumps({'node': node, 'revision': snapshot.get('revision', ''), 'locale': language})
    if len(payload.encode()) > 128 * 1024:
        raise APIError(422, {'message': 'Observed topology exceeds the rendering limit; inspect source evidence'})
    if not _RENDER_SLOTS.acquire(blocking=False):
        raise APIError(429, {'message': 'Topology renderer is busy; try again shortly'})
    try:
        # A fixed executable/script and stdin data prevent shell/path interpolation.
        result = subprocess.run(['node', '--max-old-space-size=192', str(_RENDERER)],
                                input=payload, text=True, capture_output=True, timeout=15,
                                cwd=str(_RENDERER.parent.parent), check=False,
                                env={**os.environ, 'LD_LIBRARY_PATH': '/opt/node-libs'})
        if result.returncode or len(result.stdout.encode()) > 2 * 1024 * 1024:
            raise APIError(422, {'message': 'Topology could not be laid out within the supported limits; source evidence remains available'})
        response = json.loads(result.stdout)
        if not isinstance(response, dict) or not isinstance(response.get('html'), str) or response.get('node') != node_name:
            raise ValueError('Unexpected renderer output')
        return response
    except subprocess.TimeoutExpired:
        raise APIError(504, {'message': 'Topology rendering timed out; inspect source evidence or retry'}) from None
    except (OSError, ValueError):
        raise APIError(502, {'message': 'Topology renderer is unavailable'}) from None
    finally:
        _RENDER_SLOTS.release()
