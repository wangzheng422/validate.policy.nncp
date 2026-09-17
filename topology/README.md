# Dynamic Archify topology

AI-Author: Codex (OpenAI model not exposed by runtime)

The live topology is rendered with the actual Archify architecture renderer and standalone interactive viewer, vendored from [tt-a1i/archify](https://github.com/tt-a1i/archify), package version `2.17.0-dev.1` (skill version 2.17). This is not a static screenshot or a restyled replacement renderer. Node.js 18+ is the only runtime dependency; no npm install or remote asset request is needed.

The authenticated backend reads the inventory with the Console user's token, then sends one JSON document on stdin to `node topology/render.mjs`:

```json
{"node":{"name":"node-name","primaryPath":[],"protectedInterfaces":[],"defaultRoutes":[],"edges":[],"warnings":[],"ready":false},"revision":"inventory-revision","locale":"zh-CN"}
```

Stdout contains exactly one JSON object with `html`, `node` (name), `revision`, `warnings`, and `renderer`. Errors use stderr and a nonzero exit. Production images need only `render.mjs`, `specification.mjs`, and `vendor/`; do not include live candidate specifications, captured HTML, screenshots, or validation receipts.

The generator derives interface nodes and dependency edges exclusively from NodeEvidence. Normalized default routes add explicit route-to-interface edges. Self-membership edges such as `br-ex → br-ex` are omitted from the drawing with an explanation; the application's raw evidence remains intact. Protected profile and alternative names are listed as aliases, not invented topology interfaces. Main uplink dependencies and OVN/supporting interfaces are arranged separately. Missing edge evidence is disclosed and never repaired by guessing connections. Trace animation is explicitly illustrative, not packet telemetry.

Input is capped at 128 KiB, 256 source edges, and 12 diagram components (including default-route nodes). Oversized or unrenderable graphs fail visibly so the raw evidence can still be inspected. Generated specifications have no remote brand URLs, source links, or arbitrary file references. The renderer HTML-escapes labels, and the Console embeds the result in an iframe with scripts/downloads enabled but without same-origin access. The Console prefetches the selected inventory revision's node diagrams after inventory discovery, keyed by node, locale and revision. The embedded viewer uses Archify's native `data-embed` mode, so it contains only the diagram surface with no toolbar, header, guided views, or navigation controls. A bounded `postMessage` height report lets the outer page expand naturally without an inner vertical scrollbar. The Console's full-architecture link opens the unchanged generated HTML in a new page; that page retains Archify's pan/zoom, themes, tracing, presentation and export controls. Standalone downloads retain the full viewer. Viewer fragment links identify views within that artifact; they are not publicly hosted share URLs.

`zh-CN` and English have native viewer toolbars. Traditional Chinese diagram text is generated, but the upstream viewer toolbar falls back to English; this limitation is shown in the UI. Each request performs all nine Archify artifact checks with zero composition warnings/errors before returning HTML. Those deterministic checks do not substitute for browser or perceptual validation.

## Upstream provenance and licensing

[Vendor manifest](vendor/manifest.json) records exact source-file SHA-256 hashes and byte sizes. [MIT license](vendor/archify/LICENSE), [upstream third-party notices](vendor/archify/THIRD_PARTY_NOTICES.md), and [embedded font license](vendor/archify/assets/JetBrainsMono-OFL.txt) are included. The 24 copied runtime/license files are byte-for-byte upstream files. Only the dependency closure of the architecture renderer and artifact checker plus their embedded viewer is included; other diagram renderers, examples, skills, and tools are omitted.

`vendor-runtime.py` is a maintainer copy helper, not a runtime dependency. It requires an explicitly supplied installed Archify source directory. Validate hashes and licensing when intentionally upgrading upstream.
