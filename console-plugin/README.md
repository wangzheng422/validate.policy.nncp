# Console plugin

OpenShift dynamic Console plugin with Overview, Primary Network Path, Policies, History and Preflight. UI text supports English, Simplified Chinese and Traditional Chinese.

```bash
npm ci --ignore-scripts
npm run typecheck
npm run build
python3 tests/browser_smoke.py
```

The browser smoke test uses local simulated API and Console SDK responses; it requires Selenium, Chromium and ChromeDriver. It never connects to a cluster. The backend API forwards the Console user's identity; the frontend does not contain service-account credentials.

The embedded topology is minimal; the full architecture link opens a separate interactive viewer. See [installation](../docs/helm.md) and [UI controls](../docs/ui-controls.md).

The 2026-09-17 npm audit reports three moderate findings in the Console SDK 1.2.0 / React Router compatibility development-dependency tree (no high or critical findings). The offered fix changes the Console SDK major version and is not applied without compatibility validation. SDK and React are shared from the host Console; the final nginx image contains compiled static assets, not node_modules. This does not constitute a vulnerability assessment of the host Console.
