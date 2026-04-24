## Sprint 3 — Crawler + AssetMap

**Goal:** CrawlerReconEngine mapuje powierzchnię ataku przez Playwright (XHR interception + link extraction), produkuje AssetMap.

### Architektura — dokumenty referencyjne

```bash
DAD_PROMPT="Read /mnt/d/SimpliAppSec/docs/architecture/attack-engine.md. Extract: recon section, CrawlerReconEngine responsibilities, AssetMap structure, what engine must NOT do (P6). Bullets. Max 20 lines." bash ~/.claude/scripts/dad-exec.sh
```

### Graf zależności

```
execution_plane/crawler/asset_map.py ───┐ parallel
execution_plane/crawler/engine.py ──────┘ (engine imports asset_map)
tests/unit/execution_plane/crawler/test_asset_map.py ── po obu
```

### Dispatch table

| Plik | Worker | Skill | Uwagi |
|------|--------|-------|-------|
| `execution_plane/crawler/asset_map.py` | codex-dad | `skill:scoped-implementation` | AssetMap builder |
| `execution_plane/crawler/engine.py` | codex-main | `skill:scoped-implementation` | Playwright — złożone |
| `tests/...test_asset_map.py` | codex-main | `skill:test-impact-check` | po obu plikach |

### Prompty

```bash
# codex-dad — AssetMap builder (parallel)
DAD_PROMPT='Read /mnt/d/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read /mnt/d/SimpliAppSec/storage/db/models.py for AssetMap and Endpoint entities.
Goal: Create /mnt/d/SimpliAppSec/execution_plane/crawler/asset_map.py
- AssetMapBuilder class with: add_endpoint(url, method, auth_required, parameters), normalize_url_pattern (replace /123/ with /{id}/), build() -> AssetMap
- Endpoint dataclass mirrors DB model (url_pattern, method, auth_required, parameters list, observed_content_type, example_response_code)
- Parameter dataclass: name, location (query|body|path|header), type
from __future__ import annotations. Done when: file exists with all classes.' bash ~/.claude/scripts/dad-exec.sh

# codex-main — CrawlerReconEngine (parallel)
codex exec --dangerously-bypass-approvals-and-sandbox \
'Read d:/SimpliAppSec/.workflow/skills/scoped-implementation.md and follow its procedure.
Read d:/SimpliAppSec/control_plane/auth_manager.py for SessionSnapshot.
Read d:/SimpliAppSec/execution_plane/crawler/asset_map.py for AssetMapBuilder.
Do NOT use Gemini — write directly.
Goal: d:/SimpliAppSec/execution_plane/crawler/engine.py — CrawlerReconEngine
- Takes SessionSnapshot + target_url + scope_domains list + timeout_minutes (default 10)
- Launches Playwright chromium headless with session cookies applied
- Intercepts XHR/fetch via page.on("request") — captures URL, method, headers
- Extracts links from page — only within scope_domains
- Detects auth-required endpoints: request fails without auth headers = auth_required=True
- Extracts parameters: query params from URL, body params from POST requests
- Time-boxed: hard stop at timeout_minutes
- Returns AssetMap — does NOT fuzz, does NOT attack
- from __future__ import annotations
Constraints: never follow links outside scope_domains, never send attack payloads.
Done when: file exists, run() method returns AssetMap.'
```

### Weryfikacja

```bash
python -m pytest tests/unit/execution_plane/crawler/ -q
```

### Acceptance criteria

- [ ] `CrawlerReconEngine.run()` respects scope_domains — no out-of-scope requests
- [ ] Time-boxed at timeout_minutes
- [ ] XHR/fetch intercepted and added to AssetMap
- [ ] URL normalization: `/api/users/123` → `/api/users/{id}`
- [ ] `auth_required` correctly detected

### Post-sprint: przegląd skillów

Czy pojawił się nowy powtarzalny pattern? Jeśli tak — zaktualizuj lub dodaj skill w .workflow/skills/ przed zamknięciem sprintu. Reguła: pattern >= 2x → skodyfikuj.

