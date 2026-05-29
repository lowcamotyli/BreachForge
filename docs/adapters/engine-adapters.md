# Engine Adapters

This guide defines how external scanner outputs are normalized for BreachForge benchmark imports.

## 1) Native BreachForge (reference)

Raw output format:
- Native benchmark JSON object produced by `scripts/benchmark_lab.py` and consumed by `breachforge-bench import-results`.

Import command:
```bash
breachforge-bench import-results --file native-results.json --engine-name breachforge-native
```

Normalization mapping:
| Tool field | BreachForge field |
| --- | --- |
| `tp` | `tp` |
| `fp` | `fp` |
| `fn` | `fn` |
| `coverage` | `coverage` |

Required fields:
- `tp`, `fp`, `fn`, `coverage`

Optional fields:
- Engine-specific metadata keys

Limitations:
- Assumes output is already benchmark-shaped; no finding-level normalization pass.

## 2) HexStrike

Raw output format:
- JSON object: `{ "findings": [{ "id", "title", "severity", "endpoint", "evidence" }] }`

Import command:
```bash
breachforge-bench import-results --file hexstrike-results.json --engine-name hexstrike
```

Normalization mapping:
| Tool field | BreachForge field |
| --- | --- |
| `id` | `id` |
| `title` | `attack_class` (best-effort class mapping, fallback `UNKNOWN`) |
| `endpoint` | `endpoint` |
| `severity` | `severity` (`critical/high -> HIGH`, `medium -> MEDIUM`, `low -> LOW`) |
| n/a | `confidence` (`0.7` fixed) |
| n/a | `engine` (`hexstrike`) |
| full finding | `raw` |

Required fields:
- `id`, `title`, `severity`, `endpoint`

Optional fields:
- `evidence` (preserved under `raw`)

Limitations:
- No native confidence score in HexStrike; fixed confidence is heuristic.
- `title`-to-attack-class mapping can require manual cleanup for custom rule names.

## 3) OWASP ZAP (SARIF-based recipe)

Raw output format:
- SARIF 2.1.0 JSON (`.sarif`) exported from ZAP integrations.
- Existing importer reference: `scripts/benchmark_importers/sarif.py`.

Import command:
```bash
breachforge-bench import-results --file zap-report.sarif --engine-name zap
```

Normalization mapping:
| Tool field | BreachForge field |
| --- | --- |
| `results[].ruleId` | `id` / finding type seed |
| `results[].locations[0].physicalLocation.artifactLocation.uri` | `endpoint` |
| `results[].level` | confidence heuristic |
| rule tags + ruleId | `attack_class` (best effort via alias mapping) |
| full result | `raw` |

Required fields:
- `runs[].results[]`

Optional fields:
- `runs[].tool.driver.rules[].properties.tags`
- `results[].locations`

Limitations:
- Missing or non-standard `ruleId`/tags can produce `unknown` category.
- Confidence is inferred from SARIF level, not scanner certainty.

## 4) Nuclei (JSONL)

Raw output format:
- JSONL (`.jsonl`), one finding per line:
  `{"template-id","severity","host","matched-at","info":{"name"}}`

Import command:
```bash
breachforge-bench import-results --file nuclei-findings.jsonl --engine-name nuclei
```

Normalization mapping:
| Tool field | BreachForge field |
| --- | --- |
| `template-id` | `id` |
| `info.name` | `attack_class` (uppercased, `-` to `_`) |
| `matched-at` | `endpoint` |
| `severity` | `severity` (uppercased) |
| n/a | `confidence` (`0.6` fixed) |
| n/a | `engine` (`nuclei`) |
| full finding | `raw` |

Required fields:
- `template-id`, `info.name`, `matched-at`

Optional fields:
- `severity`, `host`

Limitations:
- Template IDs are not directly semantic classes; class quality depends on naming conventions.
- JSONL parsing skips empty lines; malformed lines should be filtered before import.

## 5) Generic SARIF

Raw output format:
- Any SARIF 2.1.0-compliant JSON.

Import command:
```bash
breachforge-bench import-results --file tool-output.sarif --engine-name <tool-name>
```

Normalization mapping:
| Tool field | BreachForge field |
| --- | --- |
| `results[].ruleId` | `id` |
| `results[].message` / rule metadata | `attack_class` seed |
| `results[].locations[..].artifactLocation.uri` | `endpoint` |
| `results[].level` | confidence heuristic |
| full result | `raw` |

Required fields:
- `version` (`2.1.0` recommended), `runs`, `runs[].results`

Optional fields:
- `runs[].tool.driver.rules`
- `runs[].results[].locations`

Limitations:
- Vendor SARIF dialects vary; some omit location or taxonomy tags.
- Category mapping is best-effort and may require manual review for unknown rules.
