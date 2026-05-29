# Benchmark Changelog

## Versioning Scheme

Benchmark results are pinned by three version identifiers:

- `corpus_version`: semantic version for the public benchmark corpus.
- `schema_version`: semantic version for the metrics and scorecard schema.
- `engine_config_version`: Git SHA prefix for the scanner engine configuration used for the run.

## Version Pinning

Pin benchmark runs by passing explicit versions to the `breachforge-bench` CLI:

```bash
breachforge-bench --corpus-version v1.0.0 --engine-config-version <git-sha-prefix>
```

The schema version is recorded in the benchmark output so scorecard renderers can reject or migrate incompatible data.

## Comparison Policy

Results from different `corpus_version` values are not directly comparable without migration notes. Corpus changes can add labs, remove labs, alter expected findings, or adjust unsupported class handling, so comparisons must use the same corpus version unless this changelog documents a migration path.

## v1.0.0 (2026-05-28)

Initial public release.

Labs:

- `api_saas`
- `graphql`
- `spa_har`
- `business_race`
- `auth_oauth`
