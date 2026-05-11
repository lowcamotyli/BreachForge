from __future__ import annotations


class GraphqlCorpus:
    def introspection_enabled_response(self) -> dict[str, object]:
        return {
            "status": 200,
            "json": {
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "Query", "fields": [{"name": "viewer", "args": []}]},
                        ]
                    }
                }
            },
        }

    def batch_without_rate_limit_response(self, batch_size: int = 20) -> dict[str, object]:
        return {
            "status": 200,
            "responses": [{"status": 200, "body": {"data": {"__typename": "Query"}}} for _ in range(batch_size)],
        }
