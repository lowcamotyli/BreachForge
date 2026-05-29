# Jenkins Webhook Trigger

Use the webhook endpoint to trigger a BreachForge scan after a Jenkins build:

- Endpoint: `POST /webhooks/trigger`
- Health check: `GET /webhooks/health`
- Header for signature: `X-BF-Signature` (optional)

## Jenkins Configuration

Add a post-build action (or pipeline stage) that sends JSON to:

`https://<breachforge-host>/webhooks/trigger`

Example payload:

```json
{
  "target_url": "https://app.example.com",
  "source": "jenkins",
  "gate_config": {
    "allowed_domains": ["app.example.com"],
    "max_requests": 500
  }
}
```

## curl with HMAC Signature

If `BREACHFORGE_WEBHOOK_SECRET` is configured on the BreachForge API, sign the raw JSON body using HMAC-SHA256:

```bash
BODY='{"target_url":"https://app.example.com","source":"jenkins"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$BREACHFORGE_WEBHOOK_SECRET" | awk '{print $2}')
curl -X POST "https://<breachforge-host>/webhooks/trigger" \
  -H "Content-Type: application/json" \
  -H "X-BF-Signature: $SIG" \
  -d "$BODY"
```

## Jenkinsfile Example (Groovy)

```groovy
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'make build'
      }
    }
  }
  post {
    success {
      script {
        def body = groovy.json.JsonOutput.toJson([
          target_url : 'https://app.example.com',
          source     : 'jenkins'
        ])
        def sig = sh(
          script: "printf '%s' '${body}' | openssl dgst -sha256 -hmac '${env.BREACHFORGE_WEBHOOK_SECRET}' | awk '{print \$2}'",
          returnStdout: true
        ).trim()
        sh """
          curl -sS -X POST "https://<breachforge-host>/webhooks/trigger" \
            -H "Content-Type: application/json" \
            -H "X-BF-Signature: ${sig}" \
            -d '${body}'
        """
      }
    }
  }
}
```

The webhook response includes `scan_id`; you can poll it from CLI:

`breachforge scan wait --scan-id <scan_id>`
