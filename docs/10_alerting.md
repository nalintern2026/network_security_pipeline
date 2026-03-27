# Alerting and Automation

## Alerting Surfaces

- n8n workflows under `nal/n8n` are the primary alert/report engine.
- Backend itself provides the monitored signals (health, stats, anomalies, realtime status).
- Webhook/Slack posts are used for outbound notifications in workflow definitions.

## Core Alert Conditions

From `1_network_security_monitoring.json`:

- API health is not `healthy`.
- Anomaly rate above configured threshold.
- Average risk score above configured threshold.
- Critical risk flow count above configured threshold.

From `5_live_monitoring_management.json`:

- Monitor expected to run but stopped (auto-restart path).
- Running monitor produces no active flows over time (health warning path).

From `4_daily_security_report.json`:

- Daily summary indicates critical issues; escalated urgent alert is sent.

## Workflow Logic by File

- `1_network_security_monitoring.json`: periodic health + threat evaluation every 5 minutes.
- `2_automated_file_analysis.json`: webhook/scheduled file-analysis orchestration and threat reporting.
- `3_training_pipeline.json`: weekly/manual model-status reporting.
- `4_daily_security_report.json`: daily consolidated reporting and critical escalation.
- `5_live_monitoring_management.json`: monitor control webhook + periodic monitor health checks.

## Integrations

- Outbound HTTP webhook nodes are preconfigured with Slack webhook placeholders.
- Workflows can be adapted for Teams/email/PagerDuty by replacing final send nodes.

## Failure Handling

- Health-check failures explicitly trigger API-down alerts.
- Workflow condition branches include no-op paths to avoid noisy output when thresholds are not crossed.
- Realtime monitor workflow supports auto-restart behavior when configured.

## Operational Notes

- JSON workflow files currently contain hardcoded `http://backend:8000` and placeholder Slack URLs; production requires environment-backed configuration updates.
- Ensure n8n credentials/webhooks are set before activation.
