# Lab 4.7: Deployment, Alert, and Rollback

## Goal

Promote a tested rule into Kibana, verify a real alert, and restore a previous revision.

## Workbench steps

1. Open `Deploy and Verify`.
2. Select the validated rule and a positive replay event.
3. Deploy through the Kibana API.
4. Replay the event with a fresh timestamp.
5. Wait for the scheduled detection and verify the alert.
6. Open Kibana and inspect the rule, execution status, query, and alert.
7. Make a controlled change, retest it, and deploy another revision.
8. Roll back and confirm the earlier revision is restored.

## Exit criteria

- Deployment gates passed.
- Kibana executed the rule.
- An Elastic Security alert was verified.
- A changed revision was deployed.
- The earlier revision was restored from deployment history.

