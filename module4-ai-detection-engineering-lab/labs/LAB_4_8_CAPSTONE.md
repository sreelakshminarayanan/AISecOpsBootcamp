# Lab 4.8: Detection Engineering Capstone

## Goal

Apply the complete lifecycle to WMIC security tool tampering without copying the PowerShell rule.

## Required work

1. Research at least three relevant detections.
2. Generate and review an evidence grounded research brief.
3. Generate and review a schema grounded design.
4. Create at least two positive ECS fixtures.
5. Create at least four negative ECS fixtures.
6. Generate and review a portable Sigma proposal.
7. Pass every deterministic quality gate.
8. Convert the rule with pySigma.
9. Execute fixtures in Elasticsearch and tune from evidence.
10. Add representative WMIC events and evaluate the complete dataset.
11. Deploy through the Kibana API.
12. Replay a fresh positive event and verify the alert.
13. Deploy a controlled revision and prove rollback.

## Acceptance criteria

- No unsupported fields or ATT&CK mappings
- Zero false negatives in the fixture pack
- Zero false positives in the fixture pack
- Successful conversion and Elasticsearch execution
- Successful Kibana deployment and alert verification
- Successful rollback
- Documented gaps and remaining false positive risk

The capstone is complete when another learner can reproduce the evidence chain from the repository.
