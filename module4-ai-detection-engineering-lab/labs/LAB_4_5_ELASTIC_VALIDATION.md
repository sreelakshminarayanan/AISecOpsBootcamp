# Lab 4.5: Elasticsearch Validation

## Goal

Execute the converted rule against known positive and negative events, then evaluate the complete dataset.

## Workbench steps

1. Open `Test and Tune`.
2. Select the Sigma rule.
3. Run regression fixtures.
4. Review true positives, false positives, false negatives, true negatives, precision, and recall.
5. Inspect the matched event IDs.
6. Evaluate the complete dataset.
7. Compare the focused fixture result with the broader dataset result.

## Exit criteria

- Every positive fixture matches.
- Every negative fixture stays quiet.
- Precision and recall equal `1.0` for the supplied fixture pack.
- The complete dataset was evaluated.
- Test reports are saved under `reports/`.

