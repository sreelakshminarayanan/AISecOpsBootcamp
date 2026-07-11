# Lab Guide: LLM Assisted Detection Engineering

## Purpose

This guide walks through an end to end detection engineering workflow. It is written for learners who are new to Sigma, Elasticsearch, Kibana, Ollama, or Detection as Code.

You will use an LLM at two points:

1. To turn detection research into a structured, testable hypothesis.
2. To propose detection code from an approved design.

You will use deterministic tooling for quality checks, query conversion, regression tests, deployment gates, and alert verification.

## What you will produce

By the end of the lab, you will have:

- A reviewed research brief
- A schema grounded detection design
- A portable Sigma rule
- A deterministic quality report
- A converted Elasticsearch query
- Positive and negative test results
- Full dataset evaluation metrics
- A deployed Kibana detection rule
- A verified Elastic Security alert
- A rollback record

## Part 1: Install the prerequisites

### Linux

Install Docker Engine and the Docker Compose plugin for your distribution. Confirm both commands work:

```bash
docker --version
docker compose version
```

If Docker reports permission denied, use `sudo` for the lab commands:

```bash
sudo docker compose up --build -d
```

To configure Docker access for your user, run:

```bash
sudo usermod -aG docker "$USER"
```

Sign out and sign in again before testing `docker ps`.

### Windows

Install Docker Desktop and enable the WSL 2 based engine. Start Docker Desktop and wait until it reports that the engine is running.

Open PowerShell and confirm:

```powershell
docker --version
docker compose version
```

Use Linux containers. The lab does not require Windows containers.

### Hardware guidance

- 8 GB of memory available to Docker is the minimum.
- 12 GB of memory available to Docker is preferable.
- Keep about 12 GB of free disk space for images, Elastic data, and the LLM model.
- Internet access is required during the first startup.

## Part 2: Prepare the project

Extract the project ZIP and open a terminal in the extracted `ai-detection-engineering-lab` folder.

### Linux

```bash
cp .env.example .env
docker compose up --build -d
```

### Windows PowerShell

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

The command starts the complete range. You do not need to start each component separately.

## Part 3: Check startup

Run:

```bash
docker compose ps
```

Expected behavior:

- `elasticsearch` becomes healthy.
- `kibana` becomes healthy.
- `telemetry-init` exits with code 0 after indexing the dataset. This is normal.
- `elastic-setup` exits with code 0 after configuring the Kibana account. This is normal.
- `pipeline` remains running.
- `portal` becomes healthy.
- `ollama` remains running.
- `ollama-init` downloads the configured model, then exits with code 0.

Open the workbench even if the model is still downloading:

http://localhost:8501

Track model progress:

```bash
docker compose logs -f ollama-init
```

Press `Ctrl+C` when you are finished viewing logs. This does not stop the containers.

Check the other services if required:

```bash
docker compose logs --tail=100 portal
docker compose logs --tail=100 telemetry-init
docker compose logs --tail=100 kibana
docker compose logs --tail=100 elasticsearch
```

## Part 4: Understand the workbench

The left menu follows the operating lifecycle:

1. Range Overview
2. Detection Research
3. Detection Design
4. Sigma Workbench
5. Test and Tune
6. Telemetry Explorer
7. Deploy and Verify
8. Capstone

Generated files are saved in `workspace/`. Test evidence is saved in `reports/`. Deployment history is saved in `deployments/`.

## Lab 4.1: LLM assisted detection research

Goal: use the LLM to analyze research evidence without allowing it to invent sources.

1. Open `Detection Research` in the workbench.
2. Select the encoded PowerShell scenario.
3. Open each starter result on detection.fyi.
4. Open the original repository for each rule.
5. Review the rule logic, fields, conditions, filters, status, references, ATT&CK tags, false positives, and test metadata.
6. Write your observations in `Source notes for LLM analysis`.
7. Add or replace sources if you find more relevant detections.
8. Select `Generate evidence grounded research brief`.
9. Review the JSON result. Check that every claim is supported by your notes.
10. Correct unsupported assumptions or missing limitations.
11. Select `Save reviewed research brief`.

Expected artifact:

```text
workspace/encoded_powershell_research.json
```

Key concept: retrieval and research evidence can guide the model, but the content is still untrusted input. The prompt tells the model to separate facts, claims, assumptions, and unknowns.

## Lab 4.2: Schema grounded detection design

Goal: convert reviewed research into a design that only uses available telemetry.

1. Open `Detection Design`.
2. Select the encoded PowerShell scenario.
3. Review the scenario evidence on the left.
4. Review the allowed ECS fields on the right.
5. Confirm that the reviewed research artifact is detected.
6. Select `Generate structured design with Ollama`.
7. Review required fields, suspicious values, selection logic, exclusions, ATT&CK mappings, assumptions, known gaps, and test hypotheses.
8. Remove any field that is not present in the schema panel.
9. Correct any ATT&CK mapping that lacks evidence.
10. Select `Save design`.
11. Select `Validate design schema`.

Expected artifact:

```text
workspace/encoded_powershell_design.json
```

Key concept: a detection design is not a rule. It is a reviewed contract that explains the behavior, evidence, logic, tests, and limits before code is generated.

## Lab 4.3: LLM assisted Detection as Code

Goal: use the approved design to propose portable Sigma.

1. Open `Sigma Workbench`.
2. Select the encoded PowerShell design.
3. Select `Draft Sigma with Ollama`.
4. Review the YAML line by line.
5. Confirm the rule uses generic Sigma fields such as `Image`, `CommandLine`, and `ParentImage`.
6. Confirm the rule does not use ECS fields directly.
7. Confirm all values and exclusions come from the approved design.
8. Select `Save Sigma draft`.

Expected artifact:

```text
workspace/encoded_powershell.yml
```

Key concept: the LLM proposes a code change. It does not certify the rule.

## Lab 4.4: Deterministic quality gates

Goal: prove that a plausible looking rule can still fail engineering controls.

1. In `Sigma Workbench`, select `Run deterministic gates`.
2. Expand every gate and inspect its result.
3. Repair failed metadata, field names, conditions, wildcards, or ATT&CK mappings.
4. Run the gates again until all checks pass.
5. Select `Convert with pySigma`.
6. Review the generated Lucene query.
7. Confirm portable Sigma fields were mapped to ECS fields.

Evidence files:

```text
reports/gui_quality_report.json
reports/gui_converted_query.txt
```

The gates cover YAML parsing, required metadata, UUID format, supported log source, portable fields, ATT&CK mappings, condition references, wildcard safety, Sigma specification validation, and fixture availability.

## Lab 4.5: Execute regression tests in Elasticsearch

Goal: test detection behavior against known positive and negative events.

1. Open `Test and Tune`.
2. Select your Sigma rule.
3. Select `Run regression fixtures`.
4. Review true positives, false positives, false negatives, true negatives, precision, and recall.
5. Inspect the matched event IDs and converted query.
6. Select `Evaluate complete dataset`.
7. Compare the fixture result with the broader dataset result.

Pass criteria for the supplied regression pack:

```text
False positives: 0
False negatives: 0
Precision: 1.0
Recall: 1.0
```

Evidence files:

```text
reports/gui_fixture_report.json
reports/gui_dataset_report.json
```

Key concept: fixture success proves behavior against represented test cases. It does not prove universal production readiness.

## Lab 4.6: Tune from evidence

Goal: repair a false positive without hiding malicious behavior.

1. Return to `Sigma Workbench`.
2. Remove the narrow approved management tool filter from a copy of the rule.
3. Save the copy with a distinct filename.
4. Open `Test and Tune` and run regression fixtures for the changed rule.
5. Identify the negative event that now matches.
6. Open `Telemetry Explorer` and inspect its command line, parent process, user, host, and scenario.
7. Add the narrowest exclusion supported by that evidence.
8. Run the regression fixtures again.
9. Confirm the false positive is gone and both positive cases still match.
10. Run the complete dataset evaluation again.

Key concept: tuning is a controlled code change with regression evidence. Broad trust based exclusions are not acceptable.

## Lab 4.7: Deploy, alert, and roll back

Goal: move a tested rule into operations and prove it produces an alert.

1. Open `Deploy and Verify`.
2. Select the validated rule.
3. Select a positive replay event.
4. Select `Deploy through Kibana API`.
5. Confirm the interface reports the deployment action and revision.
6. Select `Replay fresh malicious event`.
7. Keep the displayed rule ID.
8. Select `Wait for real alert`.
9. Wait for the Kibana rule schedule.
10. Confirm an alert record appears in the recent alerts table.
11. Open Kibana at http://localhost:5601.
12. Sign in with the credentials from the README.
13. Navigate to `Security`, then `Rules`, then `Detection rules`.
14. Inspect the query, index pattern, schedule, severity, tags, execution status, and alert.
15. Make a controlled description or logic change, retest it, and deploy a new revision.
16. Select `Roll back previous revision`.
17. Confirm the earlier revision and query were restored.

Key concept: deployment is blocked unless static checks, fixture tests, and full dataset evaluation pass.

## Lab 4.8: Capstone

Goal: repeat the workflow for a different behavior without copying the PowerShell answer.

1. Open `Capstone` and review the WMIC security tool tampering scenario.
2. Research at least three relevant detections.
3. Add your source notes in `Detection Research`.
4. Generate and review a research brief.
5. Generate and review a schema grounded design.
6. Create at least two positive fixtures.
7. Create at least four negative fixtures.
8. Store them under `tests/fixtures/wmic_security_tool_tampering/positive/` and `negative/`.
9. Generate and review the Sigma proposal.
10. Run all deterministic gates.
11. Convert the rule with pySigma.
12. Run regression tests and tune from evidence.
13. Evaluate the complete dataset after adding representative WMIC events.
14. Deploy the tested rule.
15. Replay a fresh positive event.
16. Verify the alert in the workbench and Kibana.
17. Deploy a controlled revision and prove rollback.

## Optional command line equivalents

The workbench is the main learner interface. The commands below are useful for automation and CI practice.

Check service state:

```bash
docker compose exec pipeline /workspace/bin/lab status
```

Generate a research brief from an analyst notes file:

```bash
docker compose exec pipeline /workspace/bin/lab research \
  --scenario scenarios/encoded_powershell.yml \
  --notes workspace/research_notes.txt \
  --output workspace/encoded_powershell_research.json
```

Generate a detection design:

```bash
docker compose exec pipeline /workspace/bin/lab design \
  --scenario scenarios/encoded_powershell.yml \
  --research workspace/encoded_powershell_research.json \
  --output workspace/encoded_powershell_design.json
```

Draft Sigma:

```bash
docker compose exec pipeline /workspace/bin/lab draft \
  --design workspace/encoded_powershell_design.json \
  --output workspace/encoded_powershell.yml
```

Run quality gates:

```bash
docker compose exec pipeline /workspace/bin/lab validate \
  --rule workspace/encoded_powershell.yml \
  --fixtures tests/fixtures/encoded_powershell
```

Convert with pySigma:

```bash
docker compose exec pipeline /workspace/bin/lab convert \
  --rule workspace/encoded_powershell.yml
```

Run fixture tests:

```bash
docker compose exec pipeline /workspace/bin/lab test \
  --rule workspace/encoded_powershell.yml \
  --fixtures tests/fixtures/encoded_powershell
```

Evaluate the full dataset:

```bash
docker compose exec pipeline /workspace/bin/lab evaluate \
  --rule workspace/encoded_powershell.yml \
  --index lab-security-events-v1
```

Run the supplied end to end acceptance path:

```bash
docker compose exec pipeline /workspace/bin/lab acceptance
```

Windows PowerShell uses the same Docker commands. For multiline commands, replace the Linux continuation character `\` with the PowerShell backtick, or enter each command on one line.

## Final live acceptance check

Run this after all services are ready. It exercises validation, conversion, temporary fixture indexes, full dataset evaluation, Kibana deployment, fresh event replay, alert verification tied to that replay, a second deployment revision, and rollback.

### Linux

```bash
curl -fsS http://localhost:8501/_stcore/health
docker compose exec pipeline /workspace/bin/lab status
docker compose exec pipeline /workspace/bin/lab acceptance --timeout 240
```

### Windows PowerShell

```powershell
Invoke-RestMethod http://localhost:8501/_stcore/health
docker compose exec pipeline /workspace/bin/lab status
docker compose exec pipeline /workspace/bin/lab acceptance --timeout 240
```

The final command should return JSON with `"passed": true`. The complete report is saved as:

```text
reports/acceptance_report.json
```

The alert check is restricted to the event ID and timestamp created during the acceptance run. An older alert for the same rule cannot satisfy the check.

## Troubleshooting

### Portal shows `No module named detection_lab`

This means the Streamlit process started without the project root on Python's import path. The corrected compose file sets `PYTHONPATH=/workspace`, `LAB_ROOT=/workspace`, and `working_dir: /workspace` for every Python service.

From the lab directory, rebuild the Python services and recreate the containers.

#### Linux

```bash
sudo docker compose down --remove-orphans
sudo docker compose build --no-cache telemetry-init pipeline portal
sudo docker compose up -d
sudo docker compose logs --tail=100 portal
```

#### Windows PowerShell

```powershell
docker compose down --remove-orphans
docker compose build --no-cache telemetry-init pipeline portal
docker compose up -d
docker compose logs --tail=100 portal
```

Confirm that the portal health endpoint responds.

```bash
curl -fsS http://localhost:8501/_stcore/health
```

On Windows PowerShell, use:

```powershell
Invoke-RestMethod http://localhost:8501/_stcore/health
```

### Port 11434 is already in use

The current lab does not publish Ollama on host port `11434`. If this error appears, confirm you are using the current `docker-compose.yml`, then recreate the project:

```bash
docker compose down
docker compose up --build -d
```

### Pipeline service is not running

Check the initializer logs:

```bash
docker compose ps -a
docker compose logs --tail=150 telemetry-init
docker compose logs --tail=150 elastic-setup
```

The pipeline starts after telemetry initialization succeeds. Fix the first reported initializer error, then run:

```bash
docker compose up -d
```

### Ollama model remains in initialization

Check model download progress:

```bash
docker compose logs -f ollama-init
```

Restart only the initialization job if required:

```bash
docker compose restart ollama
docker compose up -d ollama-init
```

The workbench and non LLM pipeline functions remain available while the model downloads.

### Workbench does not open

Check the portal:

```bash
docker compose ps portal
docker compose logs --tail=150 portal
```

If port `8501` is already in use, edit `.env`:

```text
PORTAL_PORT=8502
```

Recreate the portal and open http://localhost:8502:

```bash
docker compose up -d --force-recreate portal
```

### Docker permission denied on Linux

Use `sudo docker compose` immediately, or add your account to the Docker group as shown in Part 1. Do not mix commands run as different users inside the same project unless required.

### Start again with clean data

```bash
docker compose down -v
docker compose up --build -d
```

This removes the Elastic data volume and the downloaded model, so the next startup will take longer.
