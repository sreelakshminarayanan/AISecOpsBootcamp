# AI Assisted Detection Engineering Lab

This lab demonstrates how an LLM can support a real Detection as Code lifecycle without becoming the final decision maker.

The primary learner experience is a browser based Detection Engineering Workbench. Elasticsearch, Kibana, Sigma, pySigma, Ollama, realistic ECS telemetry, regression tests, deployment, alert verification, and rollback run behind the interface.

## Start here

1. Install Docker Engine with Docker Compose on Linux, or Docker Desktop on Windows.
2. Copy `.env.example` to `.env`.
3. Run:

```bash
docker compose up --build -d
```

4. Open http://localhost:8501.

The Python containers explicitly use `/workspace` as both the working directory and import root. This keeps the Streamlit portal, CLI, bootstrap process, and tests on the same module path.
5. Follow [LAB_GUIDE.md](LAB_GUIDE.md).

Kibana is available at http://localhost:5601.

```text
Username: elastic
Password: DetectionLab2026
```

The first model download can take several minutes. It does not block Elasticsearch, Kibana, the dataset, or the workbench. Track it with:

```bash
docker compose logs -f ollama-init
```

The workbench shows when the configured model is ready. Only LLM research, design, and drafting actions wait for it.

## Learning outcome

Learners implement two controlled uses of an LLM:

1. Research layer
   The learner selects public detection sources, checks original repositories, records evidence, and asks the LLM to compare stable behavior, brittle indicators, telemetry needs, false positives, and test hypotheses.

2. Detection as Code layer
   The reviewed research brief, scenario, and allowed schema ground an LLM generated design. After human review, the LLM proposes portable Sigma. Deterministic tools then validate, convert, execute, deploy, and verify the rule.

The LLM never approves its own output. Validation and deployment decisions come from code and observable evidence.

## Operational flow

```text
Public detection research
-> analyst source notes
-> LLM research brief
-> human review
-> schema grounded detection design
-> human review
-> LLM Sigma proposal
-> deterministic quality gates
-> pySigma conversion
-> positive and negative regression tests
-> full Elasticsearch dataset evaluation
-> Kibana rule deployment
-> fresh event replay
-> real alert verification
-> rollback
```

## Services

| Service | Purpose | Address |
|---|---|---|
| Workbench | Guided lab workflow | http://localhost:8501 |
| Elasticsearch | ECS telemetry and alert storage | http://localhost:9200 |
| Kibana | Rule operations and alert investigation | http://localhost:5601 |
| Ollama | Local LLM inference | Internal Docker network only |
| Telemetry initializer | Dataset generation and indexing | Internal service |
| Detection pipeline | Validation, testing, deployment, and rollback | Internal service |

Ollama is intentionally not published on host port `11434`. This avoids conflicts with an existing local Ollama installation.

## What is real

- LLM responses come from the configured local Ollama model.
- Research evidence and generated artifacts can change between runs.
- Sigma validation uses deterministic local checks and `sigma check`.
- Sigma conversion uses pySigma with the Elasticsearch ECS pipeline.
- Fixture tests create temporary indexes and execute the converted query in Elasticsearch.
- Full evaluation executes the same query against the complete simulated dataset.
- Deployment uses the Kibana Detection Engine API.
- Alert verification reads the Elastic Security alert index.
- Rollback restores a previously recorded Kibana rule payload.

The telemetry generator is deterministic enough to support repeatable regression tests. The LLM work is not hardcoded. The distinction is intentional. Reliable tests need known ground truth, while research and rule proposals should remain variable and reviewable.

## Dataset

The range generates more than 230 ECS aligned Windows and Sysmon events. It includes routine administration, Configuration Manager, certificate operations, inventory activity, scheduled tasks, process execution, network connections, file creation, registry modification, and a correlated malicious chain.

All network indicators use RFC reserved documentation ranges and inert test domains.

## Repository map

```text
portal/          Browser workbench
detection_lab/   Pipeline implementation
labs/            Individual lab references
scenarios/       Editable detection scenarios
references/      Starter detection research links
schemas/         Allowed ECS and Sigma fields
rules/           Broken and validated examples
tests/fixtures/  Positive and negative event evidence
datasets/        Generated and optional imported telemetry
workspace/       Learner research, designs, and drafts
reports/         Validation and test evidence
deployments/     Deployment history for rollback
```

## Security boundary

This range is designed for an isolated local training machine. Local ports bind to `127.0.0.1`. Change the default passwords before adapting the project for a shared environment.

## Stop or reset

Stop containers and retain data:

```bash
docker compose down
```

Remove containers and persistent volumes:

```bash
docker compose down -v
```

The second command deletes indexed data and downloaded Ollama models.

