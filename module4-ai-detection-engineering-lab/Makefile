.PHONY: up down status logs reset shell pipeline audit

up:
	docker compose up --build -d

down:
	docker compose down

status:
	docker compose exec pipeline /workspace/bin/lab status

logs:
	docker compose logs -f --tail=100

reset:
	docker compose down -v

shell:
	docker compose exec pipeline /bin/bash

pipeline:
	docker compose exec pipeline /workspace/bin/lab pipeline --rule rules/validated/encoded_powershell.yml --fixtures tests/fixtures/encoded_powershell

audit:
	docker compose exec pipeline /workspace/bin/lab audit --root .

