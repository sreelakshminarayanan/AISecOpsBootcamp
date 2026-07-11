FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/workspace \
    LAB_ROOT=/workspace \
    HOME=/var/lib/detection-lab

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /workspace
RUN PYTHONPATH=/workspace python -c "from detection_lab.config import settings; from portal.theme import apply_theme; from scripts.generate_telemetry import generate"
RUN mkdir -p "$HOME" \
    && chmod +x /workspace/bin/lab \
    && sigma check /workspace/rules/validated/encoded_powershell.yml \
    && sigma convert -t lucene -p ecs_windows /workspace/rules/validated/encoded_powershell.yml > /tmp/validated-query.txt

ENTRYPOINT ["/workspace/bin/lab"]
CMD ["help"]
