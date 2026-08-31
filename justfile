set shell := ["bash", "-c"]

default:
  @just --list

decrypt env:
  #!/usr/bin/env bash
  set -euo pipefail

  if [[ ! -f secrets/{{ env }}.enc.env ]]; then
    echo "Encrypted secrets/{{ env }}.enc.env file not found."
    exit 1
  fi

  sops --decrypt --input-type env --output-type env secrets/{{ env }}.enc.env > .env.{{ env }}

compose env *args: (decrypt env)
  #!/usr/bin/env bash
  set -euo pipefail
  docker network create unsareport-dev 2>/dev/null || true
  docker compose -f docker-compose.{{ env }}.yml --env-file .env.{{ env }} {{ args }}
