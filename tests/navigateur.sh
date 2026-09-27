#!/usr/bin/env bash
# Tests dans un vrai navigateur (Chromium piloté par Playwright) des parties JavaScript : preuve de travail du
# formulaire, partage après confirmation, clé de sécurité de l'administration (authentificateur virtuel de
# Chrome), sélection par lot. Le conteneur Playwright partage le réseau du conteneur PHP : le site est servi sur
# http://localhost, contexte sécurisé exigé par WebAuthn. Prérequis : Docker. Usage : bash tests/navigateur.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; mkdir -p "$WORK/data"; chmod 777 "$WORK/data"
PLAYWRIGHT_IMAGE="mcr.microsoft.com/playwright/python:v1.58.0-noble"
cat > "$WORK/config.php" <<'PHP'
<?php
return ['base_url'=>'http://localhost:8095','db_path'=>'/work/data/s.sqlite','secret'=>'test-secret','mail_from'=>'no-reply@example.org','mail_from_name'=>'OTSPI','contact'=>'contact@otspi.org','mail_dry_run'=>true,'mail_log'=>'/work/data/mail.log','pow_bits'=>12,'tsa_url'=>''];
PHP
CID=$(docker run -d --rm -v "$ROOT":/app -v "$WORK":/work -e SIGN_CONFIG=/work/config.php -w /app/public php:8.3-cli php -S 0.0.0.0:8095)
trap 'docker stop "$CID" >/dev/null; docker run --rm -v "$WORK":/w php:8.3-cli rm -rf /w/data; rm -rf "$WORK"' EXIT
sleep 2
docker exec "$CID" php /app/bin/admin.php invitation >/dev/null
docker run --rm --network "container:$CID" --ipc=host -v "$ROOT/tests":/tests:ro -v "$WORK":/work "$PLAYWRIGHT_IMAGE" sh -c "pip install -q --disable-pip-version-check --break-system-packages playwright==1.58.0 2>/dev/null || pip install -q --disable-pip-version-check playwright==1.58.0; python3 /tests/navigateur.py"
