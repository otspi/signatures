#!/usr/bin/env bash
# Test de bout en bout en local : inscription, confirmation, liste publique, retrait, anti-abus.
# Prérequis : Docker. Usage : bash tests/flow.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; mkdir -p "$WORK/data"
cat > "$WORK/config.php" <<'PHP'
<?php
return ['base_url'=>'http://localhost:8090','db_path'=>'/work/data/s.sqlite','secret'=>'test-secret','mail_from'=>'no-reply@example.org','mail_from_name'=>'OTSPI','contact'=>'contact@otspi.org','mail_dry_run'=>true,'mail_log'=>'/work/data/mail.log'];
PHP
CID=$(docker run -d --rm -p 8090:8090 -v "$ROOT":/app -v "$WORK":/work -e SIGN_CONFIG=/work/config.php -w /app/public php:8.3-cli php -S 0.0.0.0:8090)
trap 'docker stop "$CID" >/dev/null; rm -rf "$WORK"' EXIT
sleep 3
U=http://localhost:8090
ok() { echo "OK  $1"; }; ko() { echo "ÉCHEC $1"; exit 1; }
ft() { curl -s "$U/" | grep -o 'name="ft" value="[^"]*"' | sed 's/.*value="//;s/"$//'; }

FT=$(ft); sleep 5
R=$(curl -s -o /dev/null -w '%{http_code}' -d "ft=$FT&prenom=Ada&nom=Lovelace&email=ada@example.org&fonction=Ingénieure&organisation=Labo&publier=1&website=" "$U/")
[ "$R" = 200 ] && grep -q 'ada@example.org' "$WORK/data/mail.log" && ok "inscription et e-mail de confirmation" || ko "inscription"
TOKEN=$(grep -o 'confirm.php?t=[0-9a-f]*' "$WORK/data/mail.log" | head -1 | sed 's/.*t=//')
[ "$(curl -s "$U/signataires.php" | grep -c Lovelace)" = 0 ] && ok "non publiée avant confirmation" || ko "publiée trop tôt"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$U/confirm.php?t=$TOKEN")" = 200 ] && ok "confirmation" || ko "confirmation"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$U/confirm.php?t=$TOKEN")" = 400 ] && ok "lien de confirmation à usage unique" || ko "réutilisation du lien"
curl -s "$U/signataires.php" | grep -q Lovelace && ok "publiée après confirmation" || ko "absente de la liste"
curl -s "$U/signataires.php" | grep -q 'ada@example.org' && ko "e-mail publié !" || ok "adresse e-mail jamais publiée"
W=$(grep -o 'withdraw.php?t=[0-9a-f]*' "$WORK/data/mail.log" | tail -1 | sed 's/.*t=//')
curl -s -o /dev/null -d "t=$W" "$U/withdraw.php"
curl -s "$U/signataires.php" | grep -q Lovelace && ko "retrait sans effet" || ok "retrait et suppression"
R=$(curl -s -o /dev/null -w '%{http_code}' -d "ft=$(ft)&prenom=Bot&nom=Bot&email=bot@example.org&website=x" "$U/")
grep -q 'bot@example.org' "$WORK/data/mail.log" && ko "piège à robots" || ok "piège à robots"
FT=$(ft); curl -s -d "ft=$FT&prenom=Vite&nom=Vite&email=vite@example.org" "$U/" | grep -q 'role="alert"' && ok "formulaire envoyé trop vite refusé" || ko "trop vite"
curl -s -d "ft=faux&prenom=A&nom=B&email=a@example.org" "$U/" | grep -q 'role="alert"' && ok "jeton falsifié refusé" || ko "jeton"
echo "Tous les tests passent."
