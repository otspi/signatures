#!/usr/bin/env bash
# Test de bout en bout en local : migration, inscription, confirmation, modération, liste publique, retrait, anti-abus.
# Prérequis : Docker. Usage : bash tests/flow.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; mkdir -p "$WORK/data"
cat > "$WORK/config.php" <<'PHP'
<?php
return ['base_url'=>'http://localhost:8090','db_path'=>'/work/data/s.sqlite','secret'=>'test-secret','mail_from'=>'no-reply@example.org','mail_from_name'=>'OTSPI','contact'=>'contact@otspi.org','mail_dry_run'=>true,'mail_log'=>'/work/data/mail.log','mail_hourly_cap'=>2];
PHP
# Base à l'ancien schéma (sans modération) avec une signature confirmée, pour tester la migration
docker run --rm -v "$WORK":/work php:8.3-cli php -r '$p = new PDO("sqlite:/work/data/s.sqlite");
$p->exec("CREATE TABLE signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, prenom TEXT NOT NULL, nom TEXT NOT NULL, fonction TEXT NOT NULL DEFAULT \"\", organisation TEXT NOT NULL DEFAULT \"\", publier INTEGER NOT NULL DEFAULT 0, lang TEXT NOT NULL DEFAULT \"fr\", confirm_hash TEXT NOT NULL, withdraw_hash TEXT NOT NULL, created_at INTEGER NOT NULL, last_mail_at INTEGER NOT NULL, confirmed_at INTEGER)");
$p->exec("INSERT INTO signatures (email, prenom, nom, publier, confirm_hash, withdraw_hash, created_at, last_mail_at, confirmed_at) VALUES (\"old@example.org\", \"Grace\", \"Hopper\", 1, \"x\", \"y\", 1, 1, 1), (\"old+bis@example.org\", \"Grace\", \"Hopper\", 1, \"z\", \"w\", 1, 1, 1)");'
CID=$(docker run -d --rm -p 8090:8090 -v "$ROOT":/app -v "$WORK":/work -e SIGN_CONFIG=/work/config.php -w /app/public php:8.3-cli php -S 0.0.0.0:8090)
trap 'docker stop "$CID" >/dev/null; rm -rf "$WORK"' EXIT
sleep 3
U=http://localhost:8090
ok() { echo "OK  $1"; }; ko() { echo "ÉCHEC $1"; exit 1; }
curl -s "$U/signataires.php" | grep -q Hopper && ok "migration : signature existante reste publiée" || ko "migration"
ft() { curl -s "$U/" | grep -o 'name="ft" value="[^"]*"' | sed 's/.*value="//;s/"$//'; }

FT=$(ft); sleep 5
R=$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' -H 'Origin: null' -d "ft=$FT&prenom=Ada&nom=Lovelace&email=ada@example.org&fonction=Ingénieure&organisation=Labo&publier=1&website=" "$U/")
[ "$R" = 200 ] && grep -q 'ada@example.org' "$WORK/data/mail.log" && ok "inscription et e-mail de confirmation" || ko "inscription"
TOKEN=$(grep -o 'confirm.php?t=[0-9a-f]*' "$WORK/data/mail.log" | head -1 | sed 's/.*t=//')
[ "$(curl -s "$U/signataires.php" | grep -c Lovelace)" = 0 ] && ok "non publiée avant confirmation" || ko "publiée trop tôt"
grep -q '^Bonjour,$' "$WORK/data/mail.log" && grep -q 'Organisation : Labo' "$WORK/data/mail.log" && ok "e-mail sans nom en tête, avec récapitulatif" || ko "récapitulatif de l'e-mail"
curl -s "$U/confirm.php?t=$TOKEN" | grep -q 'method="post"' && ok "le lien affiche un bouton de confirmation" || ko "page de confirmation"
curl -s "$U/confirm.php?t=$TOKEN" | grep -q '<dd>Lovelace</dd>' && ok "récapitulatif sur la page de confirmation" || ko "récapitulatif de la page"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: cross-site' -d "t=$TOKEN" "$U/confirm.php")" = 200 ] && ok "confirmation depuis un autre site refusée" || ko "confirmation intersite"
[ "$(curl -s "$U/confirm.php?t=$TOKEN" | grep -c 'method="post"')" = 1 ] && ok "le lien seul (GET) ne confirme rien" || ko "confirmé par GET"
[ "$(curl -s -o /dev/null -w '%{http_code}' -d "t=$TOKEN" "$U/confirm.php")" = 200 ] && ok "confirmation (POST)" || ko "confirmation"
[ "$(curl -s -o /dev/null -w '%{http_code}' -d "t=$TOKEN" "$U/confirm.php")" = 400 ] && ok "lien de confirmation à usage unique" || ko "réutilisation du lien"
grep -q 'SUBJECT: Signature à modérer : Ada Lovelace' "$WORK/data/mail.log" && ok "notification de modération" || ko "notification de modération"
curl -s "$U/signataires.php" | grep -q Lovelace && ko "publiée avant modération" || ok "non publiée avant modération"
curl -s "$U/signataires.php" | grep -q '"total": 3' && ko "comptée avant modération" || ok "non comptée avant modération"
ID=$(docker exec "$CID" php /app/bin/moderation.php lister | grep -o '^#[0-9]*' | tr -d '#')
docker exec "$CID" php /app/bin/moderation.php valider "$ID" | grep -q fait && ok "validation par la modération" || ko "validation"
curl -s "$U/signataires.php" | grep -q Lovelace && ok "publiée après validation" || ko "absente de la liste"
curl -s "$U/signataires.php" | grep -q 'ada@example.org' && ko "e-mail publié !" || ok "adresse e-mail jamais publiée"
FT=$(ft); sleep 5
curl -s -o /dev/null -d "ft=$FT&prenom=Ada&nom=Lovelace&email=Ada%2Bbis@example.org" "$U/"
grep -q 'TO: ada+bis@example.org' "$WORK/data/mail.log" && ko "doublon par alias +tag" || ok "alias +tag d'une adresse déjà signée : aucun nouvel envoi"
FT=$(ft); sleep 5
curl -s -o /dev/null -d "ft=$FT&prenom=Alan&nom=Turing&email=alan%2Bmanifeste@example.org" "$U/"
grep -q 'TO: alan+manifeste@example.org' "$WORK/data/mail.log" && ok "adresse +tag acceptée, envoi à l'adresse complète" || ko "adresse +tag"
W=$(grep -o 'withdraw.php?t=[0-9a-f]*' "$WORK/data/mail.log" | tail -1 | sed 's/.*t=//')
curl -s -o /dev/null -d "t=$W" "$U/withdraw.php"
curl -s "$U/signataires.php" | grep -q Lovelace && ko "retrait sans effet" || ok "retrait et suppression"
R=$(curl -s -o /dev/null -w '%{http_code}' -d "ft=$(ft)&prenom=Bot&nom=Bot&email=bot@example.org&website=x" "$U/")
grep -q 'bot@example.org' "$WORK/data/mail.log" && ko "piège à robots" || ok "piège à robots"
FT=$(ft); curl -s -d "ft=$FT&prenom=Vite&nom=Vite&email=vite@example.org" "$U/" | grep -q 'role="alert"' && ok "formulaire envoyé trop vite refusé" || ko "trop vite"
curl -s -d "ft=faux&prenom=A&nom=B&email=a@example.org" "$U/" | grep -q 'role="alert"' && ok "jeton falsifié refusé" || ko "jeton"
FT=$(ft); sleep 5
curl -s -d "ft=$FT&nom=Faux&email=bidi@example.org" --data-urlencode "prenom=$(printf 'Ada\u202Eecalevol')" "$U/" | grep -q 'role="alert"' && ok "caractères bidirectionnels refusés" || ko "bidi accepté"
# Plafond global (2 par heure dans ce test) : on isole de la limite par IP en vidant ses empreintes.
docker exec "$CID" php -r 'require "/app/src/lib.php"; db()->exec("DELETE FROM hits");'
FT=$(ft); sleep 5
curl -s -o /dev/null -d "ft=$FT&prenom=Hedy&nom=Lamarr&email=hedy@example.org" "$U/"
grep -q 'TO: hedy@example.org' "$WORK/data/mail.log" && ok "envoi sous le plafond" || ko "envoi sous le plafond"
docker exec "$CID" php -r 'require "/app/src/lib.php"; echo mail_cap_reached() ? "plein" : "libre";' | grep -q plein && ok "plafond global d'envois atteint" || ko "plafond global"
FT=$(ft); sleep 5
curl -s -d "ft=$FT&prenom=Plafond&nom=Test&email=plafond@example.org" "$U/" | grep -q 'role="alert"' && ! grep -q 'plafond@example.org' "$WORK/data/mail.log" && ok "aucun envoi au-delà du plafond" || ko "envoi au-delà du plafond"
FT=$(ft); sleep 5
curl -s -H 'Sec-Fetch-Site: cross-site' -d "ft=$FT&prenom=A&nom=B&email=x@example.org" "$U/" | grep -q 'role="alert"' && ok "envoi depuis un autre site refusé (Sec-Fetch-Site)" || ko "intersite Sec-Fetch-Site"
curl -s -H 'Origin: https://evil.example' -d "ft=$FT&prenom=A&nom=B&email=x@example.org" "$U/" | grep -q 'role="alert"' && ok "envoi depuis un autre site refusé (Origin)" || ko "intersite Origin"
curl -s -d "ft=$FT&prenom=Ada&nom=Faux&email=lien@example.org" --data-urlencode "organisation=Voir https://evil.example" "$U/" | grep -q 'role="alert"' && ok "liens refusés dans les champs" || ko "lien accepté"
docker exec "$CID" php -r 'require "/app/src/lib.php";
$_SERVER["REMOTE_ADDR"] = "2001:db8:1:2::1"; $a = ip_hash(); $_SERVER["REMOTE_ADDR"] = "2001:db8:1:2:ffff::9"; $b = ip_hash();
$_SERVER["REMOTE_ADDR"] = "::ffff:192.0.2.1"; $c = ip_hash(); $_SERVER["REMOTE_ADDR"] = "::ffff:192.0.2.2"; $d = ip_hash();
echo $a === $b && $c !== $d ? "ok" : "ko";' | grep -q ok && ok "limite IPv6 par /64, IPv4 mappées entières" || ko "empreinte IP"
echo "Tous les tests passent."
