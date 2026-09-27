#!/usr/bin/env bash
# Test de bout en bout en local : migration, inscription, confirmation, modération, administration par clé de
# sécurité (clé virtuelle tests/authenticator.php), liste publique, retrait, anti-abus.
# Prérequis : Docker. Usage : bash tests/flow.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"; mkdir -p "$WORK/data"
cat > "$WORK/config.php" <<'PHP'
<?php
return ['base_url'=>'http://localhost:8090','db_path'=>'/work/data/s.sqlite','secret'=>'test-secret','mail_from'=>'no-reply@example.org','mail_from_name'=>'OTSPI','contact'=>'contact@otspi.org','mail_dry_run'=>true,'mail_log'=>'/work/data/mail.log','mail_hourly_cap'=>2,'pow_bits'=>8,'tsa_url'=>'http://127.0.0.1:8091','tsa_ca'=>'/work/tsa/ca.pem','backup_certificate'=>'/work/tsa/backup.pem'];
PHP
# Base à l'ancien schéma (sans modération) avec une signature confirmée, pour tester la migration
docker run --rm -v "$WORK":/work php:8.3-cli php -r '$p = new PDO("sqlite:/work/data/s.sqlite");
$p->exec("CREATE TABLE signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, prenom TEXT NOT NULL, nom TEXT NOT NULL, fonction TEXT NOT NULL DEFAULT \"\", organisation TEXT NOT NULL DEFAULT \"\", publier INTEGER NOT NULL DEFAULT 0, lang TEXT NOT NULL DEFAULT \"fr\", confirm_hash TEXT NOT NULL, withdraw_hash TEXT NOT NULL, created_at INTEGER NOT NULL, last_mail_at INTEGER NOT NULL, confirmed_at INTEGER)");
$p->exec("INSERT INTO signatures (email, prenom, nom, publier, confirm_hash, withdraw_hash, created_at, last_mail_at, confirmed_at) VALUES (\"old@example.org\", \"Grace\", \"Hopper\", 1, \"x\", \"y\", 1, 1, 1), (\"old+bis@example.org\", \"Grace\", \"Hopper\", 1, \"z\", \"w\", 1, 1, 1)");'
# Autorité d'horodatage de test (tests/tsa-mock.php) : CA et unité d'horodatage (usage timeStamping) jetables
mkdir -p "$WORK/tsa"
cat > "$WORK/tsa/tsa.cnf" <<'CNF'
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
serial = /work/tsa/serial
crypto_device = builtin
signer_cert = /work/tsa/tsu.pem
certs = /work/tsa/ca.pem
signer_key = /work/tsa/tsu.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
CNF
docker run --rm -v "$WORK":/work -w /work/tsa php:8.3-cli sh -c 'echo 01 > serial
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=Test Root" -days 2 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout tsu.key -out tsu.csr -subj "/CN=Test TSU" 2>/dev/null
printf "extendedKeyUsage=critical,timeStamping\nbasicConstraints=CA:FALSE\n" > ext.cnf
openssl x509 -req -in tsu.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out tsu.pem -days 2 -extfile ext.cnf 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout backup.key -out backup.pem -subj "/CN=Sauvegarde de test" -days 2 2>/dev/null
chmod -R a+rwX /work/tsa'
cat > "$WORK/config-staging.php" <<'PHP'
<?php
return ['base_url'=>'http://localhost:8090','db_path'=>'/work/data/s.sqlite','secret'=>'test-secret','mail_from'=>'no-reply@example.org','mail_from_name'=>'OTSPI','contact'=>'contact@otspi.org','mail_dry_run'=>true,'mail_log'=>'/work/data/mail.log'];
PHP
CID=$(docker run -d --rm -p 8090:8090 -v "$ROOT":/app -v "$WORK":/work -e SIGN_CONFIG=/work/config.php -w /app/public php:8.3-cli php -S 0.0.0.0:8090)
trap 'docker stop "$CID" >/dev/null; rm -rf "$WORK"' EXIT
docker exec -d "$CID" php -S 127.0.0.1:8091 /app/tests/tsa-mock.php
sleep 3
U=http://localhost:8090
ok() { echo "OK  $1"; }; ko() { echo "ÉCHEC $1"; exit 1; }
curl -s "$U/signataires.php" | grep -q Hopper && ok "migration : signature existante reste publiée" || ko "migration"
ft() { curl -s "$U/" | grep -o 'name="ft" value="[^"]*"' | sed 's/.*value="//;s/"$//'; }
# Preuve de travail (8 bits dans ce test), calculée comme le ferait assets/pow.js
pow() { docker exec "$CID" php -r 'require "/app/src/lib.php"; for ($n = 0; !pow_ok($argv[1], (string) $n); $n++); echo $n;' "$1"; }
badpow() { docker exec "$CID" php -r 'require "/app/src/lib.php"; for ($n = 0; pow_ok($argv[1], (string) $n); $n++); echo $n;' "$1"; }

FT=$(ft); sleep 5
R=$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' -H 'Origin: null' -d "ft=$FT&pow=$(pow "$FT")&prenom=Ada&nom=Lovelace&email=ada@example.org&fonction=Ingénieure&organisation=Labo&publier=1&website=" "$U/")
[ "$R" = 200 ] && grep -q 'ada@example.org' "$WORK/data/mail.log" && ok "inscription et e-mail de confirmation" || ko "inscription"
TOKEN=$(grep -o 'confirm.php?t=[0-9a-f]*' "$WORK/data/mail.log" | head -1 | sed 's/.*t=//')
[ "$(curl -s "$U/signataires.php" | grep -c Lovelace)" = 0 ] && ok "non publiée avant confirmation" || ko "publiée trop tôt"
curl -s "$U/" | grep -q 'data-pow="8"' && curl -s -D - -o /dev/null "$U/" | grep -qi "script-src 'self'" && ok "formulaire : preuve de travail proposée" || ko "preuve de travail absente du formulaire"
curl -s -d "ft=$FT&pow=$(pow "$FT")&prenom=Rejeu&nom=Robot&email=rejeu@example.org&website=" "$U/" | grep -q 'a expiré' && ! grep -q 'rejeu@example.org' "$WORK/data/mail.log" && ok "jeton et preuve de travail à usage unique" || ko "jeton et preuve de travail rejoués"
grep -q 'Confirmer ma signature</a>' "$WORK/data/mail.log.html" && grep -q '<td class="strong"[^>]*>Labo</td>' "$WORK/data/mail.log.html" && ok "e-mail HTML : bouton et récapitulatif" || ko "e-mail HTML"
cat > "$WORK/config-mail.php" <<'PHP'
<?php
return ['base_url'=>'http://localhost:8090','db_path'=>'/work/data/s.sqlite','secret'=>'test-secret','mail_from'=>'no-reply@example.org','mail_from_name'=>'OTSPI','contact'=>'contact@otspi.org'];
PHP
docker exec -e SIGN_CONFIG=/work/config-mail.php "$CID" php -d sendmail_path="sh -c 'cat > /work/raw.eml'" -r 'require "/app/src/lib.php"; send_mail("ada@example.org", "Signature enregistrée é", "Bonjour,\n\nMerci : ça marche.\n\nhttp://localhost:8090/preuve.php?t=abc&lang=fr\n\nOTSPI — contact@otspi.org", "fr");'
python3 - "$WORK/raw.eml" <<'PY' && ok "e-mail MIME multipart : texte et HTML décodables, sujet UTF-8" || ko "structure MIME"
import email, email.policy, sys
m = email.message_from_bytes(open(sys.argv[1], 'rb').read().replace(b'\r\n', b'\n'), policy=email.policy.default)
text = m.get_body(('plain',)).get_content(); html = m.get_body(('html',)).get_content()
assert m.get_content_type() == 'multipart/alternative', m.get_content_type()
assert 'Merci : ça marche.' in text and 'Voir ma preuve horodatée</a>' in html and 'ça marche' in html
assert all(len(l) <= 998 for l in open(sys.argv[1], 'rb').read().split(b'\n'))
PY
grep -q '^Bonjour,$' "$WORK/data/mail.log" && grep -q 'Organisation : Labo' "$WORK/data/mail.log" && ok "e-mail sans nom en tête, avec récapitulatif" || ko "récapitulatif de l'e-mail"
curl -s "$U/confirm.php?t=$TOKEN" | grep -q 'method="post"' && ok "le lien affiche un bouton de confirmation" || ko "page de confirmation"
curl -s "$U/confirm.php?t=$TOKEN" | grep -q '<dd>Lovelace</dd>' && ok "récapitulatif sur la page de confirmation" || ko "récapitulatif de la page"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: cross-site' -d "t=$TOKEN" "$U/confirm.php")" = 200 ] && ok "confirmation depuis un autre site refusée" || ko "confirmation intersite"
[ "$(curl -s "$U/confirm.php?t=$TOKEN" | grep -c 'method="post"')" = 1 ] && ok "le lien seul (GET) ne confirme rien" || ko "confirmé par GET"
curl -s "$U/confirm.php?t=$TOKEN" | grep -q 'analytics.js' && ko "mesure d'audience sur une page à jeton" || ok "page à jeton non mesurée"
touch "$WORK/tsa/panne"
R=$(curl -s -w '\n%{http_code}' -d "t=$TOKEN" "$U/confirm.php?lang=fr")
[ "$(echo "$R" | tail -1)" = 200 ] && ok "confirmation (POST)" || ko "confirmation"
echo "$R" | grep -q 'data-track-load="Manifeste|Signature confirmée|fr"' && echo "$R" | grep -q 'analytics.js' && ok "signature confirmée mesurée, sans jeton dans l'adresse" || ko "mesure de la confirmation"
echo "$R" | grep -q 'linkedin.com/sharing' && echo "$R" | grep -q 'assets/partage.js' && echo "$R" | grep -q 'compteur.php' && ok "page de confirmation : partage et compteur à intégrer" || ko "bloc de partage"
PROOF=$(grep -o 'preuve.php?t=[0-9a-f]*&lang=fr' "$WORK/data/mail.log" | tail -1)
[ -n "$PROOF" ] && curl -s "$U/$PROOF" | grep -q 'Horodatage en cours' && ok "autorité injoignable : confirmation non bloquée, preuve en attente" || ko "preuve en attente"
curl -s "$U/$PROOF" | grep -q 'analytics.js' && ko "mesure d'audience sur la page de preuve" || ok "page de preuve non mesurée"
rm "$WORK/tsa/panne"
docker exec "$CID" php /app/bin/horodatage.php | grep -q '^3 signature(s) horodatée(s), 0 échec(s), 2 preuve(s) envoyée(s)' && ok "rattrapage : nouvelle signature et signatures antérieures horodatées" || ko "rattrapage de l'horodatage"
[ "$(grep -A1 'TO: old' "$WORK/data/mail.log" | grep -c 'est désormais horodatée')" = 2 ] && ! grep -A1 'TO: ada@example.org' "$WORK/data/mail.log" | grep -q 'désormais horodatée' && ok "preuve envoyée aux signatures antérieures, pas en double" || ko "envoi des preuves"
docker exec "$CID" php /app/bin/horodatage.php | grep -q '^0 signature(s) horodatée(s), 0 échec(s), 0 preuve(s)' && ok "rattrapage idempotent" || ko "second rattrapage"
curl -s "$U/$PROOF" | grep -q 'Horodatage vérifié' && curl -s "$U/$PROOF" | grep -q '<dd>Lovelace</dd>' && ok "page de preuve : horodatage vérifié" || ko "page de preuve"
curl -s -o "$WORK/p.json" "$U/$PROOF&f=json"; curl -s -o "$WORK/p.tsr" "$U/$PROOF&f=tsr"
grep -q '"nom": "Lovelace"' "$WORK/p.json" && ! grep -q '@' "$WORK/p.json" && ok "attestation téléchargeable, sans adresse e-mail" || ko "attestation"
docker exec "$CID" openssl ts -verify -data /work/p.json -in /work/p.tsr -CAfile /work/tsa/ca.pem 2>/dev/null | grep -q 'Verification: OK' && ok "vérification indépendante (openssl ts -verify)" || ko "openssl ts -verify"
sed 's/Lovelace/Lovelacf/' "$WORK/p.json" > "$WORK/p2.json"
docker exec "$CID" openssl ts -verify -data /work/p2.json -in /work/p.tsr -CAfile /work/tsa/ca.pem 2>/dev/null | grep -q 'Verification: OK' && ko "attestation modifiée acceptée" || ok "attestation modifiée d'un caractère : jeton invalide"
docker exec -e SIGN_CONFIG=/work/config-staging.php "$CID" php -r 'require "/app/src/lib.php"; require "/app/src/horodatage.php"; try { tsa_verify(file_get_contents("/work/p.tsr"), hash("sha256", file_get_contents("/work/p.json"), true)); echo "accepté"; } catch (TimestampInvalid $e) { echo $e->getMessage(); }' | grep -q "autorité épinglée" && ok "jeton d'une autre autorité refusé par la chaîne épinglée du staging" || ko "chaîne épinglée"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$U/preuve.php?t=$(printf '0%.0s' $(seq 64))")" = 404 ] && ok "lien de preuve falsifié refusé" || ko "preuve falsifiée"
[ "$(curl -s -o /dev/null -w '%{http_code}' -d "t=$TOKEN" "$U/confirm.php")" = 400 ] && ok "lien de confirmation à usage unique" || ko "réutilisation du lien"
grep -q 'SUBJECT: Signature à modérer' "$WORK/data/mail.log" && ko "notification immédiate (récapitulatif quotidien attendu)" || ok "pas d'e-mail de modération par signature"
docker exec "$CID" php /app/bin/moderation.php recapitulatif | grep -q '^1 signature' && grep -F -A12 'SUBJECT: 1 signature à modérer' "$WORK/data/mail.log" | grep -q 'Ada Lovelace' && ok "récapitulatif de modération" || ko "récapitulatif de modération"
grep -F -A12 'SUBJECT: 1 signature à modérer' "$WORK/data/mail.log" | grep -q 'Domaine différent de l’organisation déclarée' && ok "récapitulatif : indication adresse / organisation" || ko "indication dans le récapitulatif"
curl -s "$U/signataires.php" | grep -q Lovelace && ko "publiée avant modération" || ok "non publiée avant modération"
curl -s "$U/signataires.php" | grep -q '"total": 3' && ko "comptée avant modération" || ok "non comptée avant modération"
docker exec "$CID" php /app/bin/moderation.php lister | grep -q 'Ada Lovelace' && ok "modération en ligne de commande : liste" || ko "liste de modération"
grep -F -A14 'SUBJECT: 1 signature à modérer' "$WORK/data/mail.log" | grep -q "$U/admin.php?f=attente" && ok "notification : lien vers l'administration" || ko "lien de la notification"
[ "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$U/moderation.php?id=1&t=abc")" = "303 $U/admin.php?f=attente" ] && ok "ancien lien de modération redirigé vers l'administration" || ko "redirection moderation.php"
# Administration : connexion uniquement par clé de sécurité (clé virtuelle tests/authenticator.php)
AUTH() { docker exec -i "$CID" php /app/tests/authenticator.php "$@"; }
J="$WORK/jar"; J2="$WORK/jar2"
A() { curl -s -b "$J2" -H 'Sec-Fetch-Site: same-origin' "$@"; }
curl -s "$U/admin.php" | grep -q 'Envoyer le lien d’enregistrement' && ok "aucune clé : lien d'enregistrement proposé" || ko "page sans clé"
curl -s "$U/admin.php?f=attente" | grep -q 'Se déconnecter' && ko "administration sans clé !" || ok "administration fermée sans clé"
curl -s -D - -o /dev/null "$U/admin.php" | grep -qi "content-security-policy: default-src 'none'.*script-src 'self';" && ok "CSP : seul le script du site" || ko "CSP admin"
curl -s -o /dev/null -H 'Sec-Fetch-Site: same-origin' -d "a=invitation" "$U/admin.php"
INV=$(grep -o 'admin.php?inv=[A-Za-z0-9_-]*' "$WORK/data/mail.log" | tail -1); IT=${INV#*inv=}
grep -F -B8 "$INV" "$WORK/data/mail.log" | grep -q 'TO: contact@otspi.org' && ok "lien d'enregistrement envoyé à la seule adresse de contact" || ko "destinataire de l'invitation"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$U/admin.php?inv=$(printf 'A%.0s' $(seq 43))")" = 403 ] && ok "lien d'enregistrement falsifié refusé" || ko "invitation falsifiée"
REG=$(curl -s "$U/$INV" | AUTH create /work/key.json sans-pin)
curl -s -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$REG" -d "a=enregistrer&inv=$IT&nom=YubiKey" "$U/admin.php" | grep -q 'n’a pas pu être enregistrée' && ok "clé sans code PIN refusée à l'enregistrement" || ko "clé sans PIN"
REG=$(curl -s "$U/$INV" | AUTH create /work/key.json origine)
curl -s -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$REG" -d "a=enregistrer&inv=$IT&nom=YubiKey" "$U/admin.php" | grep -q 'n’a pas pu être enregistrée' && ok "enregistrement depuis une autre origine refusé" || ko "origine à l'enregistrement"
REG=$(curl -s "$U/$INV" | AUTH create /work/key.json)
R=$(curl -s -c "$J" -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$REG" -d "a=enregistrer&inv=$IT&nom=YubiKey" "$U/admin.php")
[ "$R" = 303 ] && ok "clé enregistrée par le lien d'invitation" || ko "enregistrement ($R)"
grep -q '^#HttpOnly_localhost.*otspi-admin' "$J" && ok "cookie de session HttpOnly" || ko "cookie de session"
grep -q 'SUBJECT: Nouvelle clé de sécurité' "$WORK/data/mail.log" && ok "alerte à l'enregistrement d'une clé" || ko "alerte clé"
curl -s -b "$J" "$U/admin.php?vue=cles" | grep -q 'session en cours' && ok "session ouverte après l'enregistrement" || ko "session après enregistrement"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$U/$INV")" = 403 ] && ok "lien d'enregistrement à usage unique" || ko "invitation réutilisable"
curl -s -o /dev/null -H 'Sec-Fetch-Site: same-origin' -d "a=invitation" "$U/admin.php"
[ "$(grep -c 'admin.php?inv=' "$WORK/data/mail.log")" = 1 ] && ok "plus d'invitation depuis le web une fois une clé enregistrée" || ko "invitation après clé"
for F in sans-pin signature origine; do
  LOGIN=$(curl -s "$U/admin.php" | AUTH get /work/key.json $F)
  curl -s -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$LOGIN" -d "a=connexion" "$U/admin.php" | grep -q 'Connexion refusée' && ok "connexion refusée : $F" || ko "connexion $F"
done
LOGIN=$(curl -s "$U/admin.php" | AUTH get /work/key.json)
R=$(curl -s -c "$J2" -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$LOGIN" -d "a=connexion" "$U/admin.php")
[ "$R" = 303 ] && grep -q 'otspi-admin' "$J2" && ok "connexion avec la clé et son code PIN" || ko "connexion ($R)"
curl -s -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$LOGIN" -d "a=connexion" "$U/admin.php" | grep -q 'Connexion refusée' && ok "réponse de connexion rejouée refusée" || ko "rejeu"
LOGIN=$(curl -s "$U/admin.php" | AUTH get /work/key.json compteur)
curl -s -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$LOGIN" -d "a=connexion" "$U/admin.php" | grep -q 'Connexion refusée' && ok "compteur de signatures en recul refusé" || ko "compteur"
curl -s -b 'otspi-admin=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$U/admin.php?f=attente" | grep -q 'Se déconnecter' && ko "cookie de session falsifié accepté !" || ok "cookie de session falsifié refusé"
MID=$(docker exec "$CID" php -r 'require "/app/src/lib.php"; echo db()->query("SELECT id FROM signatures WHERE email = \"ada@example.org\"")->fetchColumn();')
A "$U/admin.php?f=attente" | grep -q '<strong>Ada Lovelace</strong>' && ok "administration : signature à modérer" || ko "liste à modérer"
curl -s -b "$J2" -H 'Sec-Fetch-Site: cross-site' -d "a=valider&id=$MID" "$U/admin.php" | grep -q 'Action refusée' && ok "modération intersite : refus affiché" || ko "refus intersite non affiché"
curl -s -H 'Sec-Fetch-Site: same-origin' -d "a=valider&id=$MID" "$U/admin.php" | grep -q 'Session expirée' && ok "action sans session refusée" || ko "action sans session"
curl -s "$U/signataires.php" | grep -q Lovelace && ko "modération sans session ou depuis un autre site" || ok "rien de publié sans session valide"
P=$(A "$U/admin.php?f=attente")
echo "$P" | grep -q 'form="lot"' && echo "$P" | grep -q 'Valider la sélection' && echo "$P" | grep -q 'Domaine différent de l’organisation déclarée' && ok "administration : sélection par lot et indication adresse / organisation" || ko "page à modérer"
A -o /dev/null -w '%{redirect_url}' -d "a=valider-lot&f=attente" "$U/admin.php" | grep -q 'fait=lot-vide' && ok "lot vide refusé" || ko "lot vide"
R=$(A -o /dev/null -w '%{http_code} %{redirect_url}' -d "a=valider-lot&ids[]=$MID&f=attente" "$U/admin.php")
echo "$R" | grep -q '^303 .*fait=valider-lot.*id=1' && ok "validation par lot depuis l'administration" || ko "validation par lot ($R)"
curl -s "$U/signataires.php" | grep -q Lovelace && ok "publiée après validation" || ko "absente de la liste"
curl -s "$U/signataires.php" | grep -q 'ada@example.org' && ko "e-mail publié !" || ok "adresse e-mail jamais publiée"
curl -s -D "$WORK/h.txt" -o "$WORK/c.svg" "$U/compteur.php"
grep -qi '^content-type: image/svg+xml' "$WORK/h.txt" && python3 -c 'import sys, xml.dom.minidom as m; d = m.parse(sys.argv[1]); t = d.getElementsByTagName("title")[0].firstChild.data; assert "signataires" in t, t' "$WORK/c.svg" && grep -q "$(curl -s "$U/signataires.php" | python3 -c 'import json,sys; print(json.load(sys.stdin)["total"])') signataires" "$WORK/c.svg" && ok "compteur SVG valide, au total de la liste publique" || ko "compteur SVG"
curl -s -D - -o /dev/null "$U/signataires.php" | grep -qi '^access-control-allow-origin: https://www.otspi.org' && ok "liste lisible depuis www.otspi.org (CORS)" || ko "CORS"
A "$U/admin.php?f=publiees" | grep -q 'Lovelace' && ok "administration : liste des publiées" || ko "liste admin"
HID=$(docker exec "$CID" php -r 'require "/app/src/lib.php"; echo db()->query("SELECT id FROM signatures WHERE email = \"old+bis@example.org\"")->fetchColumn();')
[ "$(A -d "a=supprimer&id=$HID" "$U/admin.php" | grep -c 'Supprimer définitivement')" = 1 ] && ok "suppression : confirmation demandée" || ko "confirmation de suppression"
[ "$(curl -s "$U/signataires.php" | grep -c Hopper)" = 2 ] && ok "rien supprimé sans confirmation" || ko "supprimé sans confirmation"
curl -s -o /dev/null -b "$J2" -H 'Sec-Fetch-Site: cross-site' -d "a=supprimer&id=$HID&ok=1" "$U/admin.php"
[ "$(curl -s "$U/signataires.php" | grep -c Hopper)" = 2 ] && ok "action d'administration intersite refusée" || ko "admin intersite"
R=$(A -o /dev/null -w '%{http_code} %{redirect_url}' -d "a=supprimer&id=$HID&ok=1&f=publiees" "$U/admin.php")
echo "$R" | grep -q '^303 .*fait=supprimer' && [ "$(curl -s "$U/signataires.php" | grep -c Hopper)" = 1 ] && ok "suppression confirmée (doublon retiré)" || ko "suppression admin ($R)"
# Gestion des clés : ajout depuis la session, révocation, dernière clé protégée
REG=$(A "$U/admin.php?vue=cles" | AUTH create /work/key2.json)
R=$(A -o /dev/null -w '%{http_code} %{redirect_url}' --data-urlencode "reponse=$REG" -d "a=ajouter-cle&vue=cles&nom=Secours" "$U/admin.php")
echo "$R" | grep -q '^303 .*fait=cle' && [ "$(docker exec "$CID" php /app/bin/admin.php cles | grep -c '^#')" = 2 ] && ok "seconde clé ajoutée depuis la session" || ko "ajout de clé ($R)"
REG=$(curl -s -b "$J" "$U/admin.php?vue=cles" | AUTH create /work/key3.json)
A -o /dev/null --data-urlencode "reponse=$REG" -d "a=ajouter-cle&vue=cles&nom=Autre" "$U/admin.php"
[ "$(docker exec "$CID" php /app/bin/admin.php cles | grep -c '^#')" = 2 ] && ok "défi d'enregistrement lié à sa session" || ko "défi d'une autre session accepté"
K1=$(docker exec "$CID" php /app/bin/admin.php cles | sed -n '1s/^#\([0-9]*\).*/\1/p'); K2=$(docker exec "$CID" php /app/bin/admin.php cles | sed -n '2s/^#\([0-9]*\).*/\1/p')
# Connexion avec la clé de secours (J2 porte désormais sa session), puis révocation de la première clé.
cp "$J2" "$J"
LOGIN=$(curl -s "$U/admin.php" | AUTH get /work/key2.json)
curl -s -c "$J2" -o /dev/null -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$LOGIN" -d "a=connexion" "$U/admin.php"
A "$U/admin.php?f=attente" | grep -q 'Se déconnecter' && ok "connexion avec la clé de secours" || ko "connexion clé de secours"
A -o /dev/null -d "a=revoquer&id=$K1&vue=cles" "$U/admin.php"
curl -s -b "$J" "$U/admin.php?f=attente" | grep -q 'Se déconnecter' && ko "session d'une clé révoquée encore ouverte" || ok "révocation : sessions de la clé fermées"
LOGIN=$(curl -s "$U/admin.php" | AUTH get /work/key.json)
curl -s -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$LOGIN" -d "a=connexion" "$U/admin.php" | grep -q 'Connexion refusée' && ok "clé révoquée refusée" || ko "clé révoquée acceptée"
A -o /dev/null -w '%{redirect_url}' -d "a=revoquer&id=$K2&vue=cles" "$U/admin.php" | grep -q 'fait=derniere' && ok "la dernière clé ne peut pas être révoquée" || ko "dernière clé révoquée"
A -o /dev/null -d "a=deconnexion" "$U/admin.php"
A "$U/admin.php?f=attente" | grep -q 'Se déconnecter' && ko "session encore ouverte après déconnexion" || ok "déconnexion"
LOGIN=$(curl -s "$U/admin.php" | AUTH get /work/key2.json)
curl -s -c "$J2" -o /dev/null -H 'Sec-Fetch-Site: same-origin' --data-urlencode "reponse=$LOGIN" -d "a=connexion" "$U/admin.php"
FT=$(ft); sleep 5
curl -s -o /dev/null -d "ft=$FT&pow=$(pow "$FT")&prenom=Ada&nom=Lovelace&email=Ada%2Bbis@example.org" "$U/"
grep -q 'TO: ada+bis@example.org' "$WORK/data/mail.log" && ko "doublon par alias +tag" || ok "alias +tag d'une adresse déjà signée : aucun nouvel envoi"
FT=$(ft); sleep 5
curl -s -o /dev/null -d "ft=$FT&pow=$(pow "$FT")&prenom=Alan&nom=Turing&email=alan%2Bmanifeste@example.org" "$U/"
grep -q 'TO: alan+manifeste@example.org' "$WORK/data/mail.log" && ok "adresse +tag acceptée, envoi à l'adresse complète" || ko "adresse +tag"
W=$(grep -o 'withdraw.php?t=[0-9a-f]*' "$WORK/data/mail.log" | tail -1 | sed 's/.*t=//')
curl -s -o /dev/null -d "t=$W" "$U/withdraw.php"
curl -s "$U/signataires.php" | grep -q Lovelace && ko "retrait sans effet" || ok "retrait et suppression"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$U/$PROOF")" = 404 ] && ok "retrait : preuve supprimée avec la signature" || ko "preuve après retrait"
R=$(curl -s -o /dev/null -w '%{http_code}' -d "ft=$(ft)&prenom=Bot&nom=Bot&email=bot@example.org&website=x" "$U/")
grep -q 'bot@example.org' "$WORK/data/mail.log" && ko "piège à robots" || ok "piège à robots"
FT=$(ft); sleep 5
curl -s -d "ft=$FT&prenom=Sans&nom=Calcul&email=sanscalcul@example.org" "$U/" | grep -q 'vérification anti-robot' && ! grep -q 'sanscalcul@example.org' "$WORK/data/mail.log" && ok "envoi sans preuve de travail refusé" || ko "preuve de travail absente acceptée"
curl -s -d "ft=$FT&pow=$(badpow "$FT")&prenom=Faux&nom=Calcul&email=fauxcalcul@example.org" "$U/" | grep -q 'vérification anti-robot' && ok "preuve de travail fausse refusée" || ko "preuve de travail fausse acceptée"
FT=$(ft); sleep 5
curl -s -d "ft=$FT&pow=$(pow "$FT")&prenom=Jet&nom=Able&email=jet@yopmail.fr" "$U/" | grep -q 'jetables' && ! grep -q 'jet@yopmail.fr' "$WORK/data/mail.log" && ok "adresse jetable refusée" || ko "adresse jetable acceptée"
docker exec "$CID" php -r 'require "/app/src/lib.php"; echo disposable_email("a@mx.mailinator.com") && !disposable_email("a@otspi.org") && !disposable_email("a@notyopmail.fr") ? "ok" : "ko";' | grep -q ok && ok "domaines jetables : sous-domaines compris, pas de faux positif" || ko "détection des domaines jetables"
docker exec "$CID" php -r 'require "/app/src/lib.php"; for ($n = 0, $bad = 0; $n < 3000; $n++) { $h = hash("sha256", "t:" . $n); $want = str_starts_with($h, "00"); $bad += pow_ok("t", (string) $n) !== $want; } echo $bad;' | grep -qx 0 && ok "preuve de travail : contrôle exact des 8 bits" || ko "calcul des bits nuls"
FT=$(ft); curl -s -d "ft=$FT&pow=$(pow "$FT")&prenom=Vite&nom=Vite&email=vite@example.org" "$U/" | grep -q 'role="alert"' && ok "formulaire envoyé trop vite refusé" || ko "trop vite"
curl -s -d "ft=faux&prenom=A&nom=B&email=a@example.org" "$U/" | grep -q 'role="alert"' && ok "jeton falsifié refusé" || ko "jeton"
FT=$(ft); sleep 5
curl -s -d "ft=$FT&pow=$(pow "$FT")&nom=Faux&email=bidi@example.org" --data-urlencode "prenom=$(printf 'Ada\u202Eecalevol')" "$U/" | grep -q 'role="alert"' && ok "caractères bidirectionnels refusés" || ko "bidi accepté"
# Plafond global (2 par heure dans ce test) : on isole de la limite par IP en vidant ses empreintes.
docker exec "$CID" php -r 'require "/app/src/lib.php"; db()->exec("DELETE FROM hits");'
FT=$(ft); sleep 5
curl -s -o /dev/null -d "ft=$FT&pow=$(pow "$FT")&prenom=Hedy&nom=Lamarr&email=hedy@example.org" "$U/"
grep -q 'TO: hedy@example.org' "$WORK/data/mail.log" && ok "envoi sous le plafond" || ko "envoi sous le plafond"
docker exec "$CID" php -r 'require "/app/src/lib.php"; echo mail_cap_reached() ? "plein" : "libre";' | grep -q plein && ok "plafond global d'envois atteint" || ko "plafond global"
FT=$(ft); sleep 5
curl -s -d "ft=$FT&pow=$(pow "$FT")&prenom=Plafond&nom=Test&email=plafond@example.org" "$U/" | grep -q 'role="alert"' && ! grep -q 'plafond@example.org' "$WORK/data/mail.log" && ok "aucun envoi au-delà du plafond" || ko "envoi au-delà du plafond"
FT=$(ft); sleep 5
curl -s -H 'Sec-Fetch-Site: cross-site' -d "ft=$FT&pow=$(pow "$FT")&prenom=A&nom=B&email=x@example.org" "$U/" | grep -q 'role="alert"' && ok "envoi depuis un autre site refusé (Sec-Fetch-Site)" || ko "intersite Sec-Fetch-Site"
curl -s -H 'Origin: https://evil.example' -d "ft=$FT&pow=$(pow "$FT")&prenom=A&nom=B&email=x@example.org" "$U/" | grep -q 'role="alert"' && ok "envoi depuis un autre site refusé (Origin)" || ko "intersite Origin"
curl -s -d "ft=$FT&pow=$(pow "$FT")&prenom=Ada&nom=Faux&email=lien@example.org" --data-urlencode "organisation=Voir https://evil.example" "$U/" | grep -q 'role="alert"' && ok "liens refusés dans les champs" || ko "lien accepté"
docker exec "$CID" php -r 'require "/app/src/lib.php";
$_SERVER["REMOTE_ADDR"] = "2001:db8:1:2::1"; $a = ip_hash(); $_SERVER["REMOTE_ADDR"] = "2001:db8:1:2:ffff::9"; $b = ip_hash();
$_SERVER["REMOTE_ADDR"] = "::ffff:192.0.2.1"; $c = ip_hash(); $_SERVER["REMOTE_ADDR"] = "::ffff:192.0.2.2"; $d = ip_hash();
echo $a === $b && $c !== $d ? "ok" : "ko";' | grep -q ok && ok "limite IPv6 par /64, IPv4 mappées entières" || ko "empreinte IP"
# Demandes non confirmées : renvoi du lien (au plus toutes les 10 minutes) et suppression
TID=$(docker exec "$CID" php -r 'require "/app/src/lib.php"; echo db()->query("SELECT id FROM signatures WHERE email = \"alan+manifeste@example.org\"")->fetchColumn();')
A "$U/admin.php?f=non-confirmees" | grep -q 'Alan Turing' && ok "administration : demandes en attente de confirmation" || ko "liste non confirmées"
A -o /dev/null -w '%{redirect_url}' -d "a=renvoyer&id=$TID&f=non-confirmees" "$U/admin.php" | grep -q 'fait=trop-tot' && ok "renvoi refusé moins de 10 minutes après un envoi" || ko "renvoi trop rapproché"
docker exec "$CID" php -r 'require "/app/src/lib.php"; db()->exec("UPDATE signatures SET last_mail_at = last_mail_at - 900");'
A -o /dev/null -w '%{redirect_url}' -d "a=renvoyer&id=$TID&f=non-confirmees" "$U/admin.php" | grep -q 'fait=renvoyer' && [ "$(grep -c 'TO: alan+manifeste@example.org' "$WORK/data/mail.log")" = 2 ] && ok "lien de confirmation renvoyé" || ko "renvoi du lien"
C=$(grep -o 'confirm.php?t=[0-9a-f]*' "$WORK/data/mail.log" | tail -1)
curl -s "$U/$C" | grep -q '<dd>Turing</dd>' && ok "le lien renvoyé ouvre la confirmation" || ko "lien renvoyé"
A -o /dev/null -w '%{redirect_url}' -d "a=valider&id=$TID&f=non-confirmees" "$U/admin.php" | grep -q 'fait=rien' && ok "une demande non confirmée ne peut pas être validée" || ko "validation sans confirmation"
A -o /dev/null -d "a=supprimer&id=$TID&ok=1&f=non-confirmees" "$U/admin.php"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$U/$C")" = 400 ] && ok "demande non confirmée supprimée" || ko "suppression non confirmée"
# Tâche quotidienne : registre horodaté, sauvegarde chiffrée, alertes
SQL() { docker exec "$CID" php -r 'require "/app/src/lib.php"; $r = db()->query($argv[1]); echo $r ? implode("\n", $r->fetchAll(PDO::FETCH_COLUMN)) : "";' "$1"; }
OUT=$(docker exec "$CID" php /app/cron/purge.php)
echo "$OUT" | grep -q "registre : 0 entrée(s) en attente" && echo "$OUT" | grep -q 'sauvegarde : signatures-' && ! echo "$OUT" | grep -q alerte && ok "tâche quotidienne : registre et sauvegarde, sans alerte" || ko "tâche quotidienne ($OUT)"
B=$(ls "$WORK/data/pieces-jointes/" | grep '\.sqlite\.gz\.p7m$' | tail -1)
docker exec "$CID" sh -c "openssl cms -decrypt -binary -inform DER -in /work/data/pieces-jointes/$B -inkey /work/tsa/backup.key | gunzip > /work/restauree.sqlite"
[ "$(docker exec "$CID" php -r '$p = new PDO("sqlite:/work/restauree.sqlite"); echo $p->query("SELECT COUNT(*) FROM signatures")->fetchColumn();')" = "$(SQL 'SELECT COUNT(*) FROM signatures')" ] && ok "sauvegarde chiffrée : déchiffrée et restaurée avec la clé privée" || ko "restauration de la sauvegarde"
grep -q 'SQLite format' "$WORK/data/pieces-jointes/$B" && ko "sauvegarde en clair !" || ok "sauvegarde illisible sans la clé privée"
grep -A12 'SUBJECT: Sauvegarde des signatures' "$WORK/data/mail.log" | grep -q '@example.org' && ko "données personnelles dans l'e-mail de sauvegarde" || ok "e-mail de sauvegarde sans donnée personnelle"
curl -s "$U/registre.php" | grep -q 'Chaîne intègre : 1 entrée chaînée' && ok "registre public : première entrée" || ko "page du registre"
curl -s -o "$WORK/r1.json" "$U/registre.php?n=1&f=json"; curl -s -o "$WORK/r1.tsr" "$U/registre.php?n=1&f=tsr"
[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["liste_sha256"])' "$WORK/r1.json")" = "$(curl -s "$U/signataires.php" | sha256sum | cut -d' ' -f1)" ] && ok "registre : empreinte identique à la liste publique servie" || ko "empreinte de la liste"
docker exec "$CID" openssl ts -verify -data /work/r1.json -in /work/r1.tsr -CAfile /work/tsa/ca.pem 2>/dev/null | grep -q 'Verification: OK' && ok "registre : entrée horodatée (openssl ts -verify)" || ko "horodatage du registre"
SQL "UPDATE registre SET jour = '2000-01-01'" >/dev/null
docker exec "$CID" php /app/cron/purge.php >/dev/null
[ "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["precedente_sha256"])' < <(curl -s "$U/registre.php?n=2&f=json"))" = "$(sha256sum < "$WORK/r1.json" | cut -d' ' -f1)" ] && curl -s "$U/registre.php" | grep -q '2 entrées chaînées' && ok "registre : entrée du lendemain chaînée à la précédente" || ko "chaînage du registre"
SQL "UPDATE registre SET jour = '2000-01-0' || numero" >/dev/null
touch "$WORK/tsa/panne"
docker exec "$CID" php /app/cron/purge.php | grep -q 'alerte envoyée' && grep -A8 'SUBJECT: Alerte : tâche quotidienne' "$WORK/data/mail.log" | grep -q "entrée(s) en attente d'horodatage" && ok "alerte : autorité d'horodatage injoignable" || ko "alerte d'horodatage"
rm "$WORK/tsa/panne"
SQL "UPDATE registre SET entree = replace(entree, '\"total\"', '\"total \"') WHERE numero = 1" >/dev/null
curl -s "$U/registre.php" | grep -q 'Chaînage rompu' && docker exec "$CID" php /app/cron/purge.php >/dev/null && [ "$(grep -A10 'SUBJECT: Alerte' "$WORK/data/mail.log" | grep -c 'chaînage rompu')" -ge 1 ] && ok "registre falsifié : chaîne rompue affichée et alerte envoyée" || ko "falsification du registre"
echo "Tous les tests passent."
