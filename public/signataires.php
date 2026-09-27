<?php
// SPDX-License-Identifier: EUPL-1.2
// Liste publique des signataires : uniquement les signatures confirmées dont l'auteur a consenti à la
// publication et validées par modération (bin/moderation.php). Aucune adresse e-mail. Le total compte
// aussi les signatures non publiées, mais pas celles qui attendent la modération. Format JSON, consommé par le script de génération du site
// et, en direct, par la page du manifeste de www.otspi.org (seule origine autorisée à le lire depuis un navigateur).
// Son empreinte SHA-256 est inscrite chaque jour dans le registre horodaté (src/registre.php, public/registre.php).

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/horodatage.php';
require __DIR__ . '/../src/registre.php';

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: public, max-age=300');
header('Access-Control-Allow-Origin: https://www.otspi.org');
header('X-Content-Type-Options: nosniff');
echo public_list_json();
