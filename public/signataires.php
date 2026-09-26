<?php
// SPDX-License-Identifier: EUPL-1.2
// Liste publique des signataires : uniquement les signatures confirmées dont l'auteur a consenti à la
// publication. Aucune adresse e-mail. Format JSON, consommé par le script de génération du site.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

$rows = db()->query('SELECT prenom, nom, fonction, organisation FROM signatures WHERE confirmed_at IS NOT NULL AND publier = 1 ORDER BY confirmed_at, id')->fetchAll();
$total = (int) db()->query('SELECT COUNT(*) FROM signatures WHERE confirmed_at IS NOT NULL')->fetchColumn();

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: public, max-age=300');
header('X-Content-Type-Options: nosniff');
echo json_encode(['total' => $total, 'signataires' => $rows], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
