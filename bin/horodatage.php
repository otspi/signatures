<?php
// SPDX-License-Identifier: EUPL-1.2
// Horodatage des signatures (ligne de commande uniquement) : même rattrapage que le cron quotidien, à lancer
// par exemple juste après la mise en ligne pour horodater les signatures existantes et leur envoyer leur preuve.
//   php bin/horodatage.php

declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
    exit(1);
}
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/horodatage.php';

$done = proof_catch_up();
echo "{$done['horodatees']} signature(s) horodatée(s), {$done['echecs']} échec(s), {$done['envoyees']} preuve(s) envoyée(s)\n";
exit($done['echecs'] > 0 ? 1 : 0);
