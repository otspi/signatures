<?php
// SPDX-License-Identifier: EUPL-1.2
// Purge quotidienne (tâche cron) : supprime les demandes non confirmées de plus de 7 jours
// et les empreintes de limitation de débit périmées.

declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
    exit(1);
}
require __DIR__ . '/../src/lib.php';

$pdo = db();
$old = $pdo->prepare('DELETE FROM signatures WHERE confirmed_at IS NULL AND created_at < ?');
$old->execute([time() - UNCONFIRMED_TTL]);
$pdo->prepare('DELETE FROM hits WHERE at < ?')->execute([time() - 3600]);
echo date('c') . ' purge : ' . $old->rowCount() . " demande(s) non confirmée(s) supprimée(s)\n";
