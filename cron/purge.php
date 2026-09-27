<?php
// SPDX-License-Identifier: EUPL-1.2
// Purge quotidienne (tâche cron) : supprime les demandes non confirmées de plus de 7 jours
// ainsi que les empreintes de limitation de débit, invitations, défis et sessions d'administration périmés.

declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
    exit(1);
}
require __DIR__ . '/../src/lib.php';

$pdo = db();
$old = $pdo->prepare('DELETE FROM signatures WHERE confirmed_at IS NULL AND created_at < ?');
$old->execute([time() - UNCONFIRMED_TTL]);
$pdo->prepare('DELETE FROM hits WHERE at < ?')->execute([time() - 3600]);
$pdo->prepare('DELETE FROM admin_tokens WHERE expires_at < ?')->execute([time()]);
$pdo->prepare('DELETE FROM form_tokens WHERE at < ?')->execute([time() - MAX_FILL_SECONDS]);
echo date('c') . ' purge : ' . $old->rowCount() . " demande(s) non confirmée(s) supprimée(s)\n";
