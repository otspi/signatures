<?php
// SPDX-License-Identifier: EUPL-1.2
// Sauvegarde chiffrée de la base, envoyée tout de suite (ligne de commande uniquement ; la tâche quotidienne
// l'envoie chaque nuit). Voir src/sauvegarde.php pour la restauration.
//   php bin/sauvegarde.php

declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
    exit(1);
}
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/sauvegarde.php';

$name = backup_send();
echo $name !== null ? "Sauvegarde envoyée : $name\n" : "Échec de la sauvegarde (voir le journal d'erreurs)\n";
exit($name !== null ? 0 : 1);
