<?php
// SPDX-License-Identifier: EUPL-1.2
// Modération des signatures avant publication (ligne de commande uniquement).
//   php bin/moderation.php lister           signatures confirmées en attente de validation
//   php bin/moderation.php recapitulatif    envoie tout de suite le récapitulatif des signatures à modérer
//   php bin/moderation.php valider ID...    publie les signatures dans la liste publique
//   php bin/moderation.php masquer ID...    garde la signature (comptée) sans jamais publier le nom
//   php bin/moderation.php supprimer ID...  supprime la signature et ses données (usurpation, abus), confirmée ou non
// Les mêmes actions sont accessibles dans l'administration (public/admin.php, connexion par clé de sécurité).

declare(strict_types=1);
if (PHP_SAPI !== 'cli' && isset($_SERVER['REQUEST_METHOD'])) {   // jamais depuis le Web ; php-cgi en ligne de commande accepté
    exit(1);
}
require __DIR__ . '/../src/lib.php';

$pdo = db();
$command = $argv[1] ?? '';
$ids = array_map('intval', array_slice($argv, 2));

if ($command === 'lister') {
    $rows = $pdo->query('SELECT id, prenom, nom, fonction, organisation, email, confirmed_at FROM signatures WHERE confirmed_at IS NOT NULL AND publier = 1 AND approved_at IS NULL ORDER BY confirmed_at')->fetchAll();
    foreach ($rows as $r) {
        $quality = implode(', ', array_filter([$r['fonction'], $r['organisation']], 'strlen'));
        echo "#{$r['id']}  {$r['prenom']} {$r['nom']}" . ($quality !== '' ? " — {$quality}" : '')
            . "  <{$r['email']}>  confirmée le " . date('Y-m-d H:i', (int) $r['confirmed_at']) . "\n";
    }
    echo count($rows) . " signature(s) en attente\n";
    exit;
}

if ($command === 'recapitulatif') {
    echo moderation_digest() . " signature(s) à modérer dans le récapitulatif\n";
    exit;
}

if (!in_array($command, MODERATION_ACTIONS, true) || $ids === [] || in_array(0, $ids, true)) {
    fwrite(STDERR, "Usage : php bin/moderation.php lister | recapitulatif | valider ID... | masquer ID... | supprimer ID...\n");
    exit(2);
}
foreach ($ids as $id) {
    echo "#{$id} : " . (moderate($id, $command) ? $command . ' — fait' : ($command === 'supprimer' ? 'introuvable' : 'introuvable ou non confirmée')) . "\n";
}
