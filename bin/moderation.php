<?php
// SPDX-License-Identifier: EUPL-1.2
// Modération des signatures avant publication (ligne de commande uniquement).
//   php bin/moderation.php lister           signatures confirmées en attente de validation
//   php bin/moderation.php valider ID...    publie les signatures dans la liste publique
//   php bin/moderation.php masquer ID...    garde la signature (comptée) sans jamais publier le nom
//   php bin/moderation.php supprimer ID...  supprime la signature et ses données (usurpation, abus)

declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
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

$statements = [
    'valider' => 'UPDATE signatures SET approved_at = ? WHERE id = ? AND confirmed_at IS NOT NULL',
    'masquer' => 'UPDATE signatures SET publier = 0, approved_at = ? WHERE id = ? AND confirmed_at IS NOT NULL',
    'supprimer' => 'DELETE FROM signatures WHERE id = ?',
];
if (!isset($statements[$command]) || $ids === [] || in_array(0, $ids, true)) {
    fwrite(STDERR, "Usage : php bin/moderation.php lister | valider ID... | masquer ID... | supprimer ID...\n");
    exit(2);
}
$statement = $pdo->prepare($statements[$command]);
foreach ($ids as $id) {
    $statement->execute($command === 'supprimer' ? [$id] : [time(), $id]);
    echo "#{$id} : " . ($statement->rowCount() === 1 ? $command . ' — fait' : 'introuvable ou non confirmée') . "\n";
}
