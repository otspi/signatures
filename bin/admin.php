<?php
// SPDX-License-Identifier: EUPL-1.2
// Clés de sécurité de l'administration (ligne de commande uniquement) : secours si la clé est perdue.
//   php bin/admin.php invitation     envoie à l'adresse de contact un lien d'enregistrement de clé (24 h, usage unique)
//   php bin/admin.php cles           liste les clés enregistrées
//   php bin/admin.php revoquer ID    révoque une clé et ferme ses sessions
//   php bin/admin.php deconnecter    ferme toutes les sessions d'administration

declare(strict_types=1);
if (PHP_SAPI !== 'cli' && isset($_SERVER['REQUEST_METHOD'])) {   // jamais depuis le Web ; php-cgi en ligne de commande accepté
    exit(1);
}
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/passkey.php';

$pdo = db();
$command = $argv[1] ?? '';

if ($command === 'invitation') {
    echo admin_send_invitation() ? 'Lien envoyé à ' . config()['contact'] . "\n" : "Échec de l'envoi\n";
    exit;
}
if ($command === 'cles') {
    foreach ($pdo->query('SELECT id, name, aaguid, created_at, last_used_at FROM admin_keys ORDER BY id') as $k) {
        echo "#{$k['id']}  {$k['name']}  AAGUID {$k['aaguid']}  ajoutée le " . date('Y-m-d H:i', (int) $k['created_at'])
            . ($k['last_used_at'] !== null ? ', utilisée le ' . date('Y-m-d H:i', (int) $k['last_used_at']) : '') . "\n";
    }
    exit;
}
if ($command === 'revoquer' && ctype_digit($argv[2] ?? '')) {
    $delete = $pdo->prepare('DELETE FROM admin_keys WHERE id = ?');
    $delete->execute([(int) $argv[2]]);
    $pdo->prepare("DELETE FROM admin_tokens WHERE kind = 'session' AND ref = ?")->execute([$argv[2]]);
    echo $delete->rowCount() === 1 ? "Clé #{$argv[2]} révoquée\n" : "Clé #{$argv[2]} introuvable\n";
    exit;
}
if ($command === 'deconnecter') {
    echo $pdo->exec("DELETE FROM admin_tokens WHERE kind = 'session'") . " session(s) fermée(s)\n";
    exit;
}
fwrite(STDERR, "Usage : php bin/admin.php invitation | cles | revoquer ID | deconnecter\n");
exit(2);
