<?php
// Copier en config.php (hors du dossier public/, jamais versionné) et adapter.
return [
    // Adresse publique de l'application (sans barre finale).
    'base_url' => 'https://manifesto-sign.otspi.org',
    // Base SQLite, HORS du dossier public/.
    'db_path' => __DIR__ . '/data/signatures.sqlite',
    // Chaîne aléatoire longue et secrète : php -r 'echo bin2hex(random_bytes(32));'
    'secret' => 'CHANGER-MOI',
    'mail_from' => 'no-reply@manifesto-sign.otspi.org',
    'mail_from_name' => 'OTSPI',
    'contact' => 'contact@otspi.org',
    // Pour les essais : ne pas envoyer, journaliser dans mail_log.
    'mail_dry_run' => false,
    'mail_log' => __DIR__ . '/data/mail.log',
];
