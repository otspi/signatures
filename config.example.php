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
    // Seule adresse qui reçoit les notifications et les liens d'enregistrement de clé de l'administration.
    'contact' => 'contact@otspi.org',
    // Facultatif : modèles de clé de sécurité acceptés pour l'administration (AAGUID en minuscules, affiché
    // dans la page « Clés de sécurité »). Vide : toute clé externe avec code PIN.
    'admin_aaguids' => [],
    // Facultatif : difficulté de la preuve de travail anti-robots (bits nuls, 18 par défaut ; +1 double le calcul).
    // 'pow_bits' => 18,
    // Autorité d'horodatage (API JSON RFC 3161) et chaîne épinglée pour vérifier ses jetons. Par défaut : le
    // staging d'OTSPI et src/tsa-staging-ca.pem. 'tsa_url' => '' désactive l'horodatage.
    // 'tsa_url' => 'https://api.staging.open-eidas.eu',
    // 'tsa_ca' => __DIR__ . '/src/tsa-staging-ca.pem',
    // Sauvegarde quotidienne chiffrée : destinataire (à défaut contact) et certificat de chiffrement (par défaut
    // src/sauvegarde-certificat.pem ; la clé privée correspondante reste hors du serveur).
    // 'backup_to' => 'contact@otspi.org',
    // 'backup_certificate' => __DIR__ . '/src/sauvegarde-certificat.pem',
    // Signatures à modérer : 'quotidien' (défaut, un récapitulatif par nuit) ou 'immediat' (un e-mail par signature).
    // 'moderation_notify' => 'quotidien',
    // Pour les essais : ne pas envoyer, journaliser dans mail_log.
    'mail_dry_run' => false,
    'mail_log' => __DIR__ . '/data/mail.log',
];
