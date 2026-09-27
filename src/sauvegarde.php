<?php
// SPDX-License-Identifier: EUPL-1.2
// Sauvegarde quotidienne de la base, hors du serveur : copie cohérente (VACUUM INTO), compressée, chiffrée pour
// le seul certificat src/sauvegarde-certificat.pem (CMS, AES-256), puis envoyée en pièce jointe à l'adresse de
// sauvegarde (backup_to, à défaut contact). Le serveur ne détient que le certificat public : il chiffre mais ne
// peut rien relire. Restauration, avec la clé privée gardée hors du serveur :
//   openssl cms -decrypt -binary -inform DER -in FICHIER.p7m -inkey cle-privee.pem | gunzip > signatures.sqlite

declare(strict_types=1);

/** Envoie la sauvegarde du jour ; renvoie le nom du fichier envoyé, ou null en cas d'échec (journalisé). */
function backup_send(): ?string
{
    $certificate = (string) (config()['backup_certificate'] ?? __DIR__ . '/sauvegarde-certificat.pem');
    $copy = tempnam(sys_get_temp_dir(), 'otspi-copie');
    $plain = tempnam(sys_get_temp_dir(), 'otspi-gz');
    $sealed = tempnam(sys_get_temp_dir(), 'otspi-p7m');
    try {
        // VACUUM INTO : copie cohérente même pendant une écriture (journal WAL compris), sur une connexion dédiée
        // pour qu'aucune requête en cours de l'application ne la bloque.
        @unlink($copy);
        db();
        (new PDO('sqlite:' . config()['db_path'], null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]))
            ->prepare('VACUUM INTO ?')->execute([$copy]);
        $count = (int) (new PDO('sqlite:' . $copy))->query('SELECT COUNT(*) FROM signatures')->fetchColumn();
        file_put_contents($plain, gzencode((string) file_get_contents($copy), 9));
        if (!is_file($certificate) || !openssl_cms_encrypt($plain, $sealed, (string) file_get_contents($certificate), null,
            OPENSSL_CMS_BINARY, OPENSSL_ENCODING_DER, OPENSSL_CIPHER_AES_256_CBC)) {
            error_log('otspi-signatures : sauvegarde non chiffrée (' . (openssl_error_string() ?: 'certificat introuvable') . ')');
            return null;
        }
        $name = 'signatures-' . date('Y-m-d') . '.sqlite.gz.p7m';
        $data = (string) file_get_contents($sealed);
        $sent = send_mail((string) (config()['backup_to'] ?? config()['contact']), 'Sauvegarde des signatures du ' . date('d/m/Y'),
            "Sauvegarde quotidienne de la base des signatures du manifeste, chiffrée : seule la clé privée de sauvegarde,\n"
            . "gardée hors du serveur, permet de l'ouvrir.\n\n"
            . "  Fichier : $name\n  Taille : " . strlen($data) . " octets\n  SHA-256 : " . hash('sha256', $data) . "\n  Lignes : $count signature(s) ou demande(s)\n\n"
            . "Restauration :\n"
            . "openssl cms -decrypt -binary -inform DER -in $name -inkey cle-privee.pem | gunzip > signatures.sqlite\n\n"
            . "OTSPI — contact@otspi.org", 'fr', [$name => $data]);
        if (!$sent) {
            error_log('otspi-signatures : sauvegarde non envoyée');
        }
        return $sent ? $name : null;
    } finally {
        foreach ([$copy, $plain, $sealed] as $file) {
            @unlink($file);
        }
    }
}
