<?php
// SPDX-License-Identifier: EUPL-1.2
// Bibliothèque de l'application de signature du manifeste OTSPI : configuration, base SQLite,
// jetons, limitation de débit, courriels et textes bilingues. Aucune dépendance externe.

declare(strict_types=1);

const CONFIRM_TTL = 172800;      // 48 h : validité du lien de confirmation
const UNCONFIRMED_TTL = 604800;  // 7 jours : durée de conservation d'une demande non confirmée
const MIN_FILL_SECONDS = 4;      // un humain met plus de 4 s à remplir le formulaire
const MAX_FILL_SECONDS = 7200;   // formulaire périmé au-delà de 2 h
const MAIL_HOURLY_CAP = 200;     // plafond global d'e-mails de confirmation par heure (surcharge : mail_hourly_cap)
const POW_BITS = 18;             // preuve de travail : bits nuls en tête de l'empreinte (surcharge : pow_bits)

// Erreur inattendue (base verrouillée, disque plein…) : journalisée, jamais affichée.
set_exception_handler(static function (Throwable $e): void {
    error_log('otspi-signatures : ' . $e);
    if (PHP_SAPI === 'cli') {
        exit(1);
    }
    http_response_code(500);
    $lang = lang();
    page(t('err_server_title', $lang), '<h1>' . h(t('err_server_title', $lang)) . '</h1><p>' . h(t('err_server', $lang)) . '</p>', $lang);
});

function config(): array
{
    static $config = null;
    if ($config === null) {
        $file = getenv('SIGN_CONFIG') ?: __DIR__ . '/../config.php';
        if (!is_file($file)) {
            http_response_code(500);
            exit('Configuration manquante.');
        }
        $config = require $file;
    }
    return $config;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $path = config()['db_path'];
        $new = !is_file($path);
        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $pdo->exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
        if ($new) {
            @chmod($path, 0600);
        }
        $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    email_key TEXT,
    prenom TEXT NOT NULL,
    nom TEXT NOT NULL,
    fonction TEXT NOT NULL DEFAULT '',
    organisation TEXT NOT NULL DEFAULT '',
    publier INTEGER NOT NULL DEFAULT 0,
    lang TEXT NOT NULL DEFAULT 'fr',
    confirm_hash TEXT NOT NULL,
    withdraw_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_mail_at INTEGER NOT NULL,
    confirmed_at INTEGER,
    approved_at INTEGER
);
CREATE TABLE IF NOT EXISTS hits (
    ip_hash TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS hits_ip ON hits (ip_hash, at);
CREATE TABLE IF NOT EXISTS registre (
    numero INTEGER PRIMARY KEY,
    jour TEXT NOT NULL UNIQUE,
    entree TEXT NOT NULL,
    jeton TEXT,
    horodate_le INTEGER
);
CREATE TABLE IF NOT EXISTS form_tokens (
    hash TEXT PRIMARY KEY,
    at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    aaguid TEXT NOT NULL DEFAULT '',
    transports TEXT NOT NULL DEFAULT '[]',
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS admin_tokens (
    hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
SQL);
        migrate($pdo);
        migrate_proof($pdo);
        $pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS signatures_email_key ON signatures (email_key)');
    }
    return $pdo;
}

/** Colonnes de la preuve horodatée (src/horodatage.php), ajoutées aux bases existantes. */
function migrate_proof(PDO $pdo): void
{
    $existing = $pdo->query('PRAGMA table_info(signatures)')->fetchAll(PDO::FETCH_COLUMN, 1);
    foreach (['proof_hash' => 'TEXT', 'proof_json' => 'TEXT', 'proof_token' => 'TEXT', 'proof_at' => 'INTEGER', 'proof_mailed_at' => 'INTEGER'] as $column => $type) {
        if (!in_array($column, $existing, true)) {
            $pdo->exec("ALTER TABLE signatures ADD COLUMN $column $type");
        }
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS signatures_proof ON signatures (proof_hash)');
}

/** Met à niveau les bases créées avant la modération et la clé d'unicité des adresses. */
function migrate(PDO $pdo): void
{
    $columns = static fn (): array => $pdo->query('PRAGMA table_info(signatures)')->fetchAll(PDO::FETCH_COLUMN, 1);
    if (array_diff(['approved_at', 'email_key'], $columns()) === []) {
        return;
    }
    $pdo->exec('BEGIN IMMEDIATE');
    $existing = $columns();
    if (!in_array('approved_at', $existing, true)) {
        // Les signatures confirmées avant la modération étaient déjà publiées : elles sont réputées validées.
        $pdo->exec('ALTER TABLE signatures ADD COLUMN approved_at INTEGER; UPDATE signatures SET approved_at = confirmed_at WHERE confirmed_at IS NOT NULL;');
    }
    if (!in_array('email_key', $existing, true)) {
        $pdo->exec('ALTER TABLE signatures ADD COLUMN email_key TEXT');
        $set = $pdo->prepare('UPDATE signatures SET email_key = ? WHERE id = ?');
        $seen = [];
        foreach ($pdo->query('SELECT id, email FROM signatures ORDER BY confirmed_at IS NULL, id')->fetchAll() as $row) {
            // Doublons antérieurs par alias « + » : conservés, avec l'adresse complète (déjà unique) pour clé.
            $key = email_key($row['email']);
            $key = isset($seen[$key]) ? $row['email'] : $key;
            $seen[$key] = true;
            $set->execute([$key, $row['id']]);
        }
    }
    $pdo->exec('COMMIT');
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function lang(): string
{
    $wanted = $_GET['lang'] ?? $_POST['lang'] ?? '';
    return $wanted === 'en' ? 'en' : 'fr';
}

// ---- Jetons -------------------------------------------------------------------------------------

function new_token(): string
{
    return bin2hex(random_bytes(32));
}

function token_hash(string $token): string
{
    return hash_hmac('sha256', $token, config()['secret']);
}

/**
 * Jeton de formulaire signé : horodatage, aléa et HMAC (aucune session, aucun cookie). Il sert aussi de défi
 * à la preuve de travail, et ne sert qu'une fois (form_token_spend).
 */
function form_token(): string
{
    $body = time() . '.' . bin2hex(random_bytes(8));
    return $body . '.' . hash_hmac('sha256', 'form|' . $body, config()['secret']);
}

function form_token_state(string $token): string
{
    $parts = explode('.', $token);
    if (count($parts) !== 3 || !ctype_digit($parts[0]) || preg_match('/^[0-9a-f]{16}$/', $parts[1]) !== 1) {
        return 'invalid';
    }
    $expected = hash_hmac('sha256', 'form|' . $parts[0] . '.' . $parts[1], config()['secret']);
    if (!hash_equals($expected, $parts[2])) {
        return 'invalid';
    }
    $age = time() - (int) $parts[0];
    if ($age < MIN_FILL_SECONDS) {
        return 'too_fast';
    }
    return $age > MAX_FILL_SECONDS ? 'expired' : 'ok';
}

/** Marque un jeton de formulaire comme utilisé : faux si il l'était déjà (preuve de travail rejouée). */
function form_token_spend(string $token): bool
{
    $pdo = db();
    $pdo->prepare('DELETE FROM form_tokens WHERE at < ?')->execute([time() - MAX_FILL_SECONDS]);
    $insert = $pdo->prepare('INSERT OR IGNORE INTO form_tokens (hash, at) VALUES (?, ?)');
    $insert->execute([token_hash($token), time()]);
    return $insert->rowCount() === 1;
}

function pow_bits(): int
{
    return (int) (config()['pow_bits'] ?? POW_BITS);
}

/**
 * Preuve de travail (assets/pow.js) : le navigateur cherche un entier tel que SHA-256(jeton:entier) commence
 * par pow_bits() bits nuls, soit environ 2^18 essais (moins d'une seconde sur un ordinateur, quelques secondes
 * sur un téléphone lent), calculés pendant que la personne remplit le formulaire. Négligeable pour une personne,
 * coûteux pour un robot qui envoie en masse, qui doit en outre exécuter le calcul. Aucun service tiers.
 */
function pow_ok(string $token, string $nonce): bool
{
    if (preg_match('/^[0-9]{1,12}$/', $nonce) !== 1) {
        return false;
    }
    $bits = pow_bits();
    foreach (str_split(hash('sha256', $token . ':' . $nonce, true)) as $byte) {
        if ($bits <= 0) {
            return true;
        }
        for ($zeros = 0, $value = ord($byte); $zeros < 8 && ($value & (0x80 >> $zeros)) === 0; $zeros++);
        if ($zeros < min(8, $bits)) {
            return false;
        }
        $bits -= 8;
    }
    return true;
}

// ---- Limitation de débit ------------------------------------------------------------------------

/** Empreinte salée de l'adresse IP, conservée une heure au plus. */
function ip_hash(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $packed = @inet_pton($ip);
    // IPv6 : un abonné dispose en général d'un /64 entier ; la limite porte donc sur le préfixe.
    // Les adresses IPv4 représentées en IPv6 (::ffff:a.b.c.d) restent entières.
    if ($packed !== false && strlen($packed) === 16 && substr($packed, 0, 12) !== str_repeat("\0", 10) . "\xff\xff") {
        $ip = bin2hex(substr($packed, 0, 8)) . '/64';
    }
    return hash_hmac('sha256', 'ip|' . $ip, config()['secret']);
}

function rate_limited(int $max, int $window): bool
{
    $pdo = db();
    $pdo->prepare('DELETE FROM hits WHERE at < ?')->execute([time() - 3600]);
    $count = $pdo->prepare('SELECT COUNT(*) FROM hits WHERE ip_hash = ? AND at > ?');
    $count->execute([ip_hash(), time() - $window]);
    return (int) $count->fetchColumn() >= $max;
}

/**
 * Plafond global d'e-mails de confirmation sur une heure : borne l'usage du site comme relais d'envoi,
 * même depuis de nombreuses adresses IP.
 */
function mail_cap_reached(): bool
{
    $count = db()->prepare('SELECT COUNT(*) FROM signatures WHERE last_mail_at > ?');
    $count->execute([time() - 3600]);
    return (int) $count->fetchColumn() >= (int) (config()['mail_hourly_cap'] ?? MAIL_HOURLY_CAP);
}

/**
 * POST envoyé depuis un autre site (formulaire caché qui ferait soumettre les visiteurs à leur insu).
 * Sec-Fetch-Site fait foi quand le navigateur l'envoie ; sinon, un en-tête Origin étranger suffit à
 * refuser. Origin « null » est ignoré : avec Referrer-Policy no-referrer, certains navigateurs
 * l'envoient pour nos propres formulaires.
 */
function cross_site_post(): bool
{
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
    if ($site !== null) {
        return !in_array($site, ['same-origin', 'none'], true);
    }
    $origin = $_SERVER['HTTP_ORIGIN'] ?? 'null';
    if ($origin === 'null') {
        return false;
    }
    $base = parse_url(config()['base_url']);
    $own = $base['scheme'] . '://' . $base['host'] . (isset($base['port']) ? ':' . $base['port'] : '');
    return strcasecmp($origin, $own) !== 0;
}

function record_hit(): void
{
    db()->prepare('INSERT INTO hits (ip_hash, at) VALUES (?, ?)')->execute([ip_hash(), time()]);
}

// ---- Modération -------------------------------------------------------------------------------

const MODERATION_ACTIONS = ['valider', 'masquer', 'supprimer'];

/**
 * valider : publie la signature ; masquer : la garde (comptée) sans jamais publier le nom ;
 * supprimer : efface la signature et ses données (usurpation, abus), ou une demande non confirmée.
 * Vrai si une signature a été modifiée.
 */
function moderate(int $id, string $action): bool
{
    $sql = [
        'valider' => 'UPDATE signatures SET approved_at = :now WHERE id = :id AND confirmed_at IS NOT NULL',
        'masquer' => 'UPDATE signatures SET publier = 0, approved_at = :now WHERE id = :id AND confirmed_at IS NOT NULL',
        'supprimer' => 'DELETE FROM signatures WHERE id = :id',
    ][$action] ?? null;
    if ($sql === null) {
        return false;
    }
    $statement = db()->prepare($sql);
    $statement->execute($action === 'supprimer' ? ['id' => $id] : ['id' => $id, 'now' => time()]);
    return $statement->rowCount() === 1;
}

// ---- Adresse et organisation -----------------------------------------------------------------

const FREE_MAIL = ['gmail', 'googlemail', 'outlook', 'hotmail', 'live', 'msn', 'yahoo', 'ymail', 'icloud', 'me', 'mac', 'aol',
    'orange', 'wanadoo', 'free', 'sfr', 'neuf', 'laposte', 'bbox', 'numericable', 'club-internet', 'aliceadsl', 'protonmail', 'proton',
    'pm', 'tutanota', 'tuta', 'gmx', 'web', 'zoho', 'yandex', 'mail', 'posteo', 'mailo', 'ik', 'riseup', 'disroot', 'skynet', 'bluewin', 'libero'];
const GENERIC_LABELS = ['www', 'mail', 'mx', 'smtp', 'univ', 'uni', 'u', 'etu', 'etud', 'etudiant', 'student', 'students', 'staff',
    'gouv', 'gov', 'ac', 'co', 'com', 'org', 'net', 'edu', 'asso', 'fr', 'eu', 'be', 'ch', 'de'];

function ascii_fold(string $value): string
{
    return strtolower(strtr($value, ['à' => 'a', 'â' => 'a', 'ä' => 'a', 'á' => 'a', 'ã' => 'a', 'å' => 'a', 'ç' => 'c', 'é' => 'e', 'è' => 'e',
        'ê' => 'e', 'ë' => 'e', 'í' => 'i', 'ì' => 'i', 'î' => 'i', 'ï' => 'i', 'ñ' => 'n', 'ó' => 'o', 'ò' => 'o', 'ô' => 'o', 'ö' => 'o',
        'õ' => 'o', 'ú' => 'u', 'ù' => 'u', 'û' => 'u', 'ü' => 'u', 'ÿ' => 'y', 'œ' => 'oe', 'æ' => 'ae', 'À' => 'a', 'Â' => 'a', 'Ç' => 'c',
        'É' => 'e', 'È' => 'e', 'Ê' => 'e', 'Î' => 'i', 'Ï' => 'i', 'Ô' => 'o', 'Ö' => 'o', 'Û' => 'u', 'Ü' => 'u', 'Œ' => 'oe']));
}

/**
 * Estimation, pour la modération (jamais publiée), du rapport entre l'adresse e-mail et l'organisation déclarée :
 * [libellé, classe du badge]. « Correspond » quand un libellé significatif du domaine (inria dans inria.fr,
 * lyon1 dans univ-lyon1.fr) se retrouve dans le nom ou le sigle de l'organisation. Ce n'est pas une vérification :
 * n'importe qui peut déclarer n'importe quelle organisation, et un domaine peut avoir un autre nom que l'organisation.
 */
function email_org_hint(string $email, string $organisation): array
{
    $domain = strtolower(substr($email, strrpos($email, '@') + 1));
    $labels = explode('.', $domain);
    // Messagerie grand public : fournisseur suivi d'un suffixe court (gmail.com, yahoo.co.uk), pas mail.inria.fr.
    if (in_array($labels[0], FREE_MAIL, true) && count(array_filter(array_slice($labels, 1), static fn (string $l): bool => strlen($l) > 3)) === 0) {
        return ['Messagerie grand public', 'muted'];
    }
    if (trim($organisation) === '') {
        return ['Domaine professionnel, sans organisation déclarée', 'muted'];
    }
    $words = preg_split('/[^a-z0-9]+/', ascii_fold($organisation), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    $compact = implode('', $words);
    $acronym = implode('', array_map(static fn (string $w): string => $w[0],
        array_filter($words, static fn (string $w): bool => !in_array($w, ['de', 'du', 'des', 'la', 'le', 'les', 'l', 'd', 'et', 'en', 'of', 'the', 'and'], true))));
    foreach (preg_split('/[.-]/', implode('.', array_slice($labels, 0, -1))) ?: [] as $label) {
        if (strlen($label) >= 3 && !in_array($label, GENERIC_LABELS, true)
            && (str_contains($compact, $label) || str_starts_with($acronym, $label) || (strlen($compact) >= 4 && str_contains($label, $compact)))) {
            return ['Adresse de l’organisation déclarée', 'ok'];
        }
    }
    return ['Domaine différent de l’organisation déclarée', 'pending'];
}

/**
 * Récapitulatif des signatures à modérer, envoyé à l'adresse de contact (tâche quotidienne, ou
 * php bin/moderation.php recapitulatif). Renvoie le nombre de signatures en attente (0 : rien n'est envoyé).
 */
function moderation_digest(): int
{
    $rows = db()->query('SELECT id, email, prenom, nom, fonction, organisation, confirmed_at FROM signatures WHERE confirmed_at IS NOT NULL AND publier = 1 AND approved_at IS NULL ORDER BY confirmed_at')->fetchAll();
    if ($rows === []) {
        return 0;
    }
    $lines = [];
    foreach ($rows as $r) {
        $quality = implode(', ', array_filter([$r['fonction'], $r['organisation']], 'strlen'));
        $lines[] = "#{$r['id']} " . trim($r['prenom'] . ' ' . $r['nom']) . ($quality !== '' ? " — $quality" : '') . "\n"
            . "{$r['email']} : " . email_org_hint($r['email'], $r['organisation'])[0] . ', confirmée le ' . date('d/m/Y', (int) $r['confirmed_at']);
    }
    send_mail(config()['contact'], count($rows) . ' signature' . (count($rows) > 1 ? 's' : '') . ' à modérer',
        "Signatures confirmées, en attente de validation avant publication :\n\n" . implode("\n\n", $lines) . "\n\n"
        . "Valider (une à une ou par lot), masquer ou supprimer, avec la clé de sécurité :\n\n"
        . url('admin.php', ['f' => 'attente']) . "\n\nOTSPI — contact@otspi.org");
    return count($rows);
}

// ---- Validation ---------------------------------------------------------------------------------

function clean(string $value, int $max): ?string
{
    $value = trim(preg_replace('/\s+/u', ' ', $value) ?? '');
    // Refuse les caractères de contrôle (C0, C1), privés, les contrôles bidirectionnels et les espaces
    // de largeur nulle, qui permettraient de maquiller un nom dans la liste publique. ZWJ et ZWNJ restent
    // permis : certaines écritures en ont besoin. Refuse aussi les liens, ces champs étant recopiés dans
    // l'e-mail de confirmation envoyé à une adresse que l'on ne contrôle pas encore.
    if ($value === '' || mb_strlen($value) > $max
        || preg_match('/[\p{Cc}\p{Co}\p{Cs}\x{061C}\x{200B}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2069}\x{FEFF}<>]/u', $value)
        || preg_match('#://|www\.#i', $value)) {
        return null;
    }
    return $value;
}

function clean_optional(string $value, int $max): ?string
{
    return trim($value) === '' ? '' : clean($value, $max);
}

/**
 * Clé d'unicité d'une adresse : sans l'alias « +… » de la partie locale. ada+manifeste@example.org
 * reste l'adresse d'envoi, mais ne permet pas de signer une seconde fois après ada@example.org.
 */
function email_key(string $email): string
{
    $at = strrpos($email, '@');
    if ($at === false) {
        return $email;
    }
    $local = substr($email, 0, $at);
    $plus = strpos($local, '+');
    return ($plus === false || $plus === 0 ? $local : substr($local, 0, $plus)) . substr($email, $at);
}

/** Adresse d'un service d'e-mail jetable (src/disposable-domains.txt), domaine ou sous-domaine. */
function disposable_email(string $email): bool
{
    static $domains = null;
    $domains ??= array_flip(array_filter(array_map('trim', file(__DIR__ . '/disposable-domains.txt') ?: []),
        static fn (string $line): bool => $line !== '' && $line[0] !== '#'));
    $domain = strtolower(substr($email, strrpos($email, '@') + 1));
    for ($d = $domain; $d !== ''; $d = (string) substr($d, (int) strpos($d, '.') + 1)) {
        if (isset($domains[$d])) {
            return true;
        }
        if (!str_contains($d, '.')) {
            break;
        }
    }
    return false;
}

function valid_email(string $email): bool
{
    return strlen($email) <= 254 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false
        && !preg_match('/[\r\n]/', $email);
}

// ---- Courriels ----------------------------------------------------------------------------------

/**
 * Envoie un e-mail en deux versions (multipart/alternative) : le texte brut, rédigé dans src/texts.php, et un
 * habillage HTML qui en est tiré automatiquement (mail_html). $lang choisit les libellés des boutons.
 * $attachments : pièces jointes [nom de fichier => contenu] (multipart/mixed).
 */
function send_mail(string $to, string $subject, string $body, string $lang = 'fr', array $attachments = []): bool
{
    $from = config()['mail_from'];
    $boundary = 'otspi-' . bin2hex(random_bytes(12));
    $html = mail_html($subject, $body, $lang);
    $headers = [
        'From: ' . config()['mail_from_name'] . ' <' . $from . '>',
        'Reply-To: ' . config()['contact'],
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        'Auto-Submitted: auto-generated',
        'Date: ' . date('r'),
        'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . (parse_url(config()['base_url'], PHP_URL_HOST) ?: 'localhost') . '>',
    ];
    // Quoted-printable : aucune ligne ne dépasse la limite de SMTP (998 octets), même dans le HTML.
    $message = "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
        . quoted_printable_encode(str_replace("\n", "\r\n", $body)) . "\r\n"
        . "--$boundary\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
        . quoted_printable_encode($html) . "\r\n--$boundary--\r\n";
    if ($attachments !== []) {
        $mixed = 'otspi-' . bin2hex(random_bytes(12));
        $parts = "--$mixed\r\nContent-Type: multipart/alternative; boundary=\"$boundary\"\r\n\r\n" . $message;
        foreach ($attachments as $name => $content) {
            $parts .= "--$mixed\r\nContent-Type: application/octet-stream; name=\"$name\"\r\nContent-Transfer-Encoding: base64\r\n"
                . "Content-Disposition: attachment; filename=\"$name\"\r\n\r\n" . chunk_split(base64_encode($content), 76, "\r\n");
        }
        $message = $parts . "--$mixed--\r\n";
        $headers[3] = 'Content-Type: multipart/mixed; boundary="' . $mixed . '"';
    }
    $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    if (config()['mail_dry_run'] ?? false) {
        $log = config()['mail_log'] ?? '/dev/null';
        file_put_contents($log, "TO: $to\nSUBJECT: $subject\n\n$body\n---\n", FILE_APPEND);
        if ($log !== '/dev/null') {
            file_put_contents($log . '.html', "<!-- TO: $to -->\n$html\n", FILE_APPEND);
            foreach ($attachments as $name => $content) {
                // Mode essai uniquement : pièces jointes déposées à côté du journal, lisibles par les tests.
                $dir = dirname($log) . '/pieces-jointes';
                if (!is_dir($dir) && @mkdir($dir)) {
                    @chmod($dir, 0777);
                }
                file_put_contents($dir . '/' . basename((string) $name), $content);
            }
        }
        return true;
    }
    return mail($to, $encodedSubject, $message, implode("\r\n", $headers), '-f' . $from);
}

/** Libellé et style du bouton d'un lien de l'application, selon la page visée. */
function mail_button(string $link, string $lang): array
{
    $page = basename((string) parse_url($link, PHP_URL_PATH));
    $labels = [
        'confirm.php' => [['fr' => 'Confirmer ma signature', 'en' => 'Confirm my signature'], true],
        'preuve.php' => [['fr' => 'Voir ma preuve horodatée', 'en' => 'View my timestamped proof'], true],
        'withdraw.php' => [['fr' => 'Retirer ma signature', 'en' => 'Withdraw my signature'], false],
        'admin.php' => [['fr' => 'Ouvrir l’administration', 'en' => 'Open the administration'], true],
    ];
    [$label, $primary] = $labels[$page] ?? [['fr' => 'Ouvrir le lien', 'en' => 'Open the link'], true];
    return [$label[$lang] ?? $label['fr'], $primary];
}

/**
 * Habillage HTML d'un e-mail, tiré de son texte brut : paragraphes séparés par une ligne vide, récapitulatif
 * (lignes « ␣␣Libellé : valeur ») en tableau, lien seul sur sa ligne en bouton (adresse rappelée dessous), dernier
 * paragraphe « OTSPI — … » en signature. Styles en ligne, sans image ni ressource externe ; thème sombre pris
 * en charge par les messageries qui le permettent.
 */
function mail_html(string $subject, string $body, string $lang): string
{
    $navy = '#0f2042';
    $blocks = preg_split('/\n{2,}/', trim($body)) ?: [];
    $signature = '';
    if ($blocks !== [] && str_starts_with(end($blocks), 'OTSPI')) {
        $signature = array_pop($blocks);
    }
    $preheader = '';
    $content = '';
    foreach ($blocks as $block) {
        $lines = explode("\n", $block);
        if (preg_match('#^https?://\S+$#', $block) === 1) {
            [$label, $primary] = mail_button($block, $lang);
            $style = $primary
                ? "background:#ffcc00;color:$navy;border:2px solid #ffcc00"
                : "background:transparent;color:#003399;border:2px solid #003399";
            $content .= '<table role="presentation" cellspacing="0" cellpadding="0" style="margin:4px 0 22px"><tr><td class="btn-cell" style="border-radius:8px">'
                . '<a class="' . ($primary ? 'btn' : 'btn-alt') . '" href="' . h($block) . '" style="display:inline-block;padding:13px 22px;border-radius:8px;font-weight:700;font-size:16px;text-decoration:none;' . $style . '">' . h($label) . '</a>'
                . '</td></tr></table>'
                . '<p class="muted" style="margin:-12px 0 22px;font-size:12px;line-height:1.5;color:#64748b;word-break:break-all">'
                . ($lang === 'en' ? 'Or copy this address: ' : 'Ou copiez cette adresse : ') . h($block) . '</p>';
            continue;
        }
        if (count(array_filter($lines, static fn (string $l): bool => preg_match('/^  \S/', $l) === 1)) === count($lines)) {
            $rows = '';
            foreach ($lines as $line) {
                $parts = preg_split('/\s?: /u', trim($line), 2);
                $rows .= '<tr><td class="muted" style="padding:7px 12px 7px 0;color:#475569;font-size:14px;vertical-align:top;white-space:nowrap">' . h($parts[0]) . '</td>'
                    . '<td class="strong" style="padding:7px 0;color:#0f172a;font-size:15px;font-weight:600">' . h($parts[1] ?? '') . '</td></tr>';
            }
            $content .= '<table role="presentation" class="recap" cellspacing="0" cellpadding="0" style="width:100%;margin:0 0 22px;padding:12px 16px;border:1px solid #dbe2ee;border-radius:10px;background:#f8fafd">' . $rows . '</table>';
            continue;
        }
        $text = implode('<br>', array_map('h', $lines));
        if ($preheader === '' && !preg_match('/^(Bonjour|Hello),?$/', $block)) {
            $preheader = mb_substr(str_replace("\n", ' ', $block), 0, 140);
        }
        $content .= '<p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#0f172a" class="text">' . $text . '</p>';
    }
    $footer = $signature !== ''
        ? h(str_replace(' — ', ' · ', $signature))
        : 'OTSPI · contact@otspi.org';
    return '<!doctype html><html lang="' . h($lang) . '"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark">'
        . '<title>' . h($subject) . '</title>'
        . '<style>@media (prefers-color-scheme: dark){'
        . '.bg{background:#0b1222!important}.card{background:#14203a!important;border-color:#25324f!important}'
        . '.text,.strong{color:#e6ebf5!important}.muted{color:#a5b1c8!important}'
        . '.recap{background:#101a30!important;border-color:#25324f!important}'
        . '.btn-alt{color:#7ea2ff!important;border-color:#7ea2ff!important}.foot{color:#a5b1c8!important}}'
        . '@media (max-width:600px){.card{padding:24px 20px!important}}</style></head>'
        . '<body class="bg" style="margin:0;padding:0;background:#f5f7fb">'
        . '<div style="display:none;max-height:0;overflow:hidden;opacity:0">' . h($preheader) . '</div>'
        . '<table role="presentation" class="bg" width="100%" cellspacing="0" cellpadding="0" style="background:#f5f7fb"><tr><td align="center" style="padding:24px 12px">'
        . '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;font-family:system-ui,-apple-system,\'Segoe UI\',Roboto,\'Helvetica Neue\',Arial,sans-serif">'
        . '<tr><td style="background:' . $navy . ';border-radius:12px 12px 0 0;border-bottom:4px solid #ffcc00;padding:18px 28px">'
        . '<span style="font-size:22px;font-weight:800;letter-spacing:.06em;color:#ffffff">OTSPI</span>'
        . '<span style="display:block;margin-top:2px;font-size:12px;color:#c9d6ff">' . ($lang === 'en' ? 'Manifesto for a free and open digital identity' : 'Manifeste pour une identité numérique libre et ouverte') . '</span></td></tr>'
        . '<tr><td class="card" style="background:#ffffff;border:1px solid #dbe2ee;border-top:0;border-radius:0 0 12px 12px;padding:32px 28px 14px">'
        . '<h1 class="text" style="margin:0 0 20px;font-size:21px;line-height:1.35;color:' . $navy . '">' . h($subject) . '</h1>'
        . $content . '</td></tr>'
        . '<tr><td class="foot" align="center" style="padding:18px 12px;font-size:12px;line-height:1.6;color:#64748b">' . $footer
        . '<br><a href="https://www.otspi.org/" style="color:#64748b">www.otspi.org</a></td></tr>'
        . '</table></td></tr></table></body></html>';
}

/** E-mail de double consentement : récapitulatif et lien de confirmation, dans la langue de la demande. */
function send_confirmation(array $signature, string $token, string $lang): bool
{
    return send_mail($signature['email'], t('mail_confirm_subject', $lang), sprintf(t('mail_confirm_body', $lang),
        recap_text($signature, $lang), url('confirm.php', ['t' => $token, 'lang' => $lang])), $lang);
}

/**
 * Données qui seront enregistrées (et publiées si la personne l'a accepté), à relire avant de confirmer :
 * paires libellé / valeur, rendues en texte dans l'e-mail et en HTML sur la page de confirmation.
 */
function recap(array $signature, string $lang): array
{
    return [
        t('recap_firstname', $lang) => $signature['prenom'],
        t('recap_lastname', $lang) => $signature['nom'],
        t('recap_position', $lang) => $signature['fonction'] !== '' ? $signature['fonction'] : '—',
        t('recap_organisation', $lang) => $signature['organisation'] !== '' ? $signature['organisation'] : '—',
        t('recap_publish', $lang) => t($signature['publier'] ? 'yes' : 'no', $lang),
    ];
}

function recap_text(array $signature, string $lang): string
{
    $lines = [];
    foreach (recap($signature, $lang) as $label => $value) {
        $lines[] = '  ' . $label . ($lang === 'fr' ? ' : ' : ': ') . $value;
    }
    return implode("\n", $lines);
}

function recap_html(array $signature, string $lang): string
{
    $html = '<dl class="recap">';
    foreach (recap($signature, $lang) as $label => $value) {
        $html .= '<dt>' . h($label) . '</dt><dd>' . h($value) . '</dd>';
    }
    return $html . '</dl>';
}

function url(string $path, array $query = []): string
{
    $base = rtrim(config()['base_url'], '/');
    return $base . '/' . $path . ($query ? '?' . http_build_query($query) : '');
}

// ---- Textes -------------------------------------------------------------------------------------

function t(string $key, string $lang): string
{
    static $texts = null;
    $texts ??= require __DIR__ . '/texts.php';
    return $texts[$key][$lang] ?? $texts[$key]['fr'] ?? $key;
}

function back_to_form(string $lang): string
{
    return '<p><a class="button" href="index.php?lang=' . $lang . '">' . h(t('back_to_form', $lang)) . '</a></p>';
}

/**
 * $audience charge la mesure d'audience Matomo (sans cookie) : à réserver aux pages dont l'adresse ne porte
 * aucune donnée personnelle, donc jamais aux liens de confirmation, de retrait, de modération ou d'administration.
 * $script charge un script du site (chemin relatif à public/), par exemple celui des clés de sécurité.
 */
function page(string $title, string $body, string $lang, bool $wide = false, bool $audience = false, string $script = ''): void
{
    $stats = $audience ? ' https://stats.otspi.org' : '';
    header('Content-Type: text/html; charset=UTF-8');
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'$stats; "
        . ($audience ? "script-src 'self'$stats; connect-src$stats; " : ($script !== '' ? "script-src 'self'; " : ''))
        . "form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    echo '<!doctype html><html lang="' . h($lang) . '"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="robots" content="noindex"><title>' . h($title) . '</title>'
        . '<link rel="icon" href="assets/favicon.svg" type="image/svg+xml">'
        . '<link rel="stylesheet" href="style.css">'
        . ($audience ? '<script src="assets/analytics.js?v=2" defer></script>' : '')
        . ($script !== '' ? '<script src="' . h($script) . '" defer></script>' : '')
        . '</head><body>'
        . '<header class="site-header"><div class="inner"><a class="brand" href="' . h(t('site_url', $lang)) . '">'
        . '<img class="logo-light" src="assets/logo-horizontal.svg" alt="' . h(t('home_alt', $lang)) . '" width="216" height="48">'
        . '<img class="logo-dark" src="assets/logo-horizontal-dark.svg" alt="" width="216" height="48"></a></div></header>'
        . '<main' . ($wide ? ' class="wide"' : '') . '><div class="card">' . $body . '</div></main>'
        . '<footer class="site-footer"><div class="inner">'
        . '<a href="' . h(t('manifesto_url', $lang)) . '">' . h(t('manifesto_link', $lang)) . '</a>'
        . '<a href="' . h(t('legal_url', $lang)) . '">' . h(t('legal_link', $lang)) . '</a>'
        . '<a href="registre.php">' . h(t('registry_link', $lang)) . '</a>'
        . '<a href="mailto:contact@otspi.org">contact@otspi.org</a>'
        . '</div></footer></body></html>';
}
