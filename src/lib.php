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
SQL);
        migrate($pdo);
        $pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS signatures_email_key ON signatures (email_key)');
    }
    return $pdo;
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

/** Jeton de formulaire signé : horodatage + HMAC (aucune session, aucun cookie). */
function form_token(): string
{
    $ts = (string) time();
    return $ts . '.' . hash_hmac('sha256', 'form|' . $ts, config()['secret']);
}

function form_token_state(string $token): string
{
    $parts = explode('.', $token, 2);
    if (count($parts) !== 2 || !ctype_digit($parts[0])) {
        return 'invalid';
    }
    $expected = hash_hmac('sha256', 'form|' . $parts[0], config()['secret']);
    if (!hash_equals($expected, $parts[1])) {
        return 'invalid';
    }
    $age = time() - (int) $parts[0];
    if ($age < MIN_FILL_SECONDS) {
        return 'too_fast';
    }
    return $age > MAX_FILL_SECONDS ? 'expired' : 'ok';
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
 * Jeton du lien de modération envoyé à l'adresse de contact : HMAC lié à la signature (identifiant et
 * date de la demande), sans stockage ; il cesse de fonctionner quand la signature est supprimée.
 */
function moderation_token(int $id, int $createdAt): string
{
    return hash_hmac('sha256', 'moderation|' . $id . '|' . $createdAt, config()['secret']);
}

/**
 * valider : publie la signature ; masquer : la garde (comptée) sans jamais publier le nom ;
 * supprimer : efface la signature et ses données (usurpation, abus). Vrai si une signature confirmée
 * a été modifiée.
 */
function moderate(int $id, string $action): bool
{
    $sql = [
        'valider' => 'UPDATE signatures SET approved_at = :now WHERE id = :id AND confirmed_at IS NOT NULL',
        'masquer' => 'UPDATE signatures SET publier = 0, approved_at = :now WHERE id = :id AND confirmed_at IS NOT NULL',
        'supprimer' => 'DELETE FROM signatures WHERE id = :id AND confirmed_at IS NOT NULL',
    ][$action] ?? null;
    if ($sql === null) {
        return false;
    }
    $statement = db()->prepare($sql);
    $statement->execute($action === 'supprimer' ? ['id' => $id] : ['id' => $id, 'now' => time()]);
    return $statement->rowCount() === 1;
}

// ---- Administration ----------------------------------------------------------------------------

const ADMIN_TTL = 1800;          // 30 min : validité d'un lien d'accès à l'administration

/** Jeton du lien d'accès à l'administration, envoyé à la seule adresse de contact : HMAC de l'échéance. */
function admin_token(int $expires): string
{
    return hash_hmac('sha256', 'admin|' . $expires, config()['secret']);
}

function admin_access_ok(string $expires, string $token): bool
{
    return ctype_digit($expires) && (int) $expires >= time() && (int) $expires <= time() + ADMIN_TTL
        && preg_match('/^[0-9a-f]{64}$/', $token) === 1 && hash_equals(admin_token((int) $expires), $token);
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

function valid_email(string $email): bool
{
    return strlen($email) <= 254 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false
        && !preg_match('/[\r\n]/', $email);
}

// ---- Courriels ----------------------------------------------------------------------------------

function send_mail(string $to, string $subject, string $body): bool
{
    $from = config()['mail_from'];
    $headers = [
        'From: ' . config()['mail_from_name'] . ' <' . $from . '>',
        'Reply-To: ' . config()['contact'],
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
        'Auto-Submitted: auto-generated',
        'Date: ' . date('r'),
        'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . (parse_url(config()['base_url'], PHP_URL_HOST) ?: 'localhost') . '>',
    ];
    $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    if (config()['mail_dry_run'] ?? false) {
        file_put_contents(config()['mail_log'] ?? '/dev/null', "TO: $to\nSUBJECT: $subject\n\n$body\n---\n", FILE_APPEND);
        return true;
    }
    return mail($to, $encodedSubject, $body, implode("\r\n", $headers), '-f' . $from);
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
 */
function page(string $title, string $body, string $lang, bool $wide = false, bool $audience = false): void
{
    $stats = $audience ? ' https://stats.otspi.org' : '';
    header('Content-Type: text/html; charset=UTF-8');
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'$stats; "
        . ($audience ? "script-src 'self'$stats; connect-src$stats; " : '')
        . "form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    echo '<!doctype html><html lang="' . h($lang) . '"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="robots" content="noindex"><title>' . h($title) . '</title>'
        . '<link rel="icon" href="assets/favicon.svg" type="image/svg+xml">'
        . '<link rel="stylesheet" href="style.css">'
        . ($audience ? '<script src="assets/analytics.js" defer></script>' : '')
        . '</head><body>'
        . '<header class="site-header"><div class="inner"><a class="brand" href="' . h(t('site_url', $lang)) . '">'
        . '<img class="logo-light" src="assets/logo-horizontal.svg" alt="' . h(t('home_alt', $lang)) . '" width="216" height="48">'
        . '<img class="logo-dark" src="assets/logo-horizontal-dark.svg" alt="" width="216" height="48"></a></div></header>'
        . '<main' . ($wide ? ' class="wide"' : '') . '><div class="card">' . $body . '</div></main>'
        . '<footer class="site-footer"><div class="inner">'
        . '<a href="' . h(t('manifesto_url', $lang)) . '">' . h(t('manifesto_link', $lang)) . '</a>'
        . '<a href="' . h(t('legal_url', $lang)) . '">' . h(t('legal_link', $lang)) . '</a>'
        . '<a href="mailto:contact@otspi.org">contact@otspi.org</a>'
        . '</div></footer></body></html>';
}
