<?php
// SPDX-License-Identifier: EUPL-1.2
// Bibliothèque de l'application de signature du manifeste OTSPI : configuration, base SQLite,
// jetons, limitation de débit, courriels et textes bilingues. Aucune dépendance externe.

declare(strict_types=1);

const CONFIRM_TTL = 172800;      // 48 h : validité du lien de confirmation
const UNCONFIRMED_TTL = 604800;  // 7 jours : durée de conservation d'une demande non confirmée
const MIN_FILL_SECONDS = 4;      // un humain met plus de 4 s à remplir le formulaire
const MAX_FILL_SECONDS = 7200;   // formulaire périmé au-delà de 2 h

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
    confirmed_at INTEGER
);
CREATE TABLE IF NOT EXISTS hits (
    ip_hash TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS hits_ip ON hits (ip_hash, at);
SQL);
    }
    return $pdo;
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

function record_hit(): void
{
    db()->prepare('INSERT INTO hits (ip_hash, at) VALUES (?, ?)')->execute([ip_hash(), time()]);
}

// ---- Validation ---------------------------------------------------------------------------------

function clean(string $value, int $max): ?string
{
    $value = trim(preg_replace('/\s+/u', ' ', $value) ?? '');
    if ($value === '' || mb_strlen($value) > $max || preg_match('/[\x00-\x1F\x7F<>]/u', $value)) {
        return null;
    }
    return $value;
}

function clean_optional(string $value, int $max): ?string
{
    return trim($value) === '' ? '' : clean($value, $max);
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
    ];
    $encodedSubject = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    if (config()['mail_dry_run'] ?? false) {
        file_put_contents(config()['mail_log'] ?? '/dev/null', "TO: $to\nSUBJECT: $subject\n\n$body\n---\n", FILE_APPEND);
        return true;
    }
    return mail($to, $encodedSubject, $body, implode("\r\n", $headers), '-f' . $from);
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

function page(string $title, string $body, string $lang): void
{
    header('Content-Type: text/html; charset=UTF-8');
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    echo '<!doctype html><html lang="' . h($lang) . '"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="robots" content="noindex"><title>' . h($title) . '</title>'
        . '<link rel="stylesheet" href="style.css"></head><body><main>' . $body . '</main></body></html>';
}
