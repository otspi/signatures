<?php
// SPDX-License-Identifier: EUPL-1.2
// Accès à l'administration par clé de sécurité (WebAuthn / FIDO2, une YubiKey par exemple), seule méthode de
// connexion. La clé doit vérifier son utilisateur (code PIN ou empreinte) : possession de la clé et PIN font
// deux facteurs. Une clé s'enregistre par un lien d'invitation à usage unique envoyé à la seule adresse de
// contact, ou depuis une session ouverte avec une clé déjà enregistrée. Sans dépendance : décodage CBOR,
// clés COSE converties en PEM et signatures vérifiées par OpenSSL.
//
// Jetons (table admin_tokens, empreintes HMAC seulement) : invitation (24 h, usage unique) et session
// (cookie HttpOnly, 30 min d'inactivité, 8 h au plus). Les défis WebAuthn (10 min) sont signés par HMAC et
// ne sont enregistrés qu'une fois utilisés, après une signature valide : afficher la page de connexion
// n'écrit rien en base.

declare(strict_types=1);

const ADMIN_INVITE_TTL = 86400;
const ADMIN_CHALLENGE_TTL = 600;
const ADMIN_SESSION_IDLE = 1800;
const ADMIN_SESSION_MAX = 28800;
const COSE_ES256 = -7;
const COSE_RS256 = -257;

final class PasskeyRefused extends RuntimeException
{
}

// ---- Jetons ------------------------------------------------------------------------------------

function b64url_encode(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

function b64url_decode(string $value): string
{
    $bytes = preg_match('/^[A-Za-z0-9_-]*$/', $value) === 1 ? base64_decode(strtr($value, '-_', '+/'), true) : false;
    if ($bytes === false) {
        throw new PasskeyRefused('base64url invalide');
    }
    return $bytes;
}

/** Crée un jeton à durée limitée et renvoie sa valeur ; seule son empreinte est conservée. */
function admin_token_issue(string $kind, int $ttl, string $ref = ''): string
{
    $pdo = db();
    $pdo->prepare('DELETE FROM admin_tokens WHERE expires_at < ?')->execute([time()]);
    $token = b64url_encode(random_bytes(32));
    $pdo->prepare('INSERT INTO admin_tokens (hash, kind, ref, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
        ->execute([token_hash($token), $kind, $ref, time(), time() + $ttl]);
    return $token;
}

function admin_token_find(string $kind, string $token): ?array
{
    if (preg_match('/^[A-Za-z0-9_-]{43}$/', $token) !== 1) {
        return null;
    }
    $row = db()->prepare('SELECT hash, ref, created_at, expires_at FROM admin_tokens WHERE hash = ? AND kind = ? AND expires_at >= ?');
    $row->execute([token_hash($token), $kind, time()]);
    return $row->fetch() ?: null;
}

/**
 * Défi WebAuthn : aléa, date d'émission et HMAC liant le défi à son usage (connexion, ou enregistrement
 * pour une invitation ou une session précise).
 */
function admin_challenge(string $kind, string $ref = ''): string
{
    $body = random_bytes(16) . pack('J', time());
    return b64url_encode($body . admin_challenge_mac($kind, $ref, $body));
}

function admin_challenge_mac(string $kind, string $ref, string $body): string
{
    return substr(hash_hmac('sha256', 'defi|' . $kind . '|' . $ref . '|' . $body, config()['secret'], true), 0, 16);
}

function admin_challenge_check(string $challenge, string $kind, string $ref): void
{
    $raw = b64url_decode($challenge);
    if (strlen($raw) !== 40 || !hash_equals(admin_challenge_mac($kind, $ref, substr($raw, 0, 24)), substr($raw, 24))) {
        throw new PasskeyRefused('défi invalide');
    }
    $issued = unpack('J', substr($raw, 16, 8))[1];
    if ($issued > time() || $issued < time() - ADMIN_CHALLENGE_TTL) {
        throw new PasskeyRefused('défi expiré');
    }
}

/** Marque un défi comme utilisé, une fois la réponse entièrement vérifiée : il ne sert qu'une fois. */
function admin_challenge_spend(string $challenge): void
{
    $insert = db()->prepare('INSERT OR IGNORE INTO admin_tokens (hash, kind, ref, created_at, expires_at) VALUES (?, ?, ?, ?, ?)');
    $insert->execute([token_hash($challenge), 'defi-utilise', '', time(), time() + ADMIN_CHALLENGE_TTL + 60]);
    if ($insert->rowCount() !== 1) {
        throw new PasskeyRefused('défi déjà utilisé');
    }
}

// ---- Invitations et sessions -------------------------------------------------------------------

function admin_key_count(): int
{
    return (int) db()->query('SELECT COUNT(*) FROM admin_keys')->fetchColumn();
}

/** Envoie à la seule adresse de contact un lien d'enregistrement de clé, valable 24 h et à usage unique. */
function admin_send_invitation(): bool
{
    $token = admin_token_issue('invitation', ADMIN_INVITE_TTL);
    return send_mail(config()['contact'], 'Enregistrer une clé de sécurité pour l’administration des signatures',
        "Lien d'enregistrement d'une clé de sécurité (YubiKey) pour l'administration des signatures du manifeste,\n"
        . "valable 24 heures (jusqu'au " . date('d/m/Y à H:i', time() + ADMIN_INVITE_TTL) . ") et utilisable une seule fois :\n\n"
        . url('admin.php', ['inv' => $token]) . "\n\n"
        . "Ouvrez-le sur l'ordinateur où la clé est branchée, puis suivez les indications du navigateur : la clé\n"
        . "demandera son code PIN (à créer s'il n'existe pas encore). La connexion se fera ensuite uniquement avec\n"
        . "cette clé et son code PIN.\n\n"
        . "Si vous n'avez rien demandé, ne l'ouvrez pas : le lien expirera de lui-même.\n");
}

function admin_cookie_name(): string
{
    // Le préfixe __Host- (cookie lié à l'hôte, Secure, Path=/) n'est possible qu'en HTTPS.
    return admin_https() ? '__Host-otspi-admin' : 'otspi-admin';
}

function admin_https(): bool
{
    return parse_url(config()['base_url'], PHP_URL_SCHEME) === 'https';
}

function admin_set_cookie(string $value, int $expires): void
{
    setcookie(admin_cookie_name(), $value, ['expires' => $expires, 'path' => '/', 'secure' => admin_https(),
        'httponly' => true, 'samesite' => 'Lax']);
}

function admin_login(int $keyId): void
{
    admin_set_cookie(admin_token_issue('session', ADMIN_SESSION_MAX, (string) $keyId), 0);
}

/**
 * Session d'administration en cours, ou null. L'inactivité est bornée par created_at, renouvelé à chaque
 * requête (au plus une fois par minute) ; expires_at borne la durée totale.
 */
function admin_session(): ?array
{
    $session = admin_token_find('session', (string) ($_COOKIE[admin_cookie_name()] ?? ''));
    if ($session === null || (int) $session['created_at'] < time() - ADMIN_SESSION_IDLE) {
        return null;
    }
    if ((int) $session['created_at'] < time() - 60) {
        db()->prepare('UPDATE admin_tokens SET created_at = ? WHERE hash = ?')->execute([time(), $session['hash']]);
    }
    return $session;
}

function admin_logout(): void
{
    $session = admin_token_find('session', (string) ($_COOKIE[admin_cookie_name()] ?? ''));
    if ($session !== null) {
        db()->prepare('DELETE FROM admin_tokens WHERE hash = ?')->execute([$session['hash']]);
    }
    admin_set_cookie('', 1);
}

// ---- Options transmises au navigateur ----------------------------------------------------------

function admin_origin(): string
{
    $base = parse_url(config()['base_url']);
    return $base['scheme'] . '://' . $base['host'] . (isset($base['port']) ? ':' . $base['port'] : '');
}

function admin_rp_id(): string
{
    return (string) parse_url(config()['base_url'], PHP_URL_HOST);
}

function admin_credentials(): array
{
    return array_map(static fn (array $key): array => ['type' => 'public-key', 'id' => $key['credential_id'],
        'transports' => json_decode($key['transports'], true) ?: []],
        db()->query('SELECT credential_id, transports FROM admin_keys')->fetchAll());
}

/** Options de navigator.credentials.create() : clé externe, vérification de l'utilisateur exigée. */
function admin_creation_options(string $challenge): array
{
    return [
        'challenge' => $challenge,
        'rp' => ['id' => admin_rp_id(), 'name' => 'OTSPI — administration des signatures'],
        'user' => ['id' => b64url_encode(substr(hash_hmac('sha256', 'admin-user', config()['secret'], true), 0, 16)),
            'name' => config()['contact'], 'displayName' => 'Administration des signatures'],
        'pubKeyCredParams' => [['type' => 'public-key', 'alg' => COSE_ES256], ['type' => 'public-key', 'alg' => COSE_RS256]],
        'authenticatorSelection' => ['authenticatorAttachment' => 'cross-platform', 'residentKey' => 'discouraged',
            'requireResidentKey' => false, 'userVerification' => 'required'],
        // « direct » : le navigateur transmet l'AAGUID (modèle de la clé), contrôlé si admin_aaguids est renseigné.
        'attestation' => 'direct',
        'excludeCredentials' => admin_credentials(),
        'hints' => ['security-key'],
        'timeout' => 120000,
    ];
}

function admin_request_options(string $challenge): array
{
    return [
        'challenge' => $challenge,
        'rpId' => admin_rp_id(),
        'allowCredentials' => admin_credentials(),
        'userVerification' => 'required',
        'hints' => ['security-key'],
        'timeout' => 120000,
    ];
}

// ---- Vérification des réponses de la clé -------------------------------------------------------

/**
 * Vérifie une réponse d'enregistrement (navigator.credentials.create) dont le défi a été émis pour $ref
 * (invitation ou session), consomme ce défi et renvoie la clé à enregistrer.
 */
function passkey_verify_registration(array $response, string $ref): array
{
    $clientJson = b64url_decode((string) ($response['clientDataJSON'] ?? ''));
    $challenge = passkey_client_data($clientJson, 'webauthn.create', 'cle', $ref);
    $offset = 0;
    $attestation = cbor_decode(b64url_decode((string) ($response['attestationObject'] ?? '')), $offset);
    if (!is_array($attestation) || !is_string($attestation['authData'] ?? null)) {
        throw new PasskeyRefused('objet d\'attestation invalide');
    }
    $auth = passkey_auth_data($attestation['authData'], true);
    if (!hash_equals($auth['credential_id'], b64url_decode((string) ($response['id'] ?? '')))) {
        throw new PasskeyRefused('identifiant de clé incohérent');
    }
    $allowed = array_map('strtolower', config()['admin_aaguids'] ?? []);
    if ($allowed !== [] && !in_array($auth['aaguid'], $allowed, true)) {
        throw new PasskeyRefused('modèle de clé non autorisé (AAGUID ' . $auth['aaguid'] . ')');
    }
    admin_challenge_spend($challenge);
    $transports = array_values(array_filter((array) ($response['transports'] ?? []),
        static fn ($t): bool => is_string($t) && preg_match('/^[a-z-]{2,20}$/', $t) === 1));
    return [
        'credential_id' => b64url_encode($auth['credential_id']),
        'public_key' => cose_to_pem($auth['cose']),
        'sign_count' => $auth['sign_count'],
        'aaguid' => $auth['aaguid'],
        'transports' => json_encode($transports),
    ];
}

/** Vérifie une réponse de connexion (navigator.credentials.get), consomme son défi et renvoie la clé utilisée. */
function passkey_verify_login(array $response): array
{
    $clientJson = b64url_decode((string) ($response['clientDataJSON'] ?? ''));
    $challenge = passkey_client_data($clientJson, 'webauthn.get', 'connexion', '');
    $row = db()->prepare('SELECT id, name, public_key, sign_count FROM admin_keys WHERE credential_id = ?');
    $row->execute([b64url_encode(b64url_decode((string) ($response['id'] ?? '')))]);
    $key = $row->fetch();
    if ($key === false) {
        throw new PasskeyRefused('clé inconnue');
    }
    $authData = b64url_decode((string) ($response['authenticatorData'] ?? ''));
    $auth = passkey_auth_data($authData, false);
    $signed = $authData . hash('sha256', $clientJson, true);
    if (openssl_verify($signed, b64url_decode((string) ($response['signature'] ?? '')), $key['public_key'], OPENSSL_ALGO_SHA256) !== 1) {
        throw new PasskeyRefused('signature invalide (clé #' . $key['id'] . ')');
    }
    admin_challenge_spend($challenge);
    // Compteur de signatures : s'il ne progresse pas, la clé a peut-être été clonée.
    if (($auth['sign_count'] > 0 || (int) $key['sign_count'] > 0) && $auth['sign_count'] <= (int) $key['sign_count']) {
        throw new PasskeyRefused('compteur de signatures en recul (clé #' . $key['id'] . ', clonage possible)');
    }
    db()->prepare('UPDATE admin_keys SET sign_count = ?, last_used_at = ? WHERE id = ?')->execute([$auth['sign_count'], time(), $key['id']]);
    return $key;
}

/** Contrôle clientDataJSON (type, origine, défi émis par ce site pour cet usage) et renvoie le défi. */
function passkey_client_data(string $json, string $type, string $kind, string $ref): string
{
    $client = json_decode($json, true);
    if (!is_array($client) || ($client['type'] ?? null) !== $type || !is_string($client['challenge'] ?? null)) {
        throw new PasskeyRefused('clientDataJSON invalide');
    }
    if (($client['origin'] ?? null) !== admin_origin() || ($client['crossOrigin'] ?? false) === true) {
        throw new PasskeyRefused('origine refusée : ' . (is_string($client['origin'] ?? null) ? $client['origin'] : '-'));
    }
    admin_challenge_check($client['challenge'], $kind, $ref);
    return $client['challenge'];
}

/** Données d'authentification : identifiant de la partie de confiance, présence et vérification de l'utilisateur. */
function passkey_auth_data(string $raw, bool $withCredential): array
{
    if (strlen($raw) < 37) {
        throw new PasskeyRefused('authenticatorData trop court');
    }
    if (!hash_equals(hash('sha256', admin_rp_id(), true), substr($raw, 0, 32))) {
        throw new PasskeyRefused('rpIdHash incorrect');
    }
    $flags = ord($raw[32]);
    // 0x01 : présence (la clé a été touchée) ; 0x04 : vérification (PIN ou biométrie).
    if (($flags & 0x05) !== 0x05) {
        throw new PasskeyRefused('présence ou vérification de l\'utilisateur absente');
    }
    $data = ['sign_count' => unpack('N', substr($raw, 33, 4))[1]];
    if ($withCredential) {
        if (($flags & 0x40) === 0 || strlen($raw) < 55) {
            throw new PasskeyRefused('données de clé absentes');
        }
        $length = unpack('n', substr($raw, 53, 2))[1];
        $data['aaguid'] = implode('-', sscanf(bin2hex(substr($raw, 37, 16)), '%8s%4s%4s%4s%12s'));
        $data['credential_id'] = substr($raw, 55, $length);
        if ($length === 0 || strlen($data['credential_id']) !== $length) {
            throw new PasskeyRefused('identifiant de clé tronqué');
        }
        $offset = 55 + $length;
        $data['cose'] = cbor_decode($raw, $offset);
        if (!is_array($data['cose'])) {
            throw new PasskeyRefused('clé publique COSE invalide');
        }
    }
    return $data;
}

// ---- CBOR, COSE, DER ---------------------------------------------------------------------------

/** Décodeur CBOR minimal (RFC 8949) : entiers, chaînes, tableaux, tables, étiquettes, booléens et null. */
function cbor_decode(string $data, int &$offset): mixed
{
    $head = ord(cbor_take($data, $offset, 1));
    $major = $head >> 5;
    $info = $head & 0x1f;
    if ($major === 7) {
        return match ($info) {
            20 => false, 21 => true, 22 => null,
            default => throw new PasskeyRefused('CBOR : valeur simple non prise en charge'),
        };
    }
    if ($info < 24) {
        $value = $info;
    } elseif ($info <= 27) {
        $value = 0;
        foreach (str_split(cbor_take($data, $offset, 1 << ($info - 24))) as $byte) {
            $value = ($value << 8) | ord($byte);
        }
        if ($value < 0) {
            throw new PasskeyRefused('CBOR : entier trop grand');
        }
    } else {
        throw new PasskeyRefused('CBOR : longueur indéfinie non prise en charge');
    }
    switch ($major) {
        case 0:
            return $value;
        case 1:
            return -1 - $value;
        case 2:
        case 3:
            return cbor_take($data, $offset, $value);
        case 4:
        case 5:
            // Chaque élément occupe au moins un octet : une longueur plus grande que le reste est fausse.
            if ($value > strlen($data) - $offset) {
                throw new PasskeyRefused('CBOR : longueur incohérente');
            }
            $items = [];
            for ($i = 0; $i < $value; $i++) {
                if ($major === 4) {
                    $items[] = cbor_decode($data, $offset);
                } else {
                    $key = cbor_decode($data, $offset);
                    if (!is_int($key) && !is_string($key)) {
                        throw new PasskeyRefused('CBOR : clé de table invalide');
                    }
                    $items[$key] = cbor_decode($data, $offset);
                }
            }
            return $items;
        default:
            return cbor_decode($data, $offset); // étiquette (6) : seule la valeur compte ici
    }
}

function cbor_take(string $data, int &$offset, int $length): string
{
    if ($length > strlen($data) - $offset) {
        throw new PasskeyRefused('CBOR tronqué');
    }
    $bytes = substr($data, $offset, $length);
    $offset += $length;
    return $bytes;
}

/** Clé publique COSE (ES256 sur P-256 ou RS256) convertie en PEM SubjectPublicKeyInfo pour OpenSSL. */
function cose_to_pem(array $cose): string
{
    $kty = $cose[1] ?? null;
    $alg = $cose[3] ?? null;
    if ($kty === 2 && $alg === COSE_ES256 && ($cose[-1] ?? null) === 1
        && is_string($cose[-2] ?? null) && strlen($cose[-2]) === 32 && is_string($cose[-3] ?? null) && strlen($cose[-3]) === 32) {
        // SEQUENCE { id-ecPublicKey, prime256v1 } puis BIT STRING du point non compressé.
        $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $cose[-2] . $cose[-3];
    } elseif ($kty === 3 && $alg === COSE_RS256 && is_string($cose[-1] ?? null) && is_string($cose[-2] ?? null)) {
        $rsa = der_sequence(der_integer($cose[-1]) . der_integer($cose[-2]));
        $der = der_sequence(der_sequence(hex2bin('06092a864886f70d010101') . "\x05\x00")
            . "\x03" . der_length(strlen($rsa) + 1) . "\x00" . $rsa);
    } else {
        throw new PasskeyRefused('algorithme de clé non pris en charge');
    }
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    if (openssl_pkey_get_public($pem) === false) {
        throw new PasskeyRefused('clé publique illisible');
    }
    return $pem;
}

function der_length(int $length): string
{
    if ($length < 0x80) {
        return chr($length);
    }
    $bytes = ltrim(pack('N', $length), "\0");
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function der_sequence(string $content): string
{
    return "\x30" . der_length(strlen($content)) . $content;
}

function der_integer(string $unsigned): string
{
    $value = ltrim($unsigned, "\0");
    if ($value === '' || ord($value[0]) & 0x80) {
        $value = "\0" . $value;
    }
    return "\x02" . der_length(strlen($value)) . $value;
}
