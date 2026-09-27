<?php
// SPDX-License-Identifier: EUPL-1.2
// Clé de sécurité virtuelle (ES256) pour tests/flow.sh : lit sur l'entrée standard une page d'administration,
// en extrait les options WebAuthn du formulaire et écrit la réponse JSON que posterait assets/admin.js.
//   php tests/authenticator.php create FICHIER_CLE [défaut]   enregistrement (crée la clé dans FICHIER_CLE)
//   php tests/authenticator.php get FICHIER_CLE [défaut]      connexion
// défaut : sans-pin (vérification de l'utilisateur absente), origine (autre site), signature (altérée),
// compteur (compteur de signatures qui recule).

declare(strict_types=1);

[, $mode, $file] = $argv + [null, '', ''];
$fault = $argv[3] ?? '';
$origin = getenv('ORIGIN') ?: 'http://localhost:8090';

preg_match('/data-webauthn="' . $mode . '" data-options="([^"]*)"/', stream_get_contents(STDIN), $m) or exit("options absentes\n");
$options = json_decode(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5), true);

$b64u = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
$client = json_encode(['type' => $mode === 'create' ? 'webauthn.create' : 'webauthn.get', 'challenge' => $options['challenge'],
    'origin' => $fault === 'origine' ? 'https://evil.example' : $origin, 'crossOrigin' => false]);
$rpId = $options['rp']['id'] ?? $options['rpId'];
$flags = $fault === 'sans-pin' ? 0x01 : 0x05;

// Encodeur CBOR juste suffisant : entiers, chaînes d'octets (préfixe « b: ») et de texte, tables.
function cbor(mixed $v): string
{
    $head = static function (int $major, int $n): string {
        if ($n < 24) {
            return chr($major << 5 | $n);
        }
        return $n < 256 ? chr($major << 5 | 24) . chr($n) : chr($major << 5 | 25) . pack('n', $n);
    };
    if (is_int($v)) {
        return $v >= 0 ? $head(0, $v) : $head(1, -1 - $v);
    }
    if (is_string($v)) {
        return str_starts_with($v, 'b:') ? $head(2, strlen($v) - 2) . substr($v, 2) : $head(3, strlen($v)) . $v;
    }
    $out = $head(5, count($v));
    foreach ($v as $key => $item) {
        $out .= cbor($key) . cbor($item);
    }
    return $out;
}

if ($mode === 'create') {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $ec = openssl_pkey_get_details($key)['ec'];
    $id = random_bytes(32);
    openssl_pkey_export($key, $pem);
    $cose = cbor([1 => 2, 3 => -7, -1 => 1, -2 => 'b:' . str_pad($ec['x'], 32, "\0", STR_PAD_LEFT), -3 => 'b:' . str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)]);
    $authData = hash('sha256', $rpId, true) . chr($flags | 0x40) . pack('N', 0) . str_repeat("\x11", 16) . pack('n', 32) . $id . $cose;
    file_put_contents($file, json_encode(['pem' => $pem, 'id' => $b64u($id), 'count' => 0]));
    echo json_encode(['id' => $b64u($id), 'clientDataJSON' => $b64u($client), 'transports' => ['usb'],
        'attestationObject' => $b64u(cbor(['fmt' => 'none', 'attStmt' => [], 'authData' => 'b:' . $authData]))]);
    exit;
}

$stored = json_decode(file_get_contents($file), true);
$count = $fault === 'compteur' ? max(0, $stored['count'] - 1) : $stored['count'] + 1;
$authData = hash('sha256', $rpId, true) . chr($flags) . pack('N', $count);
openssl_sign($authData . hash('sha256', $client, true), $signature, $stored['pem'], OPENSSL_ALGO_SHA256);
if ($fault === 'signature') {
    $signature[10] = chr(ord($signature[10]) ^ 1);
}
if ($fault === '') {
    file_put_contents($file, json_encode(['count' => $count] + $stored));
}
echo json_encode(['id' => $stored['id'], 'clientDataJSON' => $b64u($client), 'authenticatorData' => $b64u($authData), 'signature' => $b64u($signature)]);
