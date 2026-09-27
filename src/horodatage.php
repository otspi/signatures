<?php
// SPDX-License-Identifier: EUPL-1.2
// Horodatage des signatures par l'autorité d'horodatage (RFC 3161) de STAGING d'OTSPI
// (api.staging.open-eidas.eu) : à la confirmation, une attestation JSON de la signature est figée, son empreinte
// SHA-256 est horodatée, et la personne reçoit un lien vers sa preuve (public/preuve.php). Le jeton est vérifié
// sans dépendance : lecture DER, signature CMS de l'unité d'horodatage, empreinte, usage « Time Stamping » et
// émission par un certificat épinglé (src/tsa-staging-ca.pem). Staging : preuve non qualifiée, sans valeur juridique.

declare(strict_types=1);

const TSA_TIMEOUT = 5;            // secondes : la confirmation n'attend pas plus ; sinon, le cron réessaie
const PROOF_MAILS_PER_RUN = 100;  // e-mails de preuve envoyés au plus par passage du cron (signatures antérieures)
const MANIFESTO_URL = 'https://www.otspi.org/manifeste.html';

final class TimestampInvalid extends RuntimeException
{
}

function tsa_url(): string
{
    return rtrim((string) (config()['tsa_url'] ?? 'https://api.staging.open-eidas.eu'), '/');
}

/**
 * Attestation figée de la signature, dont l'empreinte est horodatée : ni adresse e-mail ni jeton, et un sel
 * aléatoire, pour que l'empreinte ne permette pas de retrouver qui a signé.
 */
function attestation(array $signature): string
{
    return json_encode([
        'objet' => 'Signature du manifeste pour une identité numérique libre et ouverte',
        'manifeste' => MANIFESTO_URL,
        'signature' => (int) $signature['id'],
        'prenom' => $signature['prenom'],
        'nom' => $signature['nom'],
        'fonction' => $signature['fonction'],
        'organisation' => $signature['organisation'],
        'publication_demandee' => (int) $signature['publier'] === 1,
        'confirmee_le' => gmdate('Y-m-d\TH:i:s\Z', (int) $signature['confirmed_at']),
        'sel' => bin2hex(random_bytes(16)),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
}

/** Crée le lien de preuve d'une signature confirmée (nouveau jeton d'accès) et fige son attestation si besoin. */
function proof_link(array $signature): string
{
    $token = new_token();
    db()->prepare('UPDATE signatures SET proof_hash = ?, proof_json = COALESCE(proof_json, ?) WHERE id = ?')
        ->execute([token_hash($token), attestation($signature), $signature['id']]);
    return url('preuve.php', ['t' => $token, 'lang' => $signature['lang'] === 'en' ? 'en' : 'fr']);
}

/** Horodate l'attestation d'une signature confirmée, si ce n'est pas déjà fait. Vrai si elle est horodatée. */
function timestamp_signature(int $id): bool
{
    $row = db()->prepare('SELECT id, prenom, nom, fonction, organisation, publier, confirmed_at, proof_json, proof_token FROM signatures WHERE id = ? AND confirmed_at IS NOT NULL');
    $row->execute([$id]);
    $signature = $row->fetch();
    if ($signature === false || tsa_url() === '') {
        return false;
    }
    if ($signature['proof_token'] !== null) {
        return true;
    }
    if ($signature['proof_json'] === null) {
        $signature['proof_json'] = attestation($signature);
        db()->prepare('UPDATE signatures SET proof_json = ? WHERE id = ? AND proof_json IS NULL')->execute([$signature['proof_json'], $id]);
        $signature['proof_json'] = db()->query('SELECT proof_json FROM signatures WHERE id = ' . $id)->fetchColumn();
    }
    try {
        $response = tsa_request(hash('sha256', $signature['proof_json']));
        $details = tsa_verify($response, hash('sha256', $signature['proof_json'], true));
    } catch (TimestampInvalid $e) {
        error_log('otspi-signatures : horodatage de la signature #' . $id . ' impossible (' . $e->getMessage() . ')');
        return false;
    }
    db()->prepare('UPDATE signatures SET proof_token = ?, proof_at = ? WHERE id = ?')->execute([base64_encode($response), $details['gen_time'], $id]);
    return true;
}

/**
 * Rattrapage (cron quotidien, php bin/horodatage.php) : horodate les signatures confirmées qui ne le sont pas
 * encore (autorité injoignable à la confirmation, signatures antérieures), puis envoie leur preuve à celles qui
 * ne l'ont jamais reçue (signatures antérieures à l'horodatage), au plus PROOF_MAILS_PER_RUN par passage.
 */
function proof_catch_up(): array
{
    $done = ['horodatees' => 0, 'echecs' => 0, 'envoyees' => 0];
    foreach (db()->query('SELECT id FROM signatures WHERE confirmed_at IS NOT NULL AND proof_token IS NULL ORDER BY id LIMIT 500')->fetchAll(PDO::FETCH_COLUMN) as $id) {
        $done[timestamp_signature((int) $id) ? 'horodatees' : 'echecs']++;
    }
    $rows = db()->prepare('SELECT id, email, prenom, nom, fonction, organisation, publier, lang, confirmed_at FROM signatures WHERE proof_token IS NOT NULL AND proof_mailed_at IS NULL ORDER BY id LIMIT ?');
    $rows->execute([PROOF_MAILS_PER_RUN]);
    foreach ($rows->fetchAll() as $signature) {
        $lang = $signature['lang'] === 'en' ? 'en' : 'fr';
        $claim = db()->prepare('UPDATE signatures SET proof_mailed_at = ? WHERE id = ? AND proof_mailed_at IS NULL');
        $claim->execute([time(), $signature['id']]);
        if ($claim->rowCount() === 1 && send_mail($signature['email'], t('mail_proof_subject', $lang), sprintf(t('mail_proof_body', $lang), proof_link($signature)))) {
            $done['envoyees']++;
        }
    }
    return $done;
}

/** Demande un jeton à l'autorité d'horodatage (API JSON) ; renvoie la TimeStampResp DER. */
function tsa_request(string $hashHex): string
{
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
        'content' => json_encode(['hash' => $hashHex, 'algorithm' => 'sha256', 'nonce' => true]),
        'timeout' => TSA_TIMEOUT,
        'ignore_errors' => true,
    ]]);
    $body = @file_get_contents(tsa_url() . '/api/v1/timestamp', false, $context);
    $data = is_string($body) ? json_decode($body, true) : null;
    if (!is_array($data) || ($data['granted'] ?? false) !== true || !is_string($data['token'] ?? null)) {
        throw new TimestampInvalid(is_array($data) && is_string($data['error'] ?? null) ? $data['error'] : 'autorité injoignable ou réponse invalide');
    }
    $der = base64_decode($data['token'], true);
    if ($der === false) {
        throw new TimestampInvalid('jeton non décodable');
    }
    return $der;
}

// ---- Vérification du jeton ---------------------------------------------------------------------

/**
 * Vérifie une TimeStampResp (RFC 3161) pour l'empreinte attendue et renvoie ses informations : date certifiée,
 * numéro de série, politique, unité d'horodatage. Exception au moindre écart.
 */
function tsa_verify(string $response, string $expectedDigest): array
{
    [$status, $token] = asn1_children(asn1_one($response, 0x30)) + [null, null];
    $code = asn1_children($status[1] ?? '')[0] ?? null;
    if ($token === null || $code === null || $code[0] !== 0x02 || !in_array(ord($code[1]), [0, 1], true)) {
        throw new TimestampInvalid('horodatage refusé par l\'autorité');
    }
    [$contentType, $wrapped] = asn1_children($token[1]) + [null, null];
    if (asn1_oid($contentType) !== '1.2.840.113549.1.7.2' || $wrapped[0] !== 0xA0) {
        throw new TimestampInvalid('jeton : SignedData attendu');
    }
    $signedData = asn1_children(asn1_one($wrapped[1], 0x30));
    $encap = asn1_children($signedData[2][1] ?? '');
    if (asn1_oid($encap[0] ?? null) !== '1.2.840.113549.1.9.16.1.4' || ($encap[1][0] ?? null) !== 0xA0) {
        throw new TimestampInvalid('jeton : TSTInfo attendu');
    }
    $tstInfoDer = asn1_one($encap[1][1], 0x04);
    $certificates = [];
    foreach (array_slice($signedData, 3) as $part) {
        if ($part[0] === 0xA0) {
            foreach (asn1_children($part[1]) as $cert) {
                $certificates[] = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($cert[2]), 64, "\n") . "-----END CERTIFICATE-----\n";
            }
        }
    }
    $signerInfos = end($signedData);
    $signer = asn1_children(asn1_children($signerInfos[1])[0][1] ?? '');
    $digestAlgorithm = asn1_digest(asn1_children($signer[2][1] ?? '')[0] ?? null);
    $attributes = $signer[3] ?? null;
    if ($attributes === null || $attributes[0] !== 0xA0 || ($signer[5][0] ?? null) !== 0x04) {
        throw new TimestampInvalid('jeton : attributs signés absents');
    }
    // L'empreinte signée porte sur les attributs encodés en SET (RFC 5652 §5.4).
    $messageDigest = null;
    foreach (asn1_children($attributes[1]) as $attribute) {
        [$type, $values] = asn1_children($attribute[1]) + [null, null];
        if (asn1_oid($type) === '1.2.840.113549.1.9.4') {
            $messageDigest = asn1_one(asn1_children($values[1])[0][2] ?? '', 0x04);
        }
    }
    if ($messageDigest === null || !hash_equals(hash($digestAlgorithm, $tstInfoDer, true), $messageDigest)) {
        throw new TimestampInvalid('jeton : empreinte du TSTInfo incorrecte');
    }
    $signedAttributes = "\x31" . substr($attributes[2], 1);
    $signerCert = null;
    foreach ($certificates as $cert) {
        if (openssl_verify($signedAttributes, $signer[5][1], $cert, $digestAlgorithm) === 1) {
            $signerCert = $cert;
            break;
        }
    }
    if ($signerCert === null) {
        throw new TimestampInvalid('signature de l\'unité d\'horodatage invalide');
    }

    $tst = asn1_children(asn1_one($tstInfoDer, 0x30));
    $imprint = asn1_children($tst[2][1] ?? '');
    if (asn1_digest(asn1_children($imprint[0][1] ?? '')[0] ?? null) !== 'sha256'
        || !hash_equals($expectedDigest, asn1_one($imprint[1][2] ?? '', 0x04))) {
        throw new TimestampInvalid('le jeton ne porte pas sur cette attestation');
    }
    if (($tst[4][0] ?? null) !== 0x18
        || preg_match('/^(\d{14})(?:\.(\d{1,6}))?Z$/', $tst[4][1], $time) !== 1) {
        throw new TimestampInvalid('date d\'horodatage illisible');
    }
    $genTime = DateTimeImmutable::createFromFormat('!YmdHis', $time[1], new DateTimeZone('UTC'));

    $signerInfo = openssl_x509_parse($signerCert);
    if ($genTime === false || $signerInfo === false
        || !str_contains((string) ($signerInfo['extensions']['extendedKeyUsage'] ?? ''), 'Time Stamping')
        || $genTime->getTimestamp() < $signerInfo['validFrom_time_t'] || $genTime->getTimestamp() > $signerInfo['validTo_time_t']) {
        throw new TimestampInvalid('certificat de l\'unité d\'horodatage inadapté ou hors validité');
    }
    $issuer = null;
    foreach (tsa_pinned_certificates() as $ca) {
        if (openssl_x509_verify($signerCert, $ca) === 1) {
            $issuer = openssl_x509_parse($ca);
            break;
        }
    }
    if ($issuer === null) {
        throw new TimestampInvalid('unité d\'horodatage non émise par l\'autorité épinglée');
    }
    return [
        'gen_time' => $genTime->getTimestamp(),
        'gen_time_utc' => $genTime->format('Y-m-d H:i:s') . (isset($time[2]) ? '.' . $time[2] : '') . ' UTC',
        'serial' => strtoupper(bin2hex(asn1_one($tst[3][2] ?? '', 0x02))),
        'policy' => asn1_oid($tst[1] ?? null),
        'unit' => (string) ($signerInfo['subject']['CN'] ?? ''),
        'issuer' => (string) ($issuer['subject']['CN'] ?? ''),
    ];
}

function tsa_pinned_certificates(): array
{
    $pem = (string) @file_get_contents((string) (config()['tsa_ca'] ?? __DIR__ . '/tsa-staging-ca.pem'));
    preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $matches);
    return $matches[0];
}

// ---- Lecture DER minimale ----------------------------------------------------------------------

/** Lit un élément DER : [étiquette, contenu, encodage complet]. */
function asn1_read(string $data, int &$offset): array
{
    $start = $offset;
    if ($offset + 2 > strlen($data)) {
        throw new TimestampInvalid('DER tronqué');
    }
    $tag = ord($data[$offset++]);
    $length = ord($data[$offset++]);
    if (($tag & 0x1f) === 0x1f || $length === 0x80) {
        throw new TimestampInvalid('DER non pris en charge');
    }
    if ($length > 0x80) {
        $bytes = $length & 0x7f;
        if ($bytes > 4 || $offset + $bytes > strlen($data)) {
            throw new TimestampInvalid('DER : longueur invalide');
        }
        $length = 0;
        for ($i = 0; $i < $bytes; $i++) {
            $length = ($length << 8) | ord($data[$offset++]);
        }
    }
    if ($length > strlen($data) - $offset) {
        throw new TimestampInvalid('DER tronqué');
    }
    $content = substr($data, $offset, $length);
    $offset += $length;
    return [$tag, $content, substr($data, $start, $offset - $start)];
}

function asn1_children(string $content): array
{
    $items = [];
    for ($offset = 0; $offset < strlen($content);) {
        $items[] = asn1_read($content, $offset);
    }
    return $items;
}

/** Contenu d'un élément unique d'étiquette donnée. */
function asn1_one(string $der, int $tag): string
{
    $offset = 0;
    $item = asn1_read($der, $offset);
    if ($item[0] !== $tag) {
        throw new TimestampInvalid(sprintf('DER : étiquette 0x%02X attendue', $tag));
    }
    return $item[1];
}

function asn1_oid(?array $item): string
{
    if ($item === null || $item[0] !== 0x06 || $item[1] === '') {
        return '';
    }
    $bytes = array_map('ord', str_split($item[1]));
    $first = array_shift($bytes);
    $parts = [intdiv($first, 40), $first % 40];
    $value = 0;
    foreach ($bytes as $byte) {
        $value = ($value << 7) | ($byte & 0x7f);
        if (($byte & 0x80) === 0) {
            $parts[] = $value;
            $value = 0;
        }
    }
    return implode('.', $parts);
}

function asn1_digest(?array $oid): string
{
    return match (asn1_oid($oid)) {
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
        default => throw new TimestampInvalid('algorithme d\'empreinte non pris en charge'),
    };
}
