<?php
// SPDX-License-Identifier: EUPL-1.2
// Preuve horodatée d'une signature, par le lien personnel reçu par e-mail : attestation, jeton RFC 3161 vérifié
// par le serveur (src/horodatage.php), téléchargements (?f=json, ?f=tsr) et vérification indépendante sur la
// démonstration d'OTSPI ou avec OpenSSL. Adresse porteuse d'un jeton : jamais de mesure d'audience.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/horodatage.php';
require __DIR__ . '/../src/pdf.php';

const DEMO_VERIFIER = 'https://demo.open-eidas.eu/#verifier';

$lang = lang();
$token = (string) ($_GET['t'] ?? '');
$signature = false;
if (preg_match('/^[0-9a-f]{64}$/', $token) === 1) {
    $row = db()->prepare('SELECT id, prenom, nom, fonction, organisation, publier, lang, proof_json, proof_token, proof_pdf FROM signatures WHERE proof_hash = ? AND confirmed_at IS NOT NULL');
    $row->execute([token_hash($token)]);
    $signature = $row->fetch();
}
if ($signature === false || $signature['proof_json'] === null) {
    http_response_code(404);
    page(t('proof_title', $lang), '<h1>' . h(t('proof_title', $lang)) . '</h1><p>' . h(t('proof_invalid', $lang)) . '</p>' . back_to_form($lang), $lang);
    exit;
}

$name = 'signature-otspi-' . (int) $signature['id'];
$file = (string) ($_GET['f'] ?? '');
if ($file === 'pdf' && $signature['proof_token'] !== null) {
    // Attestation PDF : construite au premier téléchargement, conservée une fois horodatée (PAdES) ; sans
    // horodatage (autorité injoignable), servie telle quelle et reconstruite au téléchargement suivant.
    $pdf = $signature['proof_pdf'];
    if ($pdf === null) {
        try {
            $details = tsa_verify(base64_decode($signature['proof_token']), hash('sha256', $signature['proof_json'], true));
        } catch (TimestampInvalid $e) {
            http_response_code(503);
            page(t('proof_title', $lang), '<h1>' . h(t('proof_title', $lang)) . '</h1><p>' . h(t('proof_error', $lang)) . '</p>', $lang);
            exit;
        }
        [$pdf, $stamped] = proof_pdf($signature, $details, $lang);
        if ($stamped) {
            $store = db()->prepare('UPDATE signatures SET proof_pdf = ? WHERE id = ?');
            $store->bindValue(1, $pdf, PDO::PARAM_LOB);
            $store->bindValue(2, (int) $signature['id'], PDO::PARAM_INT);
            $store->execute();
        }
    }
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="' . $name . '.pdf"');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    echo $pdf;
    exit;
}
if ($file === 'json' || ($file === 'tsr' && $signature['proof_token'] !== null)) {
    header('Content-Type: ' . ($file === 'json' ? 'application/json; charset=UTF-8' : 'application/timestamp-reply'));
    header('Content-Disposition: attachment; filename="' . $name . '.' . $file . '"');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    echo $file === 'json' ? $signature['proof_json'] : base64_decode($signature['proof_token']);
    exit;
}

$digest = hash('sha256', $signature['proof_json']);
$details = null;
$status = '<p class="proof-status pending" role="status">' . h(t('proof_pending', $lang)) . '</p>';
if ($signature['proof_token'] !== null) {
    try {
        $details = tsa_verify(base64_decode($signature['proof_token']), hex2bin($digest));
        $status = '<p class="proof-status ok" role="status"><span aria-hidden="true">✓</span> ' . h(t('proof_ok', $lang)) . '</p>';
    } catch (TimestampInvalid $e) {
        error_log('otspi-signatures : preuve de la signature #' . (int) $signature['id'] . ' invalide (' . $e->getMessage() . ')');
        $status = '<p class="proof-status error" role="alert">' . h(t('proof_error', $lang)) . '</p>';
    }
}

$other = $lang === 'fr' ? 'en' : 'fr';
$link = static fn (array $query): string => h(url('preuve.php', ['t' => $token] + $query));
$body = '<p class="lang"><a href="' . $link(['lang' => $other]) . '">' . strtoupper($other) . '</a></p>'
    . '<h1>' . h(t('proof_title', $lang)) . '</h1>' . $status
    . '<p>' . h(t('proof_intro', $lang)) . '</p>'
    . recap_html($signature, $lang);

if ($details !== null) {
    $paris = (new DateTimeImmutable('@' . $details['gen_time']))->setTimezone(new DateTimeZone('Europe/Paris'));
    $rows = [
        t('proof_date', $lang) => $paris->format($lang === 'fr' ? 'd/m/Y à H:i:s' : 'Y-m-d, H:i:s') . ' (Paris) — ' . $details['gen_time_utc'],
        t('proof_digest', $lang) => $digest,
        t('proof_serial', $lang) => $details['serial'],
        t('proof_unit', $lang) => $details['unit'],
        t('proof_issuer', $lang) => $details['issuer'],
        t('proof_policy', $lang) => $details['policy'],
    ];
    $body .= '<h2>' . h(t('proof_timestamp', $lang)) . '</h2><dl class="recap proof-details">';
    foreach ($rows as $label => $value) {
        $body .= '<dt>' . h($label) . '</dt><dd><code>' . h($value) . '</code></dd>';
    }
    $body .= '</dl><h2>' . h(t('proof_checks', $lang)) . '</h2><ul class="checks">'
        . '<li>' . h(t('proof_check_signature', $lang)) . '</li>'
        . '<li>' . h(t('proof_check_digest', $lang)) . '</li>'
        . '<li>' . h(t('proof_check_chain', $lang)) . '</li></ul>'
        . '<h2>' . h(t('proof_self', $lang)) . '</h2>'
        . '<p><a class="button" href="' . $link(['f' => 'pdf']) . '" download>' . h(t('proof_download_pdf', $lang)) . '</a></p>'
        . '<p class="muted">' . h(t('proof_pdf_help', $lang)) . '</p>'
        . '<div class="moderation-actions">'
        . '<a class="button secondary" href="' . $link(['f' => 'json']) . '" download>' . h(t('proof_download_json', $lang)) . '</a>'
        . '<a class="button secondary" href="' . $link(['f' => 'tsr']) . '" download>' . h(t('proof_download_tsr', $lang)) . '</a></div>'
        . '<p>' . h(t('proof_demo', $lang)) . '</p>'
        . '<p><a class="button" href="' . h(DEMO_VERIFIER) . '" rel="noopener">' . h(t('proof_demo_link', $lang)) . '</a></p>'
        . '<p>' . h(t('proof_openssl', $lang)) . ' <a href="' . h(tsa_url() . '/api/v1/certificate') . '">' . h(t('proof_chain_link', $lang)) . '</a></p>'
        . '<pre><code>openssl ts -verify -data ' . $name . '.json -in ' . $name . '.tsr -CAfile chaine.pem</code></pre>';
}
$body .= '<p class="notice">' . h(t('proof_staging', $lang)) . '</p>';

page(t('proof_title', $lang), $body, $lang);
