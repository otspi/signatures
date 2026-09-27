<?php
// SPDX-License-Identifier: EUPL-1.2
// Retrait de la signature et suppression des données (page de confirmation puis POST).

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

$lang = lang();
$token = (string) ($_GET['t'] ?? $_POST['t'] ?? '');
$valid = preg_match('/^[0-9a-f]{64}$/', $token) === 1;
$pdo = db();
$hash = $valid ? token_hash($token) : '';

if ($valid && $_SERVER['REQUEST_METHOD'] === 'POST' && !cross_site_post()) {
    $delete = $pdo->prepare('DELETE FROM signatures WHERE withdraw_hash = ?');
    $delete->execute([$hash]);
    if ($delete->rowCount() > 0) {
        page(t('withdrawn_title', $lang), '<h1>' . h(t('withdrawn_title', $lang)) . '</h1><p>' . h(t('withdrawn', $lang)) . '</p>', $lang);
        exit;
    }
} elseif ($valid) {
    $row = $pdo->prepare('SELECT email, prenom, nom, fonction, organisation, publier, lang, created_at, confirmed_at, approved_at, proof_at, proof_json, proof_token FROM signatures WHERE withdraw_hash = ?');
    $row->execute([$hash]);
    $signature = $row->fetch();
    if ($signature !== false && ($_GET['f'] ?? '') === 'json') {
        // Droit d'accès et de portabilité : toutes les données enregistrées, sans les empreintes de jetons.
        $iso = static fn ($t): ?string => $t === null ? null : gmdate('Y-m-d\TH:i:s\Z', (int) $t);
        header('Content-Type: application/json; charset=UTF-8');
        header('Content-Disposition: attachment; filename="mes-donnees-signature-otspi.json"');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        echo json_encode([
            'responsable' => 'Initiative OTSPI — contact@otspi.org',
            'email' => $signature['email'], 'prenom' => $signature['prenom'], 'nom' => $signature['nom'],
            'fonction' => $signature['fonction'], 'organisation' => $signature['organisation'],
            'publication_acceptee' => (int) $signature['publier'] === 1, 'langue' => $signature['lang'],
            'demande_le' => $iso($signature['created_at']), 'confirmee_le' => $iso($signature['confirmed_at']),
            'moderee_le' => $iso($signature['approved_at']), 'horodatee_le' => $iso($signature['proof_at']),
            'attestation_horodatee' => $signature['proof_json'] === null ? null : json_decode($signature['proof_json'], true),
            // Jeton RFC 3161 (TimeStampResp, DER en base64) portant sur l'empreinte SHA-256 de l'attestation, exacte à
            // l'octet près telle qu'enregistrée : attestation_texte.
            'attestation_texte' => $signature['proof_json'],
            'jeton_horodatage_rfc3161_base64' => $signature['proof_token'],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }
    if ($signature !== false) {
        page(t('withdraw_title', $lang),
            '<h1>' . h(t('withdraw_title', $lang)) . '</h1><p>' . h(t('withdraw_ask', $lang)) . '</p>'
            . '<p>' . h(t('withdraw_export', $lang)) . ' <a href="?' . h(http_build_query(['t' => $token, 'lang' => $lang, 'f' => 'json'])) . '">' . h(t('withdraw_export_link', $lang)) . '</a></p>'
            . '<form method="post" action="?lang=' . $lang . '"><input type="hidden" name="t" value="' . h($token) . '">'
            . '<button type="submit">' . h(t('withdraw_button', $lang)) . '</button></form>', $lang);
        exit;
    }
}
http_response_code(400);
page(t('confirm_invalid_title', $lang), '<h1>' . h(t('confirm_invalid_title', $lang)) . '</h1><p>' . h(t('confirm_invalid', $lang)) . '</p>' . back_to_form($lang), $lang);
