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
    $exists = $pdo->prepare('SELECT 1 FROM signatures WHERE withdraw_hash = ?');
    $exists->execute([$hash]);
    if ($exists->fetchColumn()) {
        page(t('withdraw_title', $lang),
            '<h1>' . h(t('withdraw_title', $lang)) . '</h1><p>' . h(t('withdraw_ask', $lang)) . '</p>'
            . '<form method="post" action="?lang=' . $lang . '"><input type="hidden" name="t" value="' . h($token) . '">'
            . '<button type="submit">' . h(t('withdraw_button', $lang)) . '</button></form>', $lang);
        exit;
    }
}
http_response_code(400);
page(t('confirm_invalid_title', $lang), '<h1>' . h(t('confirm_invalid_title', $lang)) . '</h1><p>' . h(t('confirm_invalid', $lang)) . '</p>' . back_to_form($lang), $lang);
