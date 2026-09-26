<?php
// SPDX-License-Identifier: EUPL-1.2
// Confirmation de la signature par le lien reçu par e-mail.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

$lang = lang();
$token = (string) ($_GET['t'] ?? '');
$pdo = db();

if (preg_match('/^[0-9a-f]{64}$/', $token) === 1) {
    $pdo->beginTransaction();
    $row = $pdo->prepare('SELECT id, email, prenom, lang, created_at, confirmed_at FROM signatures WHERE confirm_hash = ?');
    $row->execute([token_hash($token)]);
    $signature = $row->fetch();
    if ($signature !== false && $signature['confirmed_at'] === null && time() - (int) $signature['created_at'] <= CONFIRM_TTL) {
        $withdraw = new_token();
        $pdo->prepare('UPDATE signatures SET confirmed_at = ?, confirm_hash = ?, withdraw_hash = ? WHERE id = ?')
            ->execute([time(), token_hash(new_token()), token_hash($withdraw), $signature['id']]);
        $pdo->commit();
        $l = $signature['lang'] === 'en' ? 'en' : 'fr';
        send_mail($signature['email'], t('mail_done_subject', $l), sprintf(t('mail_done_body', $l), $signature['prenom'], url('withdraw.php', ['t' => $withdraw, 'lang' => $l])));
        page(t('confirmed_title', $lang), '<h1>' . h(t('confirmed_title', $lang)) . '</h1><p>' . h(t('confirmed', $lang)) . '</p>', $lang);
        exit;
    }
    $pdo->rollBack();
}
http_response_code(400);
page(t('confirm_invalid_title', $lang), '<h1>' . h(t('confirm_invalid_title', $lang)) . '</h1><p>' . h(t('confirm_invalid', $lang)) . '</p>', $lang);
