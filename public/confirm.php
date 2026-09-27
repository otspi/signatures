<?php
// SPDX-License-Identifier: EUPL-1.2
// Confirmation de la signature par le lien reçu par e-mail : le lien (GET) affiche un bouton, seul le
// POST confirme. Les antivirus de messagerie qui suivent les liens ne confirment donc rien à la place
// de la personne.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/horodatage.php';

$lang = lang();
$token = (string) ($_GET['t'] ?? $_POST['t'] ?? '');
$pdo = db();

if (preg_match('/^[0-9a-f]{64}$/', $token) === 1) {
    $row = $pdo->prepare('SELECT id, email, prenom, nom, fonction, organisation, publier, lang, created_at FROM signatures WHERE confirm_hash = ? AND confirmed_at IS NULL');
    $row->execute([token_hash($token)]);
    $signature = $row->fetch();
    if ($signature !== false && time() - (int) $signature['created_at'] <= CONFIRM_TTL) {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || cross_site_post()) {
            page(t('confirm_title', $lang),
                '<h1>' . h(t('confirm_title', $lang)) . '</h1><p>' . h(t('confirm_ask', $lang)) . '</p>'
                . recap_html($signature, $lang)
                . '<form method="post" action="?lang=' . $lang . '"><input type="hidden" name="t" value="' . h($token) . '">'
                . '<button type="submit">' . h(t('confirm_button', $lang)) . '</button></form>', $lang);
            exit;
        }
        $withdraw = new_token();
        // Condition sur confirmed_at : de deux confirmations simultanées, une seule aboutit.
        $update = $pdo->prepare('UPDATE signatures SET confirmed_at = ?, confirm_hash = ?, withdraw_hash = ? WHERE id = ? AND confirmed_at IS NULL');
        $now = time();
        $update->execute([$now, token_hash(new_token()), token_hash($withdraw), $signature['id']]);
        if ($update->rowCount() === 1) {
            $l = $signature['lang'] === 'en' ? 'en' : 'fr';
            // Preuve : attestation figée puis horodatée ; si l'autorité ne répond pas, le cron réessaie et le lien
            // affiche « horodatage en cours ». proof_mailed_at évite au cron un second envoi.
            $proof = proof_link($signature + ['confirmed_at' => $now]);
            db()->prepare('UPDATE signatures SET proof_mailed_at = ? WHERE id = ?')->execute([$now, $signature['id']]);
            timestamp_signature((int) $signature['id']);
            send_mail($signature['email'], t('mail_done_subject', $l), sprintf(t('mail_done_body', $l), url('withdraw.php', ['t' => $withdraw, 'lang' => $l]), $proof), $l);
            if ((int) $signature['publier'] === 1) {
                // Rien n'est publié avant validation : on prévient la personne qui modère, qui se connecte à
                // l'administration avec sa clé de sécurité (la ligne de commande bin/moderation.php reste possible).
                $who = trim($signature['prenom'] . ' ' . $signature['nom']);
                $quality = implode(', ', array_filter([$signature['fonction'], $signature['organisation']], 'strlen'));
                send_mail(config()['contact'], 'Signature à modérer : ' . $who,
                    "Nouvelle signature confirmée, en attente de validation avant publication.\n\n"
                    . "#{$signature['id']} {$who}" . ($quality !== '' ? " — {$quality}" : '') . "\n"
                    . "E-mail : {$signature['email']}\n\n"
                    . "Valider, masquer ou supprimer (connexion avec la clé de sécurité) :\n"
                    . url('admin.php', ['f' => 'attente']) . "\n\n"
                    . "En ligne de commande : php bin/moderation.php valider {$signature['id']}\n");
            }
            // Réponse au POST : son adresse (confirm.php?lang=…) ne porte pas le jeton, resté dans le corps de
            // la requête. Elle peut donc être mesurée ; un rechargement renvoie le jeton usé et aboutit à la 400.
            page(t('confirmed_title', $lang), '<h1 data-track-load="Manifeste|Signature confirmée|' . $lang . '">' . h(t('confirmed_title', $lang)) . '</h1><p>' . h(t('confirmed', $lang)) . '</p>', $lang, audience: true);
            exit;
        }
    }
}
http_response_code(400);
page(t('confirm_invalid_title', $lang), '<h1>' . h(t('confirm_invalid_title', $lang)) . '</h1><p>' . h(t('confirm_invalid', $lang)) . '</p>' . back_to_form($lang), $lang);
