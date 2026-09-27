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
            if ((int) $signature['publier'] === 1 && (config()['moderation_notify'] ?? 'quotidien') === 'immediat') {
                // Rien n'est publié avant validation. Par défaut, la personne qui modère reçoit un récapitulatif
                // quotidien (moderation_digest, tâche quotidienne) ; avec moderation_notify = 'immediat', un e-mail
                // par signature. Connexion avec la clé de sécurité ; bin/moderation.php reste possible.
                $who = trim($signature['prenom'] . ' ' . $signature['nom']);
                $quality = implode(', ', array_filter([$signature['fonction'], $signature['organisation']], 'strlen'));
                send_mail(config()['contact'], 'Signature à modérer : ' . $who,
                    "Nouvelle signature confirmée, en attente de validation avant publication.\n\n"
                    . "#{$signature['id']} {$who}" . ($quality !== '' ? " — {$quality}" : '') . "\n"
                    . "E-mail : {$signature['email']} (" . email_org_hint($signature['email'], $signature['organisation'])[0] . ")\n\n"
                    . "Valider, masquer ou supprimer (connexion avec la clé de sécurité) :\n"
                    . url('admin.php', ['f' => 'attente']) . "\n\n"
                    . "En ligne de commande : php bin/moderation.php valider {$signature['id']}\n");
            }
            // Réponse au POST : son adresse (confirm.php?lang=…) ne porte pas le jeton, resté dans le corps de
            // la requête. Elle peut donc être mesurée ; un rechargement renvoie le jeton usé et aboutit à la 400.
            page(t('confirmed_title', $lang), '<h1 data-track-load="Manifeste|Signature confirmée|' . $lang . '">' . h(t('confirmed_title', $lang)) . '</h1><p>' . h(t('confirmed', $lang)) . '</p>'
                . share_block($lang), $lang, audience: true, script: 'assets/partage.js');
            exit;
        }
    }
}
/**
 * Partage après signature : liens simples (rien n'est chargé depuis un réseau social avant le clic), partage natif
 * et copie du lien (assets/partage.js), code d'intégration du compteur (compteur.php).
 */
function share_block(string $lang): string
{
    $manifesto = $lang === 'en' ? 'https://www.otspi.org/en/manifesto.html' : 'https://www.otspi.org/manifeste.html';
    $text = t('share_text', $lang);
    $links = [
        'LinkedIn' => 'https://www.linkedin.com/sharing/share-offsite/?url=' . rawurlencode($manifesto),
        'Bluesky' => 'https://bsky.app/intent/compose?text=' . rawurlencode($text . ' ' . $manifesto),
        'Mastodon' => 'https://mastodonshare.com/?text=' . rawurlencode($text) . '&url=' . rawurlencode($manifesto),
        t('share_mail', $lang) => 'mailto:?subject=' . rawurlencode(t('share_mail_subject', $lang)) . '&body=' . rawurlencode($text . "\n" . $manifesto),
    ];
    $html = '';
    foreach ($links as $name => $href) {
        $html .= '<a class="button secondary small" href="' . h($href) . '" rel="noopener noreferrer" target="_blank" data-track="Manifeste|Partager|' . h($name) . '">' . h($name) . '</a>';
    }
    $counter = url('compteur.php', $lang === 'en' ? ['lang' => 'en'] : []);
    $embed = '<a href="' . $manifesto . '"><img src="' . $counter . '" alt="' . t('share_mail_subject', $lang) . '"></a>';
    return '<h2>' . h(t('share_title', $lang)) . '</h2><p>' . h(t('share_intro', $lang)) . '</p>'
        . '<div class="share" data-share-url="' . h($manifesto) . '" data-share-text="' . h($text) . '" data-share-title="' . h(t('share_mail_subject', $lang)) . '" data-copied="' . h(t('share_copied', $lang)) . '">'
        . '<button type="button" class="share-native small" hidden data-track="Manifeste|Partager|natif">' . h(t('share_native', $lang)) . '</button>'
        . $html
        . '<button type="button" class="share-copy small secondary" hidden data-track="Manifeste|Partager|lien copié">' . h(t('share_copy', $lang)) . '</button></div>'
        . '<details class="embed"><summary>' . h(t('share_embed', $lang)) . '</summary><p>' . h(t('share_embed_help', $lang)) . '</p>'
        . '<p><img src="compteur.php' . ($lang === 'en' ? '?lang=en' : '') . '" alt=""></p><pre><code>' . h($embed) . '</code></pre></details>';
}

http_response_code(400);
page(t('confirm_invalid_title', $lang), '<h1>' . h(t('confirm_invalid_title', $lang)) . '</h1><p>' . h(t('confirm_invalid', $lang)) . '</p>' . back_to_form($lang), $lang);
