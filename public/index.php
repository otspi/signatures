<?php
// SPDX-License-Identifier: EUPL-1.2
// Formulaire de signature et traitement de la demande (confirmation par e-mail, double consentement).

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

$lang = lang();
$error = null;
$old = ['prenom' => '', 'nom' => '', 'email' => '', 'fonction' => '', 'organisation' => '', 'publier' => false];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $old = [
        'prenom' => (string) ($_POST['prenom'] ?? ''), 'nom' => (string) ($_POST['nom'] ?? ''),
        'email' => (string) ($_POST['email'] ?? ''), 'fonction' => (string) ($_POST['fonction'] ?? ''),
        'organisation' => (string) ($_POST['organisation'] ?? ''), 'publier' => isset($_POST['publier']),
    ];
    $state = form_token_state((string) ($_POST['ft'] ?? ''));

    if (($_POST['website'] ?? '') !== '') {
        // Piège à robots : champ invisible rempli. On répond comme en cas de succès, sans rien faire.
        page(t('sent_title', $lang), '<h1>' . h(t('sent_title', $lang)) . '</h1><p>' . h(t('sent', $lang)) . '</p>', $lang, audience: true);
        exit;
    }
    if ($state !== 'ok' || cross_site_post()) {
        $error = 'err_form';
    } elseif (rate_limited(5, 3600)) {
        $error = 'err_rate';
    } else {
        record_hit();
        $prenom = clean($old['prenom'], 80);
        $nom = clean($old['nom'], 80);
        $fonction = clean_optional($old['fonction'], 120);
        $organisation = clean_optional($old['organisation'], 120);
        $email = strtolower(trim($old['email']));
        if ($prenom === null || $nom === null || $fonction === null || $organisation === null || !valid_email($email)) {
            $error = 'err_invalid';
        } else {
            $pdo = db();
            $token = new_token();
            $withdraw = new_token();
            $now = time();
            // Unicité vérifiée sans l'alias « +… » : une même boîte ne signe qu'une fois.
            $existing = $pdo->prepare('SELECT id, confirmed_at, last_mail_at FROM signatures WHERE email_key = ?');
            $existing->execute([email_key($email)]);
            $row = $existing->fetch();
            $sendConfirm = true;
            if (($row === false || $row['confirmed_at'] === null) && mail_cap_reached()) {
                // Plafond global atteint : rien n'est enregistré, la personne réessaiera plus tard.
                $error = 'err_rate';
                $sendConfirm = false;
            } elseif ($row === false) {
                // ON CONFLICT : deux envois simultanés pour la même adresse ne provoquent pas d'erreur ;
                // le second est traité comme un renvoi trop rapproché.
                $insert = $pdo->prepare('INSERT INTO signatures (email, email_key, prenom, nom, fonction, organisation, publier, lang, confirm_hash, withdraw_hash, created_at, last_mail_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING');
                $insert->execute([$email, email_key($email), $prenom, $nom, $fonction, $organisation, $old['publier'] ? 1 : 0, $lang, token_hash($token), token_hash($withdraw), $now, $now]);
                $sendConfirm = $insert->rowCount() === 1;
            } elseif ($row['confirmed_at'] === null && $now - (int) $row['last_mail_at'] > 600) {
                // Demande non confirmée : on met à jour les données (y compris l'alias choisi) et on renvoie un
                // lien, au plus toutes les 10 minutes.
                $pdo->prepare('UPDATE signatures SET email=?, prenom=?, nom=?, fonction=?, organisation=?, publier=?, lang=?, confirm_hash=?, withdraw_hash=?, created_at=?, last_mail_at=? WHERE id=?')
                    ->execute([$email, $prenom, $nom, $fonction, $organisation, $old['publier'] ? 1 : 0, $lang, token_hash($token), token_hash($withdraw), $now, $now, $row['id']]);
            } else {
                // Déjà confirmée ou renvoi trop rapproché : réponse identique, pour ne pas révéler si l'adresse est connue.
                $sendConfirm = false;
            }
            $recap = ['prenom' => $prenom, 'nom' => $nom, 'fonction' => $fonction, 'organisation' => $organisation, 'publier' => $old['publier']];
            if ($sendConfirm) {
                $sent = send_mail($email, t('mail_confirm_subject', $lang), sprintf(t('mail_confirm_body', $lang), recap_text($recap, $lang), url('confirm.php', ['t' => $token, 'lang' => $lang])));
                if (!$sent) {
                    $error = 'err_mail';
                }
            }
            if ($error === null) {
                page(t('sent_title', $lang), '<h1>' . h(t('sent_title', $lang)) . '</h1><p>' . h(t('sent', $lang)) . '</p>', $lang, audience: true);
                exit;
            }
        }
    }
}

$other = $lang === 'fr' ? 'en' : 'fr';
$field = static fn (string $name, string $label, string $type, bool $required, int $max): string =>
    '<p><label>' . h($label) . '<br><input name="' . $name . '" type="' . $type . '" maxlength="' . $max . '"'
    . ($required ? ' required' : '') . ' value="' . h((string) $old[$name]) . '"></label></p>';

$body = '<p class="lang"><a href="?lang=' . $other . '">' . strtoupper($other) . '</a></p>'
    . '<h1>' . h(t('heading', $lang)) . '</h1>'
    . ($error ? '<p class="error" role="alert">' . h(t($error, $lang)) . '</p>' : '')
    . '<form method="post" action="?lang=' . $lang . '">'
    . '<input type="hidden" name="lang" value="' . $lang . '"><input type="hidden" name="ft" value="' . h(form_token()) . '">'
    . '<p class="hp" aria-hidden="true"><label>Website<input name="website" tabindex="-1" autocomplete="off"></label></p>'
    . $field('prenom', t('firstname', $lang), 'text', true, 80)
    . $field('nom', t('lastname', $lang), 'text', true, 80)
    . $field('email', t('email', $lang), 'email', true, 254)
    . $field('fonction', t('position', $lang), 'text', false, 120)
    . $field('organisation', t('organisation', $lang), 'text', false, 120)
    . '<p><label><input type="checkbox" name="publier" value="1"' . ($old['publier'] ? ' checked' : '') . '> ' . h(t('publish', $lang)) . '</label></p>'
    . '<p><button type="submit">' . h(t('submit', $lang)) . '</button></p></form>'
    . '<p class="privacy">' . h(t('privacy', $lang)) . '</p>';
page(t('title', $lang), $body, $lang, audience: true);
