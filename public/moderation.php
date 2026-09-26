<?php
// SPDX-License-Identifier: EUPL-1.2
// Modération d'une signature depuis le lien signé de l'e-mail « Signature à modérer » : la page (GET)
// présente la signature, seuls les boutons (POST, même origine) agissent. Page interne, en français.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

$id = (int) ($_GET['id'] ?? $_POST['id'] ?? 0);
$token = (string) ($_GET['t'] ?? $_POST['t'] ?? '');
$row = db()->prepare('SELECT id, email, prenom, nom, fonction, organisation, publier, created_at, confirmed_at, approved_at FROM signatures WHERE id = ? AND confirmed_at IS NOT NULL');
$row->execute([$id]);
$signature = $row->fetch();

if ($signature === false || preg_match('/^[0-9a-f]{64}$/', $token) !== 1
    || !hash_equals(moderation_token($id, (int) $signature['created_at']), $token)) {
    http_response_code(400);
    page('Lien de modération invalide', '<h1>Lien de modération invalide</h1><p>Ce lien ne correspond à aucune signature : elle a peut-être été supprimée ou retirée par son auteur.</p>', 'fr');
    exit;
}

$action = (string) ($_POST['a'] ?? '');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !cross_site_post() && in_array($action, MODERATION_ACTIONS, true)) {
    moderate($id, $action);
    $done = ['valider' => 'Signature validée : elle sera publiée au prochain rafraîchissement de la liste.',
        'masquer' => 'Signature masquée : elle reste comptée, le nom ne sera jamais publié.',
        'supprimer' => 'Signature supprimée avec ses données.'][$action];
    page('Modération', '<h1>Modération</h1><p>' . h($done) . '</p>', 'fr');
    exit;
}

$state = match (true) {
    (int) $signature['publier'] === 0 && $signature['approved_at'] !== null => 'masquée (comptée, nom non publié)',
    (int) $signature['publier'] === 0 => 'non publiée à la demande de son auteur (comptée)',
    $signature['approved_at'] !== null => 'validée, publiée',
    default => 'en attente de validation',
};
$hidden = '<input type="hidden" name="id" value="' . $id . '"><input type="hidden" name="t" value="' . h($token) . '">';
$button = static fn (string $action, string $label): string =>
    '<form method="post" action="moderation.php">' . $hidden . '<input type="hidden" name="a" value="' . $action . '">'
    . '<button type="submit">' . h($label) . '</button></form>';
page('Modération', '<h1>Signature #' . $id . '</h1>'
    . '<p>État : <strong>' . h($state) . '</strong>. E-mail (jamais publié) : ' . h($signature['email']) . '</p>'
    . recap_html($signature, 'fr')
    . '<div class="moderation-actions">'
    . $button('valider', 'Valider et publier')
    . $button('masquer', 'Masquer (compter sans publier)')
    . $button('supprimer', 'Supprimer (usurpation, abus)')
    . '</div>', 'fr');
