<?php
// SPDX-License-Identifier: EUPL-1.2
// Administration des signatures (page interne, en français). Accès par lien magique : un lien signé,
// valable 30 minutes, est envoyé à la seule adresse de contact ; ni mot de passe ni cookie. Les actions
// sont en POST depuis le site lui-même, et la suppression demande une confirmation.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

const ADMIN_LINKS_PER_10_MIN = 3;   // plafond global de liens d'accès envoyés à l'adresse de contact

const FILTERS = [
    'attente' => ['En attente', 'confirmed_at IS NOT NULL AND publier = 1 AND approved_at IS NULL'],
    'publiees' => ['Publiées', 'confirmed_at IS NOT NULL AND publier = 1 AND approved_at IS NOT NULL'],
    'non-publiees' => ['Non publiées', 'confirmed_at IS NOT NULL AND publier = 0'],
    'non-confirmees' => ['Non confirmées', 'confirmed_at IS NULL'],
    'toutes' => ['Toutes', '1 = 1'],
];

function hidden_inputs(array $values): string
{
    $html = '';
    foreach ($values as $name => $value) {
        $html .= '<input type="hidden" name="' . h((string) $name) . '" value="' . h((string) $value) . '">';
    }
    return $html;
}

function when(?int $timestamp): string
{
    return $timestamp ? date('d/m/Y H:i', $timestamp) : '—';
}

function state(array $row): array
{
    return match (true) {
        $row['confirmed_at'] === null => ['Non confirmée', 'muted'],
        (int) $row['publier'] === 1 && $row['approved_at'] === null => ['En attente', 'pending'],
        (int) $row['publier'] === 1 => ['Publiée', 'ok'],
        $row['approved_at'] !== null => ['Masquée', 'muted'],
        default => ['Non publiée (choix de l’auteur)', 'muted'],
    };
}

$exp = (string) ($_GET['exp'] ?? $_POST['exp'] ?? '');
$token = (string) ($_GET['t'] ?? $_POST['t'] ?? '');
$post = $_SERVER['REQUEST_METHOD'] === 'POST';

// ---- Sans accès valide : demande d'un lien -----------------------------------------------------

if (!admin_access_ok($exp, $token)) {
    $message = '';
    if ($exp !== '' || $token !== '') {
        http_response_code(403);
        $message = '<p class="error" role="alert">Ce lien d’accès est invalide ou a expiré. Demandez-en un nouveau.</p>';
    } elseif ($post && ($_POST['a'] ?? '') === 'lien' && !cross_site_post()) {
        $pdo = db();
        $key = hash_hmac('sha256', 'admin-link', config()['secret']);
        $count = $pdo->prepare('SELECT COUNT(*) FROM hits WHERE ip_hash = ? AND at > ?');
        $count->execute([$key, time() - 600]);
        if ((int) $count->fetchColumn() >= ADMIN_LINKS_PER_10_MIN) {
            $message = '<p class="error" role="alert">Trop de liens demandés : réessayez dans quelques minutes.</p>';
        } else {
            $pdo->prepare('INSERT INTO hits (ip_hash, at) VALUES (?, ?)')->execute([$key, time()]);
            $expires = time() + ADMIN_TTL;
            $link = url('admin.php', ['exp' => $expires, 't' => admin_token($expires)]);
            $sent = send_mail(config()['contact'], 'Accès à l’administration des signatures',
                "Lien d'accès à l'administration des signatures du manifeste, valable 30 minutes (jusqu'à "
                . date('H:i', $expires) . ") :\n\n" . $link . "\n\n"
                . "Si vous n'avez rien demandé, ignorez ce message : le lien expirera de lui-même.\n");
            $message = $sent
                ? '<p role="status">Un lien d’accès valable 30 minutes vient d’être envoyé à l’adresse de contact de l’initiative.</p>'
                : '<p class="error" role="alert">L’e-mail n’a pas pu être envoyé. Réessayez plus tard.</p>';
        }
    }
    page('Administration des signatures', '<h1>Administration des signatures</h1>' . $message
        . '<p>L’accès se fait par un lien envoyé à l’adresse de contact de l’initiative ; il reste valable 30 minutes.</p>'
        . '<form method="post" action="admin.php">' . hidden_inputs(['a' => 'lien'])
        . '<button type="submit">Recevoir un lien d’accès</button></form>', 'fr');
    exit;
}

$filter = (string) ($_GET['f'] ?? $_POST['f'] ?? 'attente');
$filter = isset(FILTERS[$filter]) ? $filter : 'attente';
$auth = ['exp' => $exp, 't' => $token];
$pdo = db();

// ---- Actions (POST) ----------------------------------------------------------------------------

if ($post) {
    $action = (string) ($_POST['a'] ?? '');
    $id = (int) ($_POST['id'] ?? 0);
    if (cross_site_post() || !in_array($action, MODERATION_ACTIONS, true) || $id <= 0) {
        http_response_code(400);
        page('Administration des signatures', '<h1>Action refusée</h1><p>Requête invalide ou envoyée depuis un autre site.</p>'
            . '<p><a href="' . h(url('admin.php', $auth + ['f' => $filter])) . '">Retour à la liste</a></p>', 'fr');
        exit;
    }
    if ($action === 'supprimer' && ($_POST['ok'] ?? '') !== '1') {
        $row = $pdo->prepare('SELECT id, email, prenom, nom, fonction, organisation, publier FROM signatures WHERE id = ? AND confirmed_at IS NOT NULL');
        $row->execute([$id]);
        $signature = $row->fetch();
        if ($signature !== false) {
            page('Supprimer la signature #' . $id, '<h1>Supprimer la signature #' . $id . ' ?</h1>'
                . '<p>La signature et ses données sont effacées définitivement. E-mail : ' . h($signature['email']) . '</p>'
                . recap_html($signature, 'fr')
                . '<div class="moderation-actions"><form method="post" action="admin.php">'
                . hidden_inputs($auth + ['f' => $filter, 'a' => 'supprimer', 'id' => $id, 'ok' => '1'])
                . '<button type="submit" class="danger">Supprimer définitivement</button></form>'
                . '<a class="button secondary" href="' . h(url('admin.php', $auth + ['f' => $filter])) . '">Annuler</a></div>', 'fr');
            exit;
        }
    }
    $done = moderate($id, $action);
    // Post/Redirect/Get : un rechargement de la page ne rejoue pas l'action.
    header('Location: ' . url('admin.php', $auth + ['f' => $filter, 'fait' => $done ? $action : 'rien', 'id' => $id]), true, 303);
    exit;
}

// ---- Liste -------------------------------------------------------------------------------------

$flash = '';
$doneAction = (string) ($_GET['fait'] ?? '');
$doneId = (int) ($_GET['id'] ?? 0);
$labels = ['valider' => 'validée : elle sera publiée au prochain rafraîchissement de la liste', 'masquer' => 'masquée', 'supprimer' => 'supprimée'];
if (isset($labels[$doneAction])) {
    $flash = '<p class="notice" role="status">Signature #' . $doneId . ' ' . $labels[$doneAction] . '.</p>';
} elseif ($doneAction === 'rien') {
    $flash = '<p class="error" role="alert">Signature #' . $doneId . ' introuvable ou non confirmée : aucune modification.</p>';
}

$tabs = '';
foreach (FILTERS as $key => [$label, $where]) {
    $count = (int) $pdo->query('SELECT COUNT(*) FROM signatures WHERE ' . $where)->fetchColumn();
    $tabs .= '<a href="' . h(url('admin.php', $auth + ['f' => $key])) . '"' . ($key === $filter ? ' aria-current="page"' : '') . '>'
        . h($label) . ' <span class="count">' . $count . '</span></a>';
}

$rows = $pdo->query('SELECT id, email, prenom, nom, fonction, organisation, publier, lang, created_at, confirmed_at, approved_at FROM signatures WHERE '
    . FILTERS[$filter][1] . ' ORDER BY COALESCE(confirmed_at, created_at) DESC, id DESC LIMIT 500')->fetchAll();

$button = static fn (int $id, string $action, string $label, string $class = ''): string =>
    '<form method="post" action="admin.php">' . hidden_inputs($auth + ['f' => $filter, 'a' => $action, 'id' => $id])
    . '<button type="submit" class="small' . ($class !== '' ? ' ' . $class : '') . '">' . h($label) . '</button></form>';

$lines = '';
foreach ($rows as $row) {
    [$stateLabel, $stateClass] = state($row);
    $quality = implode(', ', array_filter([$row['fonction'], $row['organisation']], 'strlen'));
    $actions = '';
    if ($row['confirmed_at'] !== null) {
        if ((int) $row['publier'] === 1 && $row['approved_at'] === null) {
            $actions .= $button((int) $row['id'], 'valider', 'Valider');
        }
        if ((int) $row['publier'] === 1) {
            $actions .= $button((int) $row['id'], 'masquer', 'Masquer', 'secondary');
        }
        $actions .= $button((int) $row['id'], 'supprimer', 'Supprimer…', 'danger');
    } else {
        $actions = '<span class="muted">Purge automatique sous 7 jours</span>';
    }
    $lines .= '<tr><td>' . (int) $row['id'] . '</td>'
        . '<td><strong>' . h(trim($row['prenom'] . ' ' . $row['nom'])) . '</strong>'
        . ($quality !== '' ? '<br><span class="muted">' . h($quality) . '</span>' : '') . '</td>'
        . '<td class="email">' . h($row['email']) . '</td>'
        . '<td class="dates">Demande : ' . when((int) $row['created_at']) . '<br>Confirmée : ' . when($row['confirmed_at'] === null ? null : (int) $row['confirmed_at']) . '</td>'
        . '<td><span class="badge ' . $stateClass . '">' . h($stateLabel) . '</span></td>'
        . '<td><div class="row-actions">' . $actions . '</div></td></tr>';
}

page('Administration des signatures', '<h1>Administration des signatures</h1>'
    . '<p class="muted">Accès valable jusqu’à ' . date('H:i', (int) $exp) . '. Les signatures validées apparaissent sur www.otspi.org au prochain rafraîchissement quotidien.</p>'
    . $flash
    . '<nav class="tabs" aria-label="Filtrer les signatures">' . $tabs . '</nav>'
    . ($rows === []
        ? '<p>Aucune signature dans cette catégorie.</p>'
        : '<div class="table-wrap"><table class="admin-table"><thead><tr><th scope="col">#</th><th scope="col">Signataire</th>'
            . '<th scope="col">E-mail</th><th scope="col">Dates</th><th scope="col">État</th><th scope="col">Actions</th></tr></thead>'
            . '<tbody>' . $lines . '</tbody></table></div>'), 'fr', true);
