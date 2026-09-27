<?php
// SPDX-License-Identifier: EUPL-1.2
// Administration des signatures (page interne, en français). Connexion uniquement par clé de sécurité
// (WebAuthn, YubiKey avec code PIN : voir src/passkey.php) ; ni mot de passe ni lien de connexion. Une clé
// s'enregistre par un lien d'invitation envoyé à la seule adresse de contact (tant qu'aucune clé n'existe,
// ou par php bin/admin.php invitation), ou depuis une session ouverte. Les actions sont en POST depuis le
// site lui-même, et la suppression demande une confirmation.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/passkey.php';

const ADMIN_INVITES_PER_10_MIN = 3;   // plafond global d'invitations envoyées depuis la page de connexion

const FILTERS = [
    'attente' => ['À modérer', 'confirmed_at IS NOT NULL AND publier = 1 AND approved_at IS NULL'],
    'publiees' => ['Publiées', 'confirmed_at IS NOT NULL AND publier = 1 AND approved_at IS NOT NULL'],
    'non-publiees' => ['Non publiées', 'confirmed_at IS NOT NULL AND publier = 0'],
    'non-confirmees' => ['En attente de confirmation', 'confirmed_at IS NULL'],
    'toutes' => ['Toutes', '1 = 1'],
];

const DONE = [
    'valider' => ['notice', 'Signature #%d validée : elle sera publiée au prochain rafraîchissement de la liste.'],
    'masquer' => ['notice', 'Signature #%d masquée.'],
    'supprimer' => ['notice', 'Signature #%d supprimée.'],
    'renvoyer' => ['notice', 'Lien de confirmation renvoyé pour la demande #%d, valable 48 heures.'],
    'trop-tot' => ['error', 'Demande #%d : un e-mail lui a été envoyé il y a moins de 10 minutes, réessayez plus tard.'],
    'echec' => ['error', 'Demande #%d : l’e-mail n’a pas pu être envoyé.'],
    'rien' => ['error', 'Signature #%d introuvable ou dans un autre état : aucune modification.'],
    'valider-lot' => ['notice', '%d signature(s) validée(s) : elles seront publiées dans quelques minutes.'],
    'masquer-lot' => ['notice', '%d signature(s) masquée(s).'],
    'lot-vide' => ['error', 'Aucune signature sélectionnée.'],
    'cle' => ['notice', 'Clé de sécurité enregistrée.'],
    'revoquee' => ['notice', 'Clé #%d révoquée.'],
    'derniere' => ['error', 'La clé #%d est la seule enregistrée : ajoutez-en une autre avant de la révoquer.'],
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
        $row['confirmed_at'] === null => ['En attente de confirmation', 'muted'],
        (int) $row['publier'] === 1 && $row['approved_at'] === null => ['À modérer', 'pending'],
        (int) $row['publier'] === 1 => ['Publiée', 'ok'],
        $row['approved_at'] !== null => ['Masquée', 'muted'],
        default => ['Non publiée (choix de l’auteur)', 'muted'],
    };
}

function admin_page(string $title, string $body, bool $wide = false): void
{
    page($title, $body, 'fr', $wide, script: 'assets/admin.js');
}

function redirect(array $query = []): never
{
    // Post/Redirect/Get : un rechargement de la page ne rejoue pas l'action.
    header('Location: ' . url('admin.php', $query), true, 303);
    exit;
}

/** Formulaire qui interroge la clé de sécurité (assets/admin.js) puis envoie sa réponse. */
function webauthn_form(string $mode, array $options, array $fields, string $button, string $extra = ''): string
{
    return '<form method="post" action="admin.php" data-webauthn="' . $mode . '" data-options="' . h(json_encode($options, JSON_UNESCAPED_SLASHES)) . '">'
        . hidden_inputs($fields + ['reponse' => '']) . $extra
        . '<p><button type="submit">' . h($button) . '</button></p>'
        . '<p class="webauthn-status muted" role="status"></p></form>';
}

function key_response(): array
{
    $response = json_decode((string) ($_POST['reponse'] ?? ''), true);
    return is_array($response) ? $response : [];
}

/**
 * Enregistre la clé dont la réponse est postée, pour un défi émis pour $ref. Avec une invitation, celle-ci
 * est consommée et la session ouverte. Prévient l'adresse de contact. Renvoie un message d'erreur, ou redirige.
 */
function register_key(string $ref, ?string $inviteHash): string
{
    try {
        $key = passkey_verify_registration(key_response(), $ref);
    } catch (PasskeyRefused $e) {
        error_log('otspi-signatures : enregistrement de clé refusé (' . $e->getMessage() . ')');
        return 'La clé n’a pas pu être enregistrée (délai dépassé, code PIN absent ou modèle non autorisé). Réessayez.';
    }
    $name = clean((string) ($_POST['nom'] ?? ''), 60) ?? 'Clé de sécurité';
    $pdo = db();
    $pdo->exec('BEGIN IMMEDIATE');
    if ($inviteHash !== null) {
        $use = $pdo->prepare("DELETE FROM admin_tokens WHERE hash = ? AND kind = 'invitation'");
        $use->execute([$inviteHash]);
        if ($use->rowCount() !== 1) {
            $pdo->exec('ROLLBACK');
            return 'Ce lien d’enregistrement vient d’être utilisé.';
        }
    }
    $insert = $pdo->prepare('INSERT INTO admin_keys (credential_id, public_key, sign_count, aaguid, transports, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING');
    $insert->execute([$key['credential_id'], $key['public_key'], $key['sign_count'], $key['aaguid'], $key['transports'], $name, time()]);
    if ($insert->rowCount() !== 1) {
        $pdo->exec('ROLLBACK');
        return 'Cette clé est déjà enregistrée.';
    }
    $id = (int) $pdo->lastInsertId();
    $pdo->exec('COMMIT');
    send_mail(config()['contact'], 'Nouvelle clé de sécurité pour l’administration des signatures',
        "Une clé de sécurité vient d'être enregistrée pour l'administration des signatures :\n\n"
        . "  #{$id} {$name}, le " . date('d/m/Y à H:i') . ($inviteHash !== null ? ", par lien d'invitation" : ', depuis une session ouverte') . "\n\n"
        . "Si ce n'est pas vous, révoquez-la sans attendre : " . url('admin.php', ['vue' => 'cles']) . "\n"
        . "ou, sur le serveur : php bin/admin.php revoquer {$id}\n");
    if ($inviteHash !== null) {
        admin_login($id);
    }
    redirect(['vue' => 'cles', 'fait' => 'cle']);
}

/** Renvoie un lien de confirmation (nouveau jeton, 48 h) à une demande non confirmée ; résultat pour DONE. */
function resend_confirmation(int $id): string
{
    $row = db()->prepare('SELECT id, email, prenom, nom, fonction, organisation, publier, lang, last_mail_at FROM signatures WHERE id = ? AND confirmed_at IS NULL');
    $row->execute([$id]);
    $signature = $row->fetch();
    if ($signature === false) {
        return 'rien';
    }
    if (time() - (int) $signature['last_mail_at'] <= 600) {
        return 'trop-tot';
    }
    $token = new_token();
    db()->prepare('UPDATE signatures SET confirm_hash = ?, created_at = ?, last_mail_at = ? WHERE id = ? AND confirmed_at IS NULL')
        ->execute([token_hash($token), time(), time(), $id]);
    return send_confirmation($signature, $token, $signature['lang'] === 'en' ? 'en' : 'fr') ? 'renvoyer' : 'echec';
}

$post = $_SERVER['REQUEST_METHOD'] === 'POST';
$action = (string) ($_POST['a'] ?? '');
$invitation = (string) ($_GET['inv'] ?? $_POST['inv'] ?? '');

// ---- Enregistrement d'une clé par lien d'invitation --------------------------------------------

if ($invitation !== '') {
    $invite = admin_token_find('invitation', $invitation);
    if ($invite === null) {
        http_response_code(403);
        admin_page('Lien d’enregistrement invalide', '<h1>Lien d’enregistrement invalide</h1>'
            . '<p>Ce lien est invalide, a expiré ou a déjà servi. Une personne déjà connectée peut ajouter une clé depuis l’administration ; '
            . 'sinon, un nouveau lien s’obtient sur le serveur avec <code>php bin/admin.php invitation</code>.</p>');
        exit;
    }
    $ref = 'invitation:' . $invite['hash'];
    $error = '';
    if ($post && $action === 'enregistrer') {
        $error = cross_site_post() ? 'Requête envoyée depuis un autre site : refusée.' : register_key($ref, $invite['hash']);
    }
    admin_page('Enregistrer une clé de sécurité', '<h1>Enregistrer une clé de sécurité</h1>'
        . ($error !== '' ? '<p class="error" role="alert">' . h($error) . '</p>' : '')
        . '<p>Branchez la clé de sécurité (YubiKey) sur cet ordinateur. Le navigateur demandera son code PIN, ou de le créer s’il n’existe pas encore : '
        . 'la connexion à l’administration exigera ensuite la clé <strong>et</strong> ce code PIN.</p>'
        . '<p class="muted">Lien à usage unique, valable jusqu’au ' . date('d/m/Y à H:i', (int) $invite['expires_at']) . '.</p>'
        . webauthn_form('create', admin_creation_options(admin_challenge('cle', $ref)), ['a' => 'enregistrer', 'inv' => $invitation],
            'Enregistrer la clé', '<p><label>Nom de la clé<br><input type="text" name="nom" maxlength="60" required value="YubiKey"></label></p>'));
    exit;
}

// ---- Sans session : connexion par clé ----------------------------------------------------------

$session = admin_session();
if ($session === null) {
    $message = '';
    if ($post && cross_site_post()) {
        http_response_code(400);
        $message = '<p class="error" role="alert">Requête envoyée depuis un autre site : refusée.</p>';
    } elseif ($post && $action === 'connexion') {
        try {
            $key = passkey_verify_login(key_response());
            admin_login((int) $key['id']);
            redirect();
        } catch (PasskeyRefused $e) {
            error_log('otspi-signatures : connexion à l\'administration refusée (' . $e->getMessage() . ')');
            http_response_code(403);
            $message = '<p class="error" role="alert">Connexion refusée : clé inconnue, code PIN non vérifié ou délai dépassé. Réessayez.</p>';
        }
    } elseif ($post && $action === 'invitation' && admin_key_count() === 0) {
        $pdo = db();
        $bucket = hash_hmac('sha256', 'admin-invitation', config()['secret']);
        $count = $pdo->prepare('SELECT COUNT(*) FROM hits WHERE ip_hash = ? AND at > ?');
        $count->execute([$bucket, time() - 600]);
        if ((int) $count->fetchColumn() >= ADMIN_INVITES_PER_10_MIN) {
            $message = '<p class="error" role="alert">Trop de liens demandés : réessayez dans quelques minutes.</p>';
        } else {
            $pdo->prepare('INSERT INTO hits (ip_hash, at) VALUES (?, ?)')->execute([$bucket, time()]);
            $message = admin_send_invitation()
                ? '<p role="status">Un lien d’enregistrement, valable 24 heures, vient d’être envoyé à l’adresse de contact de l’initiative.</p>'
                : '<p class="error" role="alert">L’e-mail n’a pas pu être envoyé. Réessayez plus tard.</p>';
        }
    } elseif ($post) {
        $message = '<p class="error" role="alert">Session expirée : reconnectez-vous, puis recommencez l’action.</p>';
    }
    $body = admin_key_count() === 0
        ? '<p>Aucune clé de sécurité n’est encore enregistrée. Un lien d’enregistrement, valable 24 heures et à usage unique, '
            . 'peut être envoyé à l’adresse de contact de l’initiative.</p>'
            . '<form method="post" action="admin.php">' . hidden_inputs(['a' => 'invitation'])
            . '<button type="submit">Envoyer le lien d’enregistrement</button></form>'
        : '<p>La connexion se fait uniquement avec une clé de sécurité enregistrée (YubiKey) et son code PIN.</p>'
            . webauthn_form('get', admin_request_options(admin_challenge('connexion')), ['a' => 'connexion'], 'Se connecter avec la clé de sécurité');
    admin_page('Administration des signatures', '<h1>Administration des signatures</h1>' . $message . $body);
    exit;
}

// ---- Actions (POST) ----------------------------------------------------------------------------

$view = (string) ($_GET['vue'] ?? $_POST['vue'] ?? '') === 'cles' ? 'cles' : 'signatures';
$filter = (string) ($_GET['f'] ?? $_POST['f'] ?? 'attente');
$filter = isset(FILTERS[$filter]) ? $filter : 'attente';
$here = $view === 'cles' ? ['vue' => 'cles'] : ['f' => $filter];
$sessionRef = 'session:' . $session['hash'];
$pdo = db();
$keyError = '';

if ($post) {
    $id = (int) ($_POST['id'] ?? 0);
    $known = in_array($action, [...MODERATION_ACTIONS, 'renvoyer', 'revoquer', 'ajouter-cle', 'deconnexion', 'valider-lot', 'masquer-lot'], true);
    if (cross_site_post() || !$known || ($id <= 0 && !in_array($action, ['ajouter-cle', 'deconnexion', 'valider-lot', 'masquer-lot'], true))) {
        error_log(sprintf('otspi-signatures : action d\'administration refusée (#%d, action « %s », Sec-Fetch-Site=%s, Origin=%s)',
            $id, $action, $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '-', $_SERVER['HTTP_ORIGIN'] ?? '-'));
        http_response_code(400);
        admin_page('Administration des signatures', '<h1>Action refusée</h1><p>Requête invalide ou envoyée depuis un autre site.</p>'
            . '<p><a href="' . h(url('admin.php', $here)) . '">Retour</a></p>');
        exit;
    }
    if ($action === 'deconnexion') {
        admin_logout();
        redirect();
    }
    if ($action === 'valider-lot' || $action === 'masquer-lot') {
        // Modération par lot : seulement valider ou masquer ; la suppression reste unitaire et confirmée.
        $ids = array_slice(array_unique(array_filter(array_map('intval', (array) ($_POST['ids'] ?? [])), static fn (int $i): bool => $i > 0)), 0, 500);
        $done = 0;
        foreach ($ids as $selected) {
            $done += moderate($selected, $action === 'valider-lot' ? 'valider' : 'masquer') ? 1 : 0;
        }
        redirect($here + ['fait' => $ids === [] ? 'lot-vide' : $action, 'id' => $done]);
    }
    if ($action === 'ajouter-cle') {
        $keyError = register_key($sessionRef, null);
    } elseif ($action === 'revoquer') {
        $pdo->exec('BEGIN IMMEDIATE');
        $done = 'rien';
        if (admin_key_count() <= 1) {
            $done = 'derniere';
        } else {
            $delete = $pdo->prepare('DELETE FROM admin_keys WHERE id = ?');
            $delete->execute([$id]);
            if ($delete->rowCount() === 1) {
                // Les sessions ouvertes avec cette clé sont fermées aussi.
                $pdo->prepare("DELETE FROM admin_tokens WHERE kind = 'session' AND ref = ?")->execute([(string) $id]);
                $done = 'revoquee';
            }
        }
        $pdo->exec('COMMIT');
        redirect(['vue' => 'cles', 'fait' => $done, 'id' => $id]);
    } elseif ($action === 'renvoyer') {
        redirect($here + ['fait' => resend_confirmation($id), 'id' => $id]);
    } else {
        if ($action === 'supprimer' && ($_POST['ok'] ?? '') !== '1') {
            $row = $pdo->prepare('SELECT id, email, prenom, nom, fonction, organisation, publier, confirmed_at, approved_at FROM signatures WHERE id = ?');
            $row->execute([$id]);
            $signature = $row->fetch();
            if ($signature !== false) {
                admin_page('Supprimer la signature #' . $id, '<h1>Supprimer la signature #' . $id . ' ?</h1>'
                    . '<p>La signature et ses données sont effacées définitivement. État : ' . h(state($signature)[0]) . '. E-mail : ' . h($signature['email']) . '</p>'
                    . recap_html($signature, 'fr')
                    . '<div class="moderation-actions"><form method="post" action="admin.php">'
                    . hidden_inputs($here + ['a' => 'supprimer', 'id' => $id, 'ok' => '1'])
                    . '<button type="submit" class="danger">Supprimer définitivement</button></form>'
                    . '<a class="button secondary" href="' . h(url('admin.php', $here)) . '">Annuler</a></div>');
                exit;
            }
        }
        redirect($here + ['fait' => moderate($id, $action) ? $action : 'rien', 'id' => $id]);
    }
}

// ---- Pages -------------------------------------------------------------------------------------

$flash = '';
$doneAction = (string) ($_GET['fait'] ?? '');
if (isset(DONE[$doneAction])) {
    [$class, $text] = DONE[$doneAction];
    $flash = '<p class="' . $class . '" role="' . ($class === 'error' ? 'alert' : 'status') . '">' . h(sprintf($text, (int) ($_GET['id'] ?? 0))) . '</p>';
}
if ($keyError !== '') {
    $flash .= '<p class="error" role="alert">' . h($keyError) . '</p>';
}

$nav = '<nav class="admin-nav" aria-label="Administration">'
    . '<a href="admin.php"' . ($view === 'signatures' ? ' aria-current="page"' : '') . '>Signatures</a>'
    . '<a href="' . h(url('admin.php', ['vue' => 'cles'])) . '"' . ($view === 'cles' ? ' aria-current="page"' : '') . '>Clés de sécurité</a>'
    . '<form method="post" action="admin.php">' . hidden_inputs(['a' => 'deconnexion'])
    . '<button type="submit" class="small secondary">Se déconnecter</button></form></nav>';

$button = static fn (int $id, string $action, string $label, string $class = ''): string =>
    '<form method="post" action="admin.php">' . hidden_inputs($here + ['a' => $action, 'id' => $id])
    . '<button type="submit" class="small' . ($class !== '' ? ' ' . $class : '') . '">' . h($label) . '</button></form>';

if ($view === 'cles') {
    $keys = $pdo->query('SELECT id, name, aaguid, created_at, last_used_at FROM admin_keys ORDER BY id')->fetchAll();
    $lines = '';
    foreach ($keys as $key) {
        $lines .= '<tr><td>' . (int) $key['id'] . '</td><td><strong>' . h($key['name']) . '</strong>'
            . ((string) $key['id'] === $session['ref'] ? ' <span class="badge ok">session en cours</span>' : '') . '</td>'
            . '<td class="email">' . h($key['aaguid'] !== '' && $key['aaguid'] !== '00000000-0000-0000-0000-000000000000' ? $key['aaguid'] : 'non communiqué') . '</td>'
            . '<td class="dates">Ajoutée : ' . when((int) $key['created_at']) . '<br>Utilisée : ' . when($key['last_used_at'] === null ? null : (int) $key['last_used_at']) . '</td>'
            . '<td><div class="row-actions">' . (count($keys) > 1 ? $button((int) $key['id'], 'revoquer', 'Révoquer', 'danger') : '<span class="muted">Seule clé</span>') . '</div></td></tr>';
    }
    admin_page('Clés de sécurité', '<h1>Clés de sécurité</h1>' . $nav . $flash
        . '<p>Seules ces clés ouvrent l’administration, avec leur code PIN. Enregistrez une seconde clé, gardée en lieu sûr, pour ne pas perdre l’accès.</p>'
        . '<div class="table-wrap"><table class="admin-table"><thead><tr><th scope="col">#</th><th scope="col">Nom</th>'
        . '<th scope="col">Modèle (AAGUID)</th><th scope="col">Dates</th><th scope="col">Actions</th></tr></thead>'
        . '<tbody>' . $lines . '</tbody></table></div>'
        . '<h2>Ajouter une clé</h2>'
        . webauthn_form('create', admin_creation_options(admin_challenge('cle', $sessionRef)), ['a' => 'ajouter-cle', 'vue' => 'cles'],
            'Enregistrer une nouvelle clé', '<p><label>Nom de la clé<br><input type="text" name="nom" maxlength="60" required value="YubiKey de secours"></label></p>'), true);
    exit;
}

$tabs = '';
foreach (FILTERS as $key => [$label, $where]) {
    $count = (int) $pdo->query('SELECT COUNT(*) FROM signatures WHERE ' . $where)->fetchColumn();
    $tabs .= '<a href="' . h(url('admin.php', ['f' => $key])) . '"' . ($key === $filter ? ' aria-current="page"' : '') . '>'
        . h($label) . ' <span class="count">' . $count . '</span></a>';
}

$rows = $pdo->query('SELECT id, email, prenom, nom, fonction, organisation, publier, lang, created_at, last_mail_at, confirmed_at, approved_at, proof_at FROM signatures WHERE '
    . FILTERS[$filter][1] . ' ORDER BY COALESCE(confirmed_at, created_at) DESC, id DESC LIMIT 500')->fetchAll();

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
    } else {
        $actions .= $button((int) $row['id'], 'renvoyer', 'Renvoyer le lien', 'secondary');
    }
    $actions .= $button((int) $row['id'], 'supprimer', 'Supprimer…', 'danger');
    $dates = 'Demande : ' . when((int) $row['created_at']) . '<br>'
        . ($row['confirmed_at'] !== null
            ? 'Confirmée : ' . when((int) $row['confirmed_at']) . '<br>Horodatée : ' . when($row['proof_at'] === null ? null : (int) $row['proof_at'])
            : 'Dernier e-mail : ' . when((int) $row['last_mail_at']) . '<br>Purge : ' . when((int) $row['created_at'] + UNCONFIRMED_TTL));
    [$hint, $hintClass] = email_org_hint($row['email'], $row['organisation']);
    $pending = $row['confirmed_at'] !== null && (int) $row['publier'] === 1 && $row['approved_at'] === null;
    $lines .= '<tr><td>' . ($pending ? '<input type="checkbox" name="ids[]" value="' . (int) $row['id'] . '" form="lot" aria-label="Sélectionner la signature #' . (int) $row['id'] . '"> ' : '') . (int) $row['id'] . '</td>'
        . '<td><strong>' . h(trim($row['prenom'] . ' ' . $row['nom'])) . '</strong>'
        . ($quality !== '' ? '<br><span class="muted">' . h($quality) . '</span>' : '') . '</td>'
        . '<td class="email">' . h($row['email']) . '<br><span class="badge ' . $hintClass . '" title="Estimation à partir du domaine, pas une vérification">' . h($hint) . '</span></td>'
        . '<td class="dates">' . $dates . '</td>'
        . '<td><span class="badge ' . $stateClass . '">' . h($stateLabel) . '</span></td>'
        . '<td><div class="row-actions">' . $actions . '</div></td></tr>';
}

admin_page('Administration des signatures', '<h1>Administration des signatures</h1>' . $nav
    . '<p class="muted">Les signatures validées apparaissent sur www.otspi.org en quelques minutes. '
    . 'Une demande non confirmée peut recevoir un nouveau lien (48 heures) ; sans confirmation, elle est purgée au bout de 7 jours.</p>'
    . $flash
    . '<nav class="tabs" aria-label="Filtrer les signatures">' . $tabs . '</nav>'
    . ($filter === 'attente' && $rows !== []
        ? '<form method="post" action="admin.php" id="lot" class="bulk-actions">' . hidden_inputs($here)
            . '<label><input type="checkbox" data-select-all> Tout sélectionner</label>'
            . '<button type="submit" name="a" value="valider-lot" class="small">Valider la sélection</button>'
            . '<button type="submit" name="a" value="masquer-lot" class="small secondary">Masquer la sélection</button></form>'
        : '')
    . ($rows === []
        ? '<p>Aucune signature dans cette catégorie.</p>'
        : '<div class="table-wrap"><table class="admin-table"><thead><tr><th scope="col">#</th><th scope="col">Signataire</th>'
            . '<th scope="col">E-mail</th><th scope="col">Dates</th><th scope="col">État</th><th scope="col">Actions</th></tr></thead>'
            . '<tbody>' . $lines . '</tbody></table></div>'), true);
