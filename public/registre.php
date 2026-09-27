<?php
// SPDX-License-Identifier: EUPL-1.2
// Registre public horodaté de la liste des signataires (src/registre.php) : état de la chaîne, dernières entrées
// avec leur horodatage vérifié par le serveur, téléchargement de chaque entrée (?n=…&f=json) et de son jeton
// (?n=…&f=tsr), et mode d'emploi pour vérifier soi-même. Page publique, sans donnée personnelle.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/horodatage.php';
require __DIR__ . '/../src/registre.php';

const REGISTRY_SHOWN = 60;

$file = (string) ($_GET['f'] ?? '');
if (in_array($file, ['json', 'tsr'], true)) {
    $row = db()->prepare('SELECT numero, entree, jeton FROM registre WHERE numero = ?');
    $row->execute([(int) ($_GET['n'] ?? 0)]);
    $entry = $row->fetch();
    if ($entry === false || ($file === 'tsr' && $entry['jeton'] === null)) {
        http_response_code(404);
        page('Registre horodaté', '<h1>Registre horodaté</h1><p>Entrée introuvable.</p>', 'fr');
        exit;
    }
    header('Content-Type: ' . ($file === 'json' ? 'application/json; charset=UTF-8' : 'application/timestamp-reply'));
    header('Content-Disposition: attachment; filename="registre-' . (int) $entry['numero'] . '.' . $file . '"');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: public, max-age=3600');
    echo $file === 'json' ? $entry['entree'] : base64_decode($entry['jeton']);
    exit;
}

$count = (int) db()->query('SELECT COUNT(*) FROM registre')->fetchColumn();
$broken = registry_broken_link();
$status = match (true) {
    $count === 0 => '<p class="proof-status pending" role="status">Le registre démarre : sa première entrée sera inscrite cette nuit.</p>',
    $broken !== null => '<p class="proof-status error" role="alert">Chaînage rompu à l’entrée n° ' . $broken . '.</p>',
    default => '<p class="proof-status ok" role="status"><span aria-hidden="true">✓</span> Chaîne intègre : ' . $count . ' entrée' . ($count > 1 ? 's' : '') . ' chaînée' . ($count > 1 ? 's' : '') . '</p>',
};

$lines = '';
$rows = db()->prepare('SELECT numero, jour, entree, jeton FROM registre ORDER BY numero DESC LIMIT ?');
$rows->execute([REGISTRY_SHOWN]);
foreach ($rows->fetchAll() as $row) {
    $entry = json_decode($row['entree'], true);
    $stamp = '<span class="muted">En attente</span>';
    if ($row['jeton'] !== null) {
        try {
            $details = tsa_verify(base64_decode($row['jeton']), hash('sha256', $row['entree'], true));
            $stamp = '<span class="badge ok">✓ ' . h((new DateTimeImmutable('@' . $details['gen_time']))->setTimezone(new DateTimeZone('Europe/Paris'))->format('d/m/Y H:i:s')) . '</span>';
        } catch (TimestampInvalid $e) {
            $stamp = '<span class="badge muted">Jeton invalide</span>';
        }
    }
    $n = (int) $row['numero'];
    $lines .= '<tr><td>' . $n . '</td><td class="dates">' . h(date('d/m/Y', (int) strtotime($row['jour']))) . '</td>'
        . '<td>' . (int) $entry['total'] . '</td><td>' . (int) $entry['noms_publies'] . '</td>'
        . '<td class="email"><code title="' . h($entry['liste_sha256']) . '">' . h(substr($entry['liste_sha256'], 0, 16)) . '…</code></td>'
        . '<td>' . $stamp . '</td>'
        . '<td><a href="registre.php?n=' . $n . '&amp;f=json" download>entrée</a>'
        . ($row['jeton'] !== null ? ' · <a href="registre.php?n=' . $n . '&amp;f=tsr" download>jeton</a>' : '') . '</td></tr>';
}

page('Registre horodaté', '<h1>Registre horodaté des signataires</h1>' . $status
    . '<p>Chaque nuit, une entrée fige le nombre de signatures, le nombre de noms publiés et l’empreinte SHA-256 de la '
    . '<a href="signataires.php">liste publique</a> telle qu’elle est servie à cet instant. Chaque entrée contient l’empreinte de la précédente, '
    . 'puis elle est horodatée (RFC 3161) par l’autorité d’horodatage d’OTSPI : l’historique ne peut pas être réécrit sans que cela se voie. '
    . 'Le registre ne conserve aucun nom : une signature retirée disparaît de la base, seules les empreintes restent.</p>'
    . ($lines === '' ? '' : '<div class="table-wrap"><table class="admin-table"><thead><tr><th scope="col">N°</th><th scope="col">Jour</th>'
        . '<th scope="col">Signatures</th><th scope="col">Noms publiés</th><th scope="col">Empreinte de la liste</th>'
        . '<th scope="col">Horodatage</th><th scope="col">Fichiers</th></tr></thead><tbody>' . $lines . '</tbody></table></div>')
    . '<h2>Vérifier soi-même</h2>'
    . '<ol><li>Liste conservée un jour donné : son empreinte (<code>sha256sum signataires.json</code>) doit être égale au champ <code>liste_sha256</code> de l’entrée du jour.</li>'
    . '<li>Chaînage : l’empreinte d’une entrée (<code>sha256sum registre-N.json</code>) est le champ <code>precedente_sha256</code> de l’entrée suivante.</li>'
    . '<li>Horodatage : sur le <a href="https://demo.open-eidas.eu/#verifier">vérificateur de la démonstration</a>, déposez l’entrée et son jeton, ou avec OpenSSL et la '
    . '<a href="' . h(tsa_url() . '/api/v1/certificate') . '">chaîne de l’autorité</a> :</li></ol>'
    . '<pre><code>openssl ts -verify -data registre-N.json -in registre-N.tsr -CAfile chaine.pem</code></pre>'
    . '<p class="notice">Autorité de démonstration (staging) : ces jetons ne sont pas qualifiés au sens du règlement eIDAS et n’ont aucune valeur juridique.</p>',
    'fr', true, audience: true);
