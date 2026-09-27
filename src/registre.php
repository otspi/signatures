<?php
// SPDX-License-Identifier: EUPL-1.2
// Registre public horodaté de la liste des signataires : chaque jour, une entrée fige le total, le nombre de
// noms publiés et l'empreinte SHA-256 de la liste publique (signataires.php), chaînée à l'entrée précédente
// par son empreinte, puis est horodatée (RFC 3161, src/horodatage.php). Qui a conservé la liste d'un jour peut
// prouver qu'elle n'a pas été modifiée, et la chaîne interdit de réécrire l'historique sans que cela se voie.
// Aucun nom n'est conservé dans le registre : une signature retirée disparaît de la base, seules restent
// les empreintes.

declare(strict_types=1);

/** Liste publique, exactement telle que la sert public/signataires.php. */
function public_list_json(): string
{
    $rows = db()->query('SELECT prenom, nom, fonction, organisation FROM signatures WHERE confirmed_at IS NOT NULL AND publier = 1 AND approved_at IS NOT NULL ORDER BY confirmed_at, id')->fetchAll();
    $total = (int) db()->query('SELECT COUNT(*) FROM signatures WHERE confirmed_at IS NOT NULL AND (publier = 0 OR approved_at IS NOT NULL)')->fetchColumn();
    return json_encode(['total' => $total, 'signataires' => $rows], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
}

/**
 * Ajoute l'entrée du jour si elle n'existe pas, puis horodate les entrées qui ne le sont pas encore (autorité
 * injoignable la veille). Renvoie le nombre d'entrées restant à horodater.
 */
function registry_update(): int
{
    $pdo = db();
    $today = date('Y-m-d');
    $exists = $pdo->prepare('SELECT 1 FROM registre WHERE jour = ?');
    $exists->execute([$today]);
    if ($exists->fetchColumn() === false) {
        $last = $pdo->query('SELECT numero, entree FROM registre ORDER BY numero DESC LIMIT 1')->fetch();
        $list = public_list_json();
        $data = json_decode($list, true);
        $entry = json_encode([
            'registre' => 'Liste publique des signataires du manifeste pour une identité numérique libre et ouverte',
            'source' => url('signataires.php'),
            'numero' => $last === false ? 1 : (int) $last['numero'] + 1,
            'jour' => $today,
            'total' => $data['total'],
            'noms_publies' => count($data['signataires']),
            'liste_sha256' => hash('sha256', $list),
            'precedente_sha256' => $last === false ? null : hash('sha256', $last['entree']),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
        $pdo->prepare('INSERT OR IGNORE INTO registre (numero, jour, entree) VALUES (?, ?, ?)')
            ->execute([json_decode($entry, true)['numero'], $today, $entry]);
    }
    $pending = 0;
    foreach ($pdo->query('SELECT numero, entree FROM registre WHERE jeton IS NULL ORDER BY numero')->fetchAll() as $row) {
        try {
            $response = tsa_request(hash('sha256', $row['entree']));
            $details = tsa_verify($response, hash('sha256', $row['entree'], true));
            $pdo->prepare('UPDATE registre SET jeton = ?, horodate_le = ? WHERE numero = ?')->execute([base64_encode($response), $details['gen_time'], $row['numero']]);
        } catch (TimestampInvalid $e) {
            error_log('otspi-signatures : horodatage du registre n° ' . $row['numero'] . ' impossible (' . $e->getMessage() . ')');
            $pending++;
        }
    }
    return $pending;
}

/** Vérifie le chaînage de tout le registre ; renvoie le numéro de la première entrée rompue, ou null. */
function registry_broken_link(): ?int
{
    $previous = null;
    foreach (db()->query('SELECT numero, entree FROM registre ORDER BY numero') as $row) {
        $entry = json_decode($row['entree'], true);
        if (!is_array($entry) || ($entry['precedente_sha256'] ?? null) !== ($previous === null ? null : hash('sha256', $previous))) {
            return (int) $row['numero'];
        }
        $previous = $row['entree'];
    }
    return null;
}
