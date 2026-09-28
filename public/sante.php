<?php
// SPDX-License-Identifier: EUPL-1.2
// État de santé de l'application, pour la surveillance externe (.github/workflows/surveillance.yml) : base,
// tâche quotidienne, sauvegarde, registre horodaté, horodatage des signatures, autorité d'horodatage.
// JSON sans aucune donnée personnelle ; HTTP 200 si tout va bien, 503 sinon. Un contrôle jamais encore exécuté
// (juste après une mise en service) est « en attente », pas en échec.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/horodatage.php';

const MAX_AGE = 93600;           // 26 h : la tâche quotidienne a au plus deux heures de retard
const STAGING_CHECK_TTL = 300;   // l'autorité d'horodatage n'est interrogée qu'une fois toutes les 5 minutes

$iso = static fn (?int $t): ?string => $t === null ? null : gmdate('Y-m-d\TH:i:s\Z', $t);
$recent = static function (?array $state) use ($iso): array {
    return $state === null
        ? ['ok' => true, 'etat' => 'en attente du premier passage', 'derniere' => null]
        : ['ok' => time() - (int) $state['at'] <= MAX_AGE, 'etat' => $state['valeur'], 'derniere' => $iso((int) $state['at'])];
};

$checks = [];
try {
    db()->query('SELECT 1 FROM signatures LIMIT 1')->fetchColumn();
    $checks['base'] = ['ok' => true];
} catch (Throwable $e) {
    error_log('otspi-signatures : santé, base inaccessible : ' . $e->getMessage());
    http_response_code(503);
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    exit(json_encode(['statut' => 'alerte', 'controles' => ['base' => ['ok' => false]]]));
}

// Première lecture de cette page : au-delà de 26 h sans aucun passage, la tâche quotidienne ne tourne pas.
if (etat_get('premiere_lecture') === null) {
    etat_set('premiere_lecture', 'sante');
}
$watchedSince = (int) etat_get('premiere_lecture')['at'];
$task = etat_get('tache');
$checks['tache_quotidienne'] = $recent($task);
if ($task === null && time() - $watchedSince > MAX_AGE) {
    $checks['tache_quotidienne'] = ['ok' => false, 'etat' => 'jamais exécutée depuis la mise en service de la surveillance', 'derniere' => null];
}
if ($task !== null && $task['valeur'] !== 'ok') {
    $checks['tache_quotidienne']['ok'] = false;
}
$checks['sauvegarde'] = $recent(etat_get('sauvegarde'));
if (etat_get('sauvegarde') === null && time() - $watchedSince > MAX_AGE) {
    $checks['sauvegarde']['ok'] = false;
}

$last = db()->query('SELECT jour, jeton IS NOT NULL AS horodatee FROM registre ORDER BY numero DESC LIMIT 1')->fetch();
$checks['registre'] = $last === false
    ? ['ok' => true, 'etat' => 'en attente de la première entrée']
    : ['ok' => $last['jour'] >= date('Y-m-d', time() - 86400) && (int) $last['horodatee'] === 1, 'derniere_entree' => $last['jour']];

$late = db()->prepare('SELECT COUNT(*) FROM signatures WHERE confirmed_at IS NOT NULL AND confirmed_at < ? AND proof_token IS NULL');
$late->execute([time() - 86400]);
$lateCount = (int) $late->fetchColumn();
// Le rattrapage passe par la tâche quotidienne : tant qu'elle n'a jamais tourné, un retard n'est pas une panne.
$checks['horodatage_des_signatures'] = ['ok' => $lateCount === 0 || $task === null, 'en_attente_depuis_24h' => $lateCount];

// Autorité d'horodatage : résultat mis en cache, pour qu'appeler cette page ne revienne pas à solliciter le staging.
$cached = etat_get('autorite');
if ($cached === null || time() - (int) $cached['at'] > STAGING_CHECK_TTL) {
    $context = stream_context_create(['http' => ['method' => 'GET', 'timeout' => 4, 'ignore_errors' => true]]);
    $body = @file_get_contents(tsa_url() . '/api/v1/policy', false, $context);
    $up = is_string($body) && is_array(json_decode($body, true));
    etat_set('autorite', $up ? 'joignable' : 'injoignable');
    $cached = etat_get('autorite');
}
$checks['autorite_horodatage'] = ['ok' => $cached['valeur'] === 'joignable', 'etat' => $cached['valeur'], 'verifiee' => $iso((int) $cached['at'])];

$ok = !in_array(false, array_column($checks, 'ok'), true);
http_response_code($ok ? 200 : 503);
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
echo json_encode(['statut' => $ok ? 'ok' : 'alerte', 'verifie_le' => $iso(time()), 'controles' => $checks],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
