<?php
// SPDX-License-Identifier: EUPL-1.2
// Tâche quotidienne (cron) : supprime les demandes non confirmées de plus de 7 jours ainsi que les empreintes
// de limitation de débit, invitations, défis et sessions d'administration périmés ; horodate les signatures qui
// ne le sont pas encore et envoie leur preuve (src/horodatage.php) ; inscrit l'entrée du jour au registre
// horodaté (src/registre.php) ; envoie la sauvegarde chiffrée de la base (src/sauvegarde.php). Au moindre
// problème, une alerte part à l'adresse de contact (au plus une par passage).

declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
    exit(1);
}
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/horodatage.php';
require __DIR__ . '/../src/registre.php';
require __DIR__ . '/../src/sauvegarde.php';

$pdo = db();
$problems = [];
$step = static function (string $label, callable $task) use (&$problems): mixed {
    try {
        return $task();
    } catch (Throwable $e) {
        error_log('otspi-signatures : tâche quotidienne, ' . $label . ' : ' . $e);
        $problems[] = ucfirst($label) . ' : erreur inattendue (' . $e->getMessage() . ').';
        return false;
    }
};

$old = $pdo->prepare('DELETE FROM signatures WHERE confirmed_at IS NULL AND created_at < ?');
$old->execute([time() - UNCONFIRMED_TTL]);
$pdo->prepare('DELETE FROM hits WHERE at < ?')->execute([time() - 3600]);
$pdo->prepare('DELETE FROM admin_tokens WHERE expires_at < ?')->execute([time()]);
$pdo->prepare('DELETE FROM form_tokens WHERE at < ?')->execute([time() - MAX_FILL_SECONDS]);
echo date('c') . ' purge : ' . $old->rowCount() . " demande(s) non confirmée(s) supprimée(s)\n";

// Horodatage : signatures en attente (autorité injoignable, signatures antérieures) et envoi de leur preuve.
$proofs = $step('horodatage des signatures', 'proof_catch_up');
if ($proofs !== false) {
    echo date('c') . " horodatage : {$proofs['horodatees']} signature(s) horodatée(s), {$proofs['echecs']} échec(s), {$proofs['envoyees']} preuve(s) envoyée(s)\n";
    $late = $pdo->prepare('SELECT COUNT(*) FROM signatures WHERE confirmed_at IS NOT NULL AND confirmed_at < ? AND proof_token IS NULL');
    $late->execute([time() - 86400]);
    $lateCount = (int) $late->fetchColumn();
    if ($proofs['echecs'] > 0) {
        $problems[] = "Horodatage : {$proofs['echecs']} signature(s) n'ont pas pu être horodatées (autorité d'horodatage injoignable ou jeton refusé)."
            . ($lateCount > 0 ? " $lateCount attendent depuis plus de 24 heures." : '');
    }
}

$pending = $step('registre horodaté', 'registry_update');
$broken = $step('registre horodaté', 'registry_broken_link');
echo date('c') . ' registre : ' . ($pending === false ? 'erreur' : "$pending entrée(s) en attente d'horodatage") . "\n";
if ($pending !== false && $pending > 0) {
    $problems[] = "Registre : $pending entrée(s) en attente d'horodatage.";
}
if ($broken !== false && $broken !== null) {
    $problems[] = "Registre : chaînage rompu à l'entrée n° $broken.";
}

$backup = $step('sauvegarde', 'backup_send');
echo date('c') . ' sauvegarde : ' . (is_string($backup) ? $backup : 'échec') . "\n";
if ($backup === null) {
    $problems[] = 'Sauvegarde : la sauvegarde chiffrée de la base n\'a pas pu être envoyée.';
}

if ($problems !== []) {
    send_mail(config()['contact'], 'Alerte : tâche quotidienne des signatures',
        "La tâche quotidienne de l'application de signature a rencontré un problème :\n\n"
        . implode("\n\n", array_map(static fn (string $p): string => '- ' . $p, $problems))
        . "\n\nDétails : data/purge.log et le journal d'erreurs PHP (error_log) sur le serveur. La tâche réessaiera la nuit prochaine ;\n"
        . "pour relancer tout de suite : php cron/purge.php\n\nOTSPI — contact@otspi.org");
    echo date('c') . ' alerte envoyée : ' . count($problems) . " problème(s)\n";
}
