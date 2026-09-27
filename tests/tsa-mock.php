<?php
// SPDX-License-Identifier: EUPL-1.2
// Autorité d'horodatage factice pour tests/flow.sh : même API JSON que le staging (POST /api/v1/timestamp),
// jetons RFC 3161 signés par « openssl ts » avec la CA de test de /work/tsa. Le fichier /work/tsa/panne simule
// une autorité indisponible.

declare(strict_types=1);

$dir = '/work/tsa';
header('Content-Type: application/json');
if (is_file("$dir/panne")) {
    http_response_code(503);
    exit(json_encode(['error' => 'panne simulée']));
}
$in = json_decode((string) file_get_contents('php://input'), true);
$hash = (string) ($in['hash'] ?? '');
if (preg_match('/^[0-9a-f]{64}$/', $hash) !== 1) {
    http_response_code(400);
    exit(json_encode(['error' => 'empreinte invalide']));
}
$query = tempnam(sys_get_temp_dir(), 'tsq');
$reply = tempnam(sys_get_temp_dir(), 'tsr');
exec("openssl ts -query -digest $hash -sha256 -cert -out $query 2>/dev/null && openssl ts -reply -config $dir/tsa.cnf -queryfile $query -out $reply 2>/dev/null", $output, $code);
if ($code !== 0) {
    http_response_code(500);
    exit(json_encode(['error' => 'openssl ts a échoué']));
}
echo json_encode(['granted' => true, 'token' => base64_encode((string) file_get_contents($reply)), 'gen_time' => gmdate('c'), 'hash_algorithm' => 'sha256']);
