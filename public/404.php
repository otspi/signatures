<?php
// SPDX-License-Identifier: EUPL-1.2
// Page d'erreur (404 et 403) aux couleurs de l'application, appelée par ErrorDocument.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

$lang = lang();
$status = (int) ($_SERVER['REDIRECT_STATUS'] ?? 404);
http_response_code($status === 403 ? 403 : 404);
page(t('notfound_title', $lang), '<h1>' . h(t('notfound_title', $lang)) . '</h1><p>' . h(t('notfound', $lang)) . '</p>' . back_to_form($lang), $lang);
