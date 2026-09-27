<?php
// SPDX-License-Identifier: EUPL-1.2
// Ancien lien de modération par e-mail : la modération se fait désormais dans l'administration, ouverte
// uniquement avec une clé de sécurité. Les liens déjà envoyés mènent à la liste des signatures à modérer.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';

header('Location: ' . url('admin.php', ['f' => 'attente']), true, 303);
