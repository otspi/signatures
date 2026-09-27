<?php
// SPDX-License-Identifier: EUPL-1.2
// Compteur de signatures en image SVG, à intégrer sur d'autres sites (lien vers le manifeste) :
//   <a href="https://www.otspi.org/manifeste.html"><img src="https://manifesto-sign.otspi.org/compteur.php" alt="…"></a>
// ?lang=en pour l'anglais. Le total est celui de la liste publique (signatures confirmées, hors attente de
// modération). Une simple image : ni script, ni cookie, ni traceur.

declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
require __DIR__ . '/../src/registre.php';

$lang = lang();
$total = (int) json_decode(public_list_json(), true)['total'];
$left = $lang === 'en' ? 'OTSPI manifesto' : 'Manifeste OTSPI';
$right = number_format($total, 0, ',', $lang === 'en' ? ',' : ' ') . ' ' . ($lang === 'en' ? 'signator' . ($total === 1 ? 'y' : 'ies') : 'signataire' . ($total > 1 ? 's' : ''));
// Largeur estimée des textes (Verdana 11 px : environ 7 px par caractère), sans mesure côté client.
$width = static fn (string $text): int => (int) ceil(mb_strlen($text) * 7 + 20);
[$w1, $w2] = [$width($left), $width($right)];

header('Content-Type: image/svg+xml; charset=UTF-8');
header('Cache-Control: public, max-age=600');
header('Content-Security-Policy: default-src \'none\'');
header('Cross-Origin-Resource-Policy: cross-origin');
header('X-Content-Type-Options: nosniff');
echo '<svg xmlns="http://www.w3.org/2000/svg" width="' . ($w1 + $w2) . '" height="28" role="img" aria-label="' . h($left . ' : ' . $right) . '">'
    . '<title>' . h($left . ' : ' . $right) . '</title>'
    . '<clipPath id="r"><rect width="' . ($w1 + $w2) . '" height="28" rx="6"/></clipPath><g clip-path="url(#r)">'
    . '<rect width="' . $w1 . '" height="28" fill="#0f2042"/><rect x="' . $w1 . '" width="' . $w2 . '" height="28" fill="#ffcc00"/></g>'
    . '<g font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
    . '<text x="' . intdiv($w1, 2) . '" y="18" fill="#ffffff">' . h($left) . '</text>'
    . '<text x="' . ($w1 + intdiv($w2, 2)) . '" y="18" fill="#0f2042" font-weight="bold">' . h($right) . '</text></g></svg>';
