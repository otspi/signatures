<?php
// SPDX-License-Identifier: EUPL-1.2
// Attestation PDF d'une signature, sans dépendance : une page A4 (polices standard Helvetica, WinAnsi) avec les
// données de la signature et de son horodatage, l'attestation JSON et son jeton RFC 3161 en pièces jointes
// (ISO 32000), et un horodatage PAdES du PDF lui-même (DocTimeStamp, /SubFilter /ETSI.RFC3161) demandé à
// l'autorité d'horodatage (src/horodatage.php), reconnu par Adobe Acrobat Reader, pdfsig ou la démonstration d'OTSPI.

declare(strict_types=1);

const PDF_TOKEN_SPACE = 16384;   // octets réservés au jeton d'horodatage du PDF (/Contents, en hexadécimal)

/** Chaîne PDF littérale en WinAnsi (Windows-1252), caractères spéciaux échappés. */
function pdf_text(string $utf8): string
{
    $text = iconv('UTF-8', 'Windows-1252//TRANSLIT', $utf8);
    return '(' . strtr($text === false ? $utf8 : $text, ['\\' => '\\\\', '(' => '\\(', ')' => '\\)', "\r" => '', "\n" => ' ']) . ')';
}

/** Coupe un texte en lignes d'au plus $max caractères (Helvetica : largeur moyenne d'environ 0,5 em). */
function pdf_wrap(string $text, int $max): array
{
    return explode("\n", wordwrap($text, $max, "\n", true));
}

/**
 * Construit l'attestation PDF. $details = résultat de tsa_verify() pour le jeton de l'attestation. Renvoie
 * [le PDF, vrai s'il porte son propre horodatage PAdES].
 */
function proof_pdf(array $signature, array $details, string $lang): array
{
    $en = $lang === 'en';
    $name = 'signature-otspi-' . (int) $signature['id'];
    $json = (string) $signature['proof_json'];
    $tsr = base64_decode((string) $signature['proof_token']);
    $paris = (new DateTimeImmutable('@' . $details['gen_time']))->setTimezone(new DateTimeZone('Europe/Paris'));
    $attestation = json_decode($json, true);

    // ---- Contenu de la page -------------------------------------------------------------------
    $ops = [];
    $y = 842;
    $line = static function (string $text, string $font = 'F1', float $size = 10.5, float $gap = 15, float $x = 56, string $color = '0.059 0.09 0.165') use (&$ops, &$y): void {
        $y -= $gap;
        $ops[] = "BT /$font $size Tf $color rg $x $y Td " . pdf_text($text) . ' Tj ET';
    };
    $ops[] = '0.059 0.125 0.259 rg 0 772 595 70 re f';                 // bandeau bleu nuit
    $ops[] = '1 0.8 0 rg 0 768 595 4 re f';                            // liseré or
    $y = 822;
    $line('OTSPI', 'F2', 20, 0, 56, '1 1 1');
    $line($en ? 'Manifesto for a free and open digital identity' : 'Manifeste pour une identité numérique libre et ouverte', 'F1', 10, 20, 56, '0.79 0.84 1');
    $y = 745;
    $line($en ? 'Certificate of signature' : 'Attestation de signature', 'F2', 20, 0);
    $line($en ? 'Timestamped by the OTSPI timestamping authority (RFC 3161)' : 'Horodatée par l’autorité d’horodatage d’OTSPI (RFC 3161)', 'F1', 11, 20, 56, '0.28 0.33 0.41');

    $section = static function (string $title) use ($line, &$ops, &$y): void {
        $y -= 14;
        $line($title, 'F2', 12.5, 16, 56, '0 0.2 0.6');
        $ops[] = '0.86 0.89 0.93 RG 0.8 w 56 ' . ($y - 6) . ' m 539 ' . ($y - 6) . ' l S';
        $y -= 6;
    };
    $row = static function (string $label, string $value) use ($line, &$y): void {
        $first = true;
        foreach (pdf_wrap($value === '' ? '—' : $value, 50) as $part) {
            if ($first) {
                $line($label, 'F1', 10, 17, 56, '0.28 0.33 0.41');
                $y += 17;
                $line($part, 'F2', 10.5, 17, 215);
                $first = false;
            } else {
                $line($part, 'F2', 10.5, 14, 215);
            }
        }
    };

    $section($en ? 'Signatory' : 'Signataire');
    $row($en ? 'Name' : 'Nom', trim($signature['prenom'] . ' ' . $signature['nom']));
    $row($en ? 'Position' : 'Fonction', (string) $signature['fonction']);
    $row($en ? 'Organisation' : 'Organisation', (string) $signature['organisation']);
    $row($en ? 'Name published' : 'Nom publié', (int) $signature['publier'] === 1 ? ($en ? 'yes' : 'oui') : ($en ? 'no' : 'non'));
    $confirmed = isset($attestation['confirmee_le']) ? (new DateTimeImmutable($attestation['confirmee_le']))->setTimezone(new DateTimeZone('Europe/Paris')) : null;
    $row($en ? 'Confirmed on' : 'Confirmée le', $confirmed === null ? '' : $confirmed->format($en ? 'Y-m-d, H:i' : 'd/m/Y à H:i') . ' (Paris)');
    $row($en ? 'Manifesto' : 'Manifeste', (string) ($attestation['manifeste'] ?? MANIFESTO_URL));

    $section($en ? 'Timestamp of the attestation' : 'Horodatage de l’attestation');
    $row($en ? 'Certified date' : 'Date certifiée', $paris->format($en ? 'Y-m-d, H:i:s' : 'd/m/Y à H:i:s') . ' (Paris) — ' . $details['gen_time_utc']);
    $row($en ? 'SHA-256 fingerprint' : 'Empreinte SHA-256', hash('sha256', $json));
    $row($en ? 'Token serial number' : 'N° de série du jeton', $details['serial']);
    $row($en ? 'Timestamping unit' : 'Unité d’horodatage', $details['unit']);
    $row($en ? 'Issued by' : 'Émise par', $details['issuer']);
    $row($en ? 'Policy (OID)' : 'Politique (OID)', (string) $details['policy']);

    $section($en ? 'Verify it yourself' : 'Vérifier vous-même');
    foreach (pdf_wrap($en
        ? "This PDF carries two attachments (paperclip panel of your reader): the attestation $name.json and its RFC 3161 token $name.tsr. The token covers the SHA-256 fingerprint above: changing the attestation, even by one character, invalidates it. The PDF itself is also timestamped (PAdES), visible in the Signatures panel of Adobe Acrobat Reader."
        : "Ce PDF porte deux pièces jointes (panneau des trombones de votre lecteur) : l’attestation $name.json et son jeton RFC 3161 $name.tsr. Le jeton porte sur l’empreinte SHA-256 ci-dessus : modifier l’attestation, même d’un caractère, le rend invalide. Le PDF lui-même est aussi horodaté (PAdES), visible dans le panneau Signatures d’Adobe Acrobat Reader.", 95) as $i => $part) {
        $line($part, 'F1', 10, $i === 0 ? 18 : 14);
    }
    $y -= 6;
    foreach (pdf_wrap($en
        ? 'Independent check: https://demo.open-eidas.eu/#verifier (drop this PDF, or the attestation and its token), or: openssl ts -verify -data ' . $name . '.json -in ' . $name . '.tsr -CAfile chain.pem'
        : 'Vérification indépendante : https://demo.open-eidas.eu/#verifier (déposez ce PDF, ou l’attestation et son jeton), ou : openssl ts -verify -data ' . $name . '.json -in ' . $name . '.tsr -CAfile chaine.pem', 95) as $i => $part) {
        $line($part, 'F1', 10, $i === 0 ? 14 : 14);
    }
    $ops[] = '1 0.97 0.85 rg 56 60 483 44 re f';
    $y = 104;
    foreach (pdf_wrap($en
        ? 'Demonstration authority (staging): this timestamp is not qualified under the eIDAS regulation and has no legal value.'
        : 'Autorité de démonstration (staging) : cet horodatage n’est pas qualifié au sens du règlement eIDAS et n’a aucune valeur juridique.', 92) as $part) {
        $line($part, 'F1', 9.5, 16, 66, '0.35 0.25 0');
    }
    $content = implode("\n", $ops);

    // ---- Objets PDF -----------------------------------------------------------------------------
    // $stamp : avec le champ d'horodatage du document (PAdES) ; sans, si l'autorité ne répond pas, pour ne pas
    // laisser un champ de signature vide que les lecteurs signaleraient comme invalide.
    $build = static function (bool $stamp) use ($content, $name, $json, $tsr, $en, $lang): string {
        $objects = [
            1 => '<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 7 0 R >> /PageMode /UseAttachments'
                . ($stamp ? ' /AcroForm << /Fields [12 0 R] /SigFlags 3 >>' : '') . ' /Lang ' . pdf_text($lang) . ' >>',
            2 => '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            3 => '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R'
                . ($stamp ? ' /Annots [12 0 R]' : '') . ' >>',
            4 => '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
            5 => '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
            6 => "<< /Length " . strlen($content) . " >>\nstream\n$content\nendstream",
            7 => '<< /Names [' . pdf_text("$name.json") . ' 8 0 R ' . pdf_text("$name.tsr") . ' 10 0 R] >>',
            8 => '<< /Type /Filespec /F ' . pdf_text("$name.json") . ' /UF ' . pdf_text("$name.json") . ' /Desc ' . pdf_text($en ? 'Timestamped attestation' : 'Attestation horodatée') . ' /AFRelationship /Data /EF << /F 9 0 R >> >>',
            9 => '<< /Type /EmbeddedFile /Subtype /application#2Fjson /Params << /Size ' . strlen($json) . " >> /Length " . strlen($json) . " >>\nstream\n$json\nendstream",
            10 => '<< /Type /Filespec /F ' . pdf_text("$name.tsr") . ' /UF ' . pdf_text("$name.tsr") . ' /Desc ' . pdf_text($en ? 'RFC 3161 timestamp token' : 'Jeton d’horodatage RFC 3161') . ' /AFRelationship /Data /EF << /F 11 0 R >> >>',
            11 => '<< /Type /EmbeddedFile /Subtype /application#2Ftimestamp-reply /Params << /Size ' . strlen($tsr) . " >> /Length " . strlen($tsr) . " >>\nstream\n$tsr\nendstream",
        ];
        if ($stamp) {
            $objects[12] = '<< /FT /Sig /T ' . pdf_text('Horodatage') . ' /V 13 0 R /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /F 132 /P 3 0 R >>';
            // Horodatage du document (PAdES) : /ByteRange et /Contents remplis après coup, à longueur constante.
            $objects[13] = '<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /ByteRange [0 ' . str_repeat(' ', 10) . ' '
                . str_repeat(' ', 10) . ' ' . str_repeat(' ', 10) . '] /Contents <' . str_repeat('0', 2 * PDF_TOKEN_SPACE) . '> >>';
        }
        $pdf = "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";
        $offsets = [];
        foreach ($objects as $number => $body) {
            $offsets[$number] = strlen($pdf);
            $pdf .= "$number 0 obj\n$body\nendobj\n";
        }
        $xref = strlen($pdf);
        $pdf .= "xref\n0 " . (count($objects) + 1) . "\n0000000000 65535 f \n";
        foreach ($offsets as $offset) {
            $pdf .= sprintf("%010d 00000 n \n", $offset);
        }
        $id = bin2hex(random_bytes(16));
        return $pdf . "trailer\n<< /Size " . (count($objects) + 1) . " /Root 1 0 R /ID [<$id> <$id>] >>\nstartxref\n$xref\n%%EOF\n";
    };
    $pdf = $build(true);

    // ---- Horodatage PAdES du PDF ----------------------------------------------------------------
    $start = strpos($pdf, '/Contents <' . str_repeat('0', 64)) + strlen('/Contents ');
    $end = $start + 2 * PDF_TOKEN_SPACE + 2;
    $range = sprintf('0 %10d %10d %10d', $start, $end, strlen($pdf) - $end);
    $pdf = str_replace('/ByteRange [0 ' . str_repeat(' ', 10) . ' ' . str_repeat(' ', 10) . ' ' . str_repeat(' ', 10) . ']', '/ByteRange [' . $range . ']', $pdf);
    try {
        $digest = hash('sha256', substr($pdf, 0, $start) . substr($pdf, $end), true);
        $response = tsa_request(bin2hex($digest));
        tsa_verify($response, $digest);
        [, $token] = asn1_children(asn1_one($response, 0x30));
        $hex = bin2hex($token[2]);
        if (strlen($hex) > 2 * PDF_TOKEN_SPACE) {
            throw new TimestampInvalid('jeton trop long pour la place réservée');
        }
        return [substr($pdf, 0, $start + 1) . str_pad($hex, 2 * PDF_TOKEN_SPACE, '0') . substr($pdf, $end - 1), true];
    } catch (TimestampInvalid $e) {
        error_log('otspi-signatures : PDF de la signature #' . (int) $signature['id'] . ' non horodaté (' . $e->getMessage() . ')');
        return [$build(false), false];
    }
}
