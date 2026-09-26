# Signatures du manifeste OTSPI

Petite application PHP (sans dépendance) et base SQLite qui recueille les signatures du [manifeste pour une identité numérique libre et ouverte](https://www.otspi.org/manifeste.html), en remplacement du formulaire Framaforms. Licence EUPL 1.2.

## Fonctionnement

1. La personne remplit le formulaire (`public/index.php`) : prénom, nom, e-mail, fonction et organisation facultatives, consentement à la publication.
2. Elle reçoit un e-mail avec un lien de confirmation valable 48 heures (double consentement). **Rien n'est publié avant confirmation.**
3. Après confirmation, un second e-mail contient le lien de retrait, qui supprime la signature et les données.
4. `public/signataires.php` expose en JSON la liste publique : signatures confirmées avec consentement à la publication, **sans adresse e-mail**.
5. `cron/purge.php` (tâche quotidienne) supprime les demandes non confirmées de plus de 7 jours.

Protections : jeton de formulaire signé avec délai minimal (aucun cookie, aucune session), champ piège pour les robots, limitation de débit par empreinte salée de l'adresse IP (conservée une heure), un seul e-mail de confirmation toutes les 10 minutes par adresse, réponse identique que l'adresse soit connue ou non, requêtes préparées, échappement HTML, en-têtes de sécurité et CSP stricte.

## Installation

1. Copier le dépôt hors du dossier web, le dossier `public/` étant la racine du site. Les dossiers `src/`, `data/` et `cron/` ne doivent pas être servis.
2. Copier `config.example.php` en `config.php` et le renseigner (secret aléatoire, adresse, expéditeur). `config.php` et `data/` ne sont jamais versionnés.
3. Planifier `php cron/purge.php` une fois par jour.
4. Prérequis : PHP 8.1 ou plus avec PDO SQLite ; la fonction `mail()` opérationnelle, avec SPF et DKIM sur le domaine d'expéditeur.

## Tests

`bash tests/flow.sh` : test de bout en bout (Docker requis) couvrant l'inscription, la confirmation, la liste publique, le retrait et les protections anti-abus.

## Données personnelles

Base légale : consentement. Conservation : demandes non confirmées 7 jours ; signatures pendant la campagne puis deux ans au plus. L'adresse e-mail n'est jamais publiée ni transmise. Le texte d'information affiché sur le formulaire est dans `src/texts.php` et doit rester aligné avec les mentions légales de www.otspi.org.
