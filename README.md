# Signatures du manifeste OTSPI

Petite application PHP (sans dépendance) et base SQLite qui recueille les signatures du [manifeste pour une identité numérique libre et ouverte](https://www.otspi.org/manifeste.html), en remplacement du formulaire Framaforms. Licence EUPL 1.2.

## Fonctionnement

1. La personne remplit le formulaire (`public/index.php`) : prénom, nom, e-mail, fonction et organisation facultatives, consentement à la publication.
2. Elle reçoit un e-mail qui récapitule les informations saisies, avec un lien valable 48 heures (double consentement). Le lien ouvre une page qui les récapitule à nouveau, avec un bouton : seul ce bouton (POST) confirme, pour que les antivirus de messagerie qui suivent les liens ne confirment pas à la place de la personne.
3. Après confirmation, un second e-mail contient le lien de retrait, qui supprime la signature et les données.
4. Si la personne a accepté la publication, la signature attend une **modération** : l'adresse `contact` reçoit une notification avec un lien signé vers `public/moderation.php` (récapitulatif et boutons, en POST), ou en ligne de commande `php bin/moderation.php lister | valider ID | masquer ID | supprimer ID` (masquer : signature comptée, nom jamais publié ; supprimer : usurpation, abus). Seule l'adresse e-mail est vérifiée par l'application, pas l'identité déclarée.
5. **Administration** : `https://manifesto-sign.otspi.org/admin.php`. Le bouton « Recevoir un lien d'accès » envoie à la seule adresse `contact` un lien signé valable 30 minutes (au plus 3 liens par 10 minutes) ; ni mot de passe ni cookie. La page liste les signatures par état (en attente, publiées, non publiées, non confirmées) avec les actions valider, masquer et supprimer, en POST depuis le site ; la suppression demande une confirmation.
6. `public/signataires.php` expose en JSON la liste publique : signatures confirmées, avec consentement à la publication et validées, **sans adresse e-mail**. Le total n'inclut pas les signatures en attente de modération.
7. `cron/purge.php` (tâche quotidienne) supprime les demandes non confirmées de plus de 7 jours.

Protections : jeton de formulaire signé avec délai minimal (aucun cookie, aucune session), champ piège pour les robots, refus des envois venant d'un autre site (`Sec-Fetch-Site`, à défaut `Origin`), limitation de débit par empreinte salée de l'adresse IP ou du préfixe /64 en IPv6 (conservée une heure), plafond global de 200 e-mails de confirmation par heure (`mail_hourly_cap`), e-mails sans texte libre hors du récapitulatif et liens refusés dans les champs, une seule signature par boîte (les alias `+…` sont acceptés mais ignorés pour l'unicité), un seul e-mail de confirmation toutes les 10 minutes par adresse, réponse identique que l'adresse soit connue ou non, refus des caractères de contrôle, bidirectionnels et de largeur nulle dans les noms, requêtes préparées, échappement HTML, erreurs journalisées et jamais affichées, en-têtes de sécurité et CSP stricte.

Mesure d'audience : seuls le formulaire (`index.php`) et la page « signature confirmée » chargent `assets/analytics.js` (Matomo Tag Manager de `stats.otspi.org`, sans cookie) et ouvrent leur CSP à ce domaine. Les pages dont l'adresse porte un jeton personnel (lien de confirmation, retrait, modération) ne sont pas mesurées. Le formulaire déclare aussi des événements anonymes (attributs `data-track` et `data-track-load`, voir `analytics.js`) : clic sur « Envoyer », code d'erreur éventuel (`err_…`, jamais les valeurs saisies) page « demande envoyée » et page « signature confirmée » (réponse au POST de confirmation, dont l'adresse `confirm.php?lang=…` ne porte pas le jeton). `analytics.js` est commun aux sites d'OTSPI : sa source est dans le dépôt `vitrine` ; après une copie, incrémenter `?v=` dans `page()` (`src/lib.php`).

## Installation

1. Copier le dépôt hors du dossier web, le dossier `public/` étant la racine du site. Les dossiers `src/`, `data/`, `bin/` et `cron/` ne doivent pas être servis.
2. Copier `config.example.php` en `config.php` et le renseigner (secret aléatoire, adresse, expéditeur). `config.php` et `data/` ne sont jamais versionnés.
3. Planifier `php cron/purge.php` une fois par jour.
4. Prérequis : PHP 8.1 ou plus avec PDO SQLite ; la fonction `mail()` opérationnelle, avec SPF et DKIM sur le domaine d'expéditeur.

## Déploiement

Le workflow `.github/workflows/deploy.yml` passe le test de bout en bout à chaque pull request et à chaque push sur `main` ; sur `main`, il envoie ensuite `bin/`, `cron/`, `src/` et `public/` en FTPS (TLS obligatoire, certificat vérifié), puis contrôle le site en lecture seule. `config.php` et `data/` ne sont jamais touchés ; le code retiré du dépôt est supprimé du serveur (sauf `public/.well-known/`, `public/cgi-bin/` et `public/error_log`, créés par le serveur).

Réglages du dépôt GitHub :

- secrets `O2_SIGN_FTP_USERNAME` et `O2_SIGN_FTP_PASSWORD` : compte FTP **dédié**, cantonné au répertoire de l'application (le parent de `public/`) ;
- variable `O2_FTP_HOST` : hôte FTP o2switch ; variable facultative `O2_SIGN_FTP_DIR` si l'application n'est pas à la racine du compte FTP ;
- environnement `production` (créé au premier déploiement) : on peut y exiger une approbation avant chaque mise en ligne.

Avant un déploiement qui modifie le schéma, sauvegarder `data/signatures.sqlite` avec ses fichiers `-wal` et `-shm`.

## Tests

`bash tests/flow.sh` : test de bout en bout (Docker requis) couvrant l'inscription, la confirmation, la liste publique, le retrait et les protections anti-abus.

## Données personnelles

Base légale : consentement. Conservation : demandes non confirmées 7 jours ; signatures pendant la campagne puis deux ans au plus. L'adresse e-mail n'est jamais publiée ni transmise. Le texte d'information affiché sur le formulaire est dans `src/texts.php` et doit rester aligné avec les mentions légales de www.otspi.org.
