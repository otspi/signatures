// SPDX-License-Identifier: EUPL-1.2
// Clé de sécurité (WebAuthn) de l'administration : les formulaires marqués data-webauthn portent les options
// préparées par le serveur ; le script interroge la clé puis envoie sa réponse en POST dans le champ « reponse ».
'use strict';

(() => {
  const decode = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const encode = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // Modération par lot : « Tout sélectionner » coche les cases rattachées au formulaire #lot.
  const all = document.querySelector('[data-select-all]');
  if (all) {
    all.addEventListener('change', () => {
      document.querySelectorAll('input[name="ids[]"][form="lot"]').forEach((box) => { box.checked = all.checked; });
    });
  }

  for (const form of document.querySelectorAll('form[data-webauthn]')) {
    const status = form.querySelector('.webauthn-status');
    const button = form.querySelector('button');
    if (!window.PublicKeyCredential) {
      status.textContent = 'Ce navigateur ne prend pas en charge les clés de sécurité.';
      button.disabled = true;
      continue;
    }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const options = JSON.parse(form.dataset.options);
      options.challenge = decode(options.challenge);
      if (options.user) {
        options.user.id = decode(options.user.id);
      }
      for (const list of [options.allowCredentials, options.excludeCredentials]) {
        (list || []).forEach((credential) => { credential.id = decode(credential.id); });
      }
      button.disabled = true;
      status.textContent = 'Branchez la clé, saisissez son code PIN si le navigateur le demande, puis touchez-la.';
      try {
        const create = form.dataset.webauthn === 'create';
        const credential = create
          ? await navigator.credentials.create({ publicKey: options })
          : await navigator.credentials.get({ publicKey: options });
        const response = credential.response;
        const data = { id: credential.id, clientDataJSON: encode(response.clientDataJSON) };
        if (create) {
          data.attestationObject = encode(response.attestationObject);
          data.transports = response.getTransports ? response.getTransports() : [];
        } else {
          data.authenticatorData = encode(response.authenticatorData);
          data.signature = encode(response.signature);
        }
        form.elements.reponse.value = JSON.stringify(data);
        status.textContent = 'Vérification…';
        form.submit();
      } catch (error) {
        status.textContent = error.name === 'InvalidStateError'
          ? 'Cette clé est déjà enregistrée.'
          : 'Opération annulée, expirée ou refusée par la clé. Réessayez.';
        button.disabled = false;
      }
    });
  }
})();
