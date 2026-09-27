// SPDX-License-Identifier: EUPL-1.2
// Preuve de travail anti-robots du formulaire, sans service tiers : dès l'affichage, le navigateur cherche un
// entier n tel que SHA-256(jeton:n) commence par data-pow bits nuls (voir pow_ok() dans src/lib.php). Le calcul
// se fait pendant que la personne remplit le formulaire ; s'il n'est pas fini à l'envoi, l'envoi l'attend.
'use strict';

(() => {
  const form = document.querySelector('form[data-pow]');
  if (!form) {
    return;
  }
  const bits = Number(form.dataset.pow);
  const token = form.elements.ft.value;
  const field = form.elements.pow;
  const status = form.querySelector('.pow-status');
  const encoder = new TextEncoder();

  const enough = (buffer) => {
    let left = bits;
    for (const byte of new Uint8Array(buffer)) {
      if (left <= 0) {
        return true;
      }
      const need = Math.min(8, left);
      if (byte >> (8 - need) !== 0) {
        return false;
      }
      left -= 8;
    }
    return true;
  };

  const search = async () => {
    for (let start = 0; ; start += 512) {
      const batch = [];
      for (let n = start; n < start + 512; n++) {
        batch.push(crypto.subtle.digest('SHA-256', encoder.encode(`${token}:${n}`)));
      }
      const found = (await Promise.all(batch)).findIndex(enough);
      if (found !== -1) {
        return String(start + found);
      }
    }
  };

  const done = window.crypto && crypto.subtle
    ? search().then((nonce) => { field.value = nonce; })
    : Promise.reject(new Error('WebCrypto indisponible'));
  done.catch(() => { status.textContent = form.dataset.powError; });

  let waiting = false;
  form.addEventListener('submit', (event) => {
    if (field.value !== '') {
      return;
    }
    event.preventDefault();
    if (waiting) {
      return;
    }
    waiting = true;
    status.textContent = form.dataset.powWait;
    done.then(() => form.submit(), () => { waiting = false; });
  });
})();
