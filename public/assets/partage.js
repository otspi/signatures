// SPDX-License-Identifier: EUPL-1.2
// Partage du manifeste après signature : bouton de partage natif (Web Share, surtout sur téléphone) s'il est
// disponible, et copie du lien. Les autres liens de partage sont de simples liens : rien n'est chargé depuis
// un réseau social tant que la personne ne clique pas.
'use strict';

(() => {
  const box = document.querySelector('[data-share-url]');
  if (!box) {
    return;
  }
  const { shareUrl: url, shareText: text, shareTitle: title, copied } = box.dataset;
  const native = box.querySelector('.share-native');
  if (native && navigator.share) {
    native.hidden = false;
    native.addEventListener('click', () => { navigator.share({ title, text, url }).catch(() => {}); });
  }
  const copy = box.querySelector('.share-copy');
  if (copy && navigator.clipboard) {
    copy.hidden = false;
    copy.addEventListener('click', () => {
      navigator.clipboard.writeText(url).then(() => { copy.textContent = copied; }, () => {});
    });
  }
})();
