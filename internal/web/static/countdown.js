"use strict";
(() => {
  const update = () => {
    for (const item of document.querySelectorAll("[data-expires]")) {
      const seconds = Math.max(0, Math.ceil(Number(item.dataset.expires) - Date.now() / 1000));
      if (!seconds) { item.textContent = "Expired"; continue; }
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      item.textContent = `${days ? days + "d " : ""}${hours ? hours + "h " : ""}${minutes}m ${seconds % 60}s`;
    }
  };
  update();
  setInterval(update, 1000);
})();
