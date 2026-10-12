"use strict";
(() => {
  const civilDate = (year, month, day) => {
    const date = new Date(0);
    date.setUTCHours(0, 0, 0, 0);
    date.setUTCFullYear(year, month, day);
    return date;
  };
  const today = () => {
    const now = new Date();
    return civilDate(now.getFullYear(), now.getMonth(), now.getDate());
  };
  const format = (date) => `${String(date.getUTCFullYear()).padStart(4, "0")}-${String(date.getUTCMonth() + 1).padStart(2, "0")}-${String(date.getUTCDate()).padStart(2, "0")}`;
  const presetDate = (choice) => {
    const date = today();
    const days = { "1d": 1, "3d": 3, "1w": 7, "2w": 14 };
    const months = { "1m": 1, "3m": 3, "6m": 6, "1y": 12, "2y": 24 };
    if (days[choice]) {
      date.setUTCDate(date.getUTCDate() + days[choice]);
    } else if (months[choice]) {
      const day = date.getUTCDate();
      date.setUTCDate(1);
      date.setUTCMonth(date.getUTCMonth() + months[choice]);
      const last = civilDate(date.getUTCFullYear(), date.getUTCMonth() + 1, 0).getUTCDate();
      date.setUTCDate(Math.min(day, last));
    } else { return ""; }
    return format(date);
  };
  for (const group of document.querySelectorAll("[data-expiry-form]")) {
    const choice = group.querySelector('[name="expiry_choice"]');
    const input = group.querySelector('[name="expires_on"]');
    const anchor = group.querySelector('[name="expiry_today"]');
    anchor.value = format(today());
    choice.addEventListener("change", () => {
      anchor.value = format(today());
      if (choice.value !== "custom") { input.value = presetDate(choice.value); }
    });
    input.addEventListener("input", () => { choice.value = "custom"; });
    group.closest("form").addEventListener("submit", () => { anchor.value = format(today()); });
  }
  const update = () => {
    const now = today().getTime();
    for (const item of document.querySelectorAll("[data-token-expires-on]")) {
      const parts = item.dataset.tokenExpiresOn.split("-").map(Number);
      const date = civilDate(parts[0], parts[1] - 1, parts[2]);
      const days = Math.round((date.getTime() - now) / 86400000);
      item.textContent = days < 0 ? "Expired" : days === 0 ? "Expires today" : `${days} ${days === 1 ? "day" : "days"} left`;
    }
  };
  update();
  setInterval(update, 60000);
})();
