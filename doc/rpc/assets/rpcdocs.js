document.addEventListener("DOMContentLoaded", () => {
  const cards = Array.from(document.querySelectorAll(".rpc-method-card"));
  if (cards.length === 0) {
    return;
  }

  const toggles = Array.from(document.querySelectorAll(".rpc-show-changed-only"));

  const applyFilter = (showChangedOnly) => {
    for (const card of cards) {
      const isChanged = card.dataset.changed === "true";
      card.classList.toggle("is-hidden", showChangedOnly && !isChanged);
    }
    for (const toggle of toggles) {
      toggle.checked = showChangedOnly;
    }
  };

  for (const toggle of toggles) {
    toggle.addEventListener("change", (event) => {
      applyFilter(event.target.checked);
    });
  }

  applyFilter(false);
});
