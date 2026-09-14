const rpcDocsScriptUrl = document.currentScript
  ? new URL(document.currentScript.src)
  : null;

const relativePageForVersion = (pageUrl, versionBaseUrl) => {
  if (
    pageUrl.origin !== versionBaseUrl.origin ||
    !pageUrl.pathname.startsWith(versionBaseUrl.pathname)
  ) {
    return "index.html";
  }
  return pageUrl.pathname.slice(versionBaseUrl.pathname.length) || "index.html";
};

const versionTargetUrl = (entry, relativePage, pagesRootUrl, hash) => {
  const versionBaseUrl = new URL(entry.url, pagesRootUrl);
  const pageExists =
    Array.isArray(entry.pages) && entry.pages.includes(relativePage);
  const target = pageExists
    ? new URL(relativePage, versionBaseUrl)
    : versionBaseUrl;
  if (pageExists) {
    target.hash = hash;
  }
  return target;
};

const loadJson = async (url) => {
  const response = await fetch(url, {
    cache: "no-cache",
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error(`Unable to load ${url}: ${response.status}`);
  }
  return response.json();
};

const appendVersionOption = (group, entry) => {
  const option = document.createElement("option");
  option.value = entry.id;
  option.textContent = entry.label;
  group.append(option);
};

const initVersionSelector = async () => {
  const versionContainer = document.querySelector(
    ".wy-side-nav-search > div.version",
  );
  if (!versionContainer || !rpcDocsScriptUrl) {
    return;
  }

  try {
    const contextUrl = new URL("rpcdocs-version.json", rpcDocsScriptUrl);
    const context = await loadJson(contextUrl);
    if (
      context.schema_version !== "1" ||
      context.enabled !== true ||
      !context.current
    ) {
      return;
    }

    const pagesRootUrl = new URL(context.pages_root, contextUrl);
    const versions = await loadJson(new URL("versions.json", pagesRootUrl));
    if (versions.schema_version !== "1" || !Array.isArray(versions.versions)) {
      return;
    }

    const entries = [];
    if (versions.development) {
      entries.push(versions.development);
    }
    entries.push(...versions.versions);
    const entriesById = new Map(entries.map((entry) => [entry.id, entry]));
    if (!entriesById.has(context.current.id)) {
      return;
    }

    const wrapper = document.createElement("label");
    wrapper.className = "rpc-version-selector";

    const label = document.createElement("span");
    label.className = "rpc-version-selector__label";
    label.textContent = "qbit version";

    const select = document.createElement("select");
    select.className = "rpc-version-selector__select";
    select.setAttribute("aria-label", "qbit RPC documentation version");

    if (versions.development) {
      const developmentGroup = document.createElement("optgroup");
      developmentGroup.label = "Development";
      appendVersionOption(developmentGroup, versions.development);
      select.append(developmentGroup);
    }

    const releaseGroup = document.createElement("optgroup");
    releaseGroup.label = "Releases";
    for (const entry of versions.versions) {
      appendVersionOption(releaseGroup, entry);
    }
    select.append(releaseGroup);
    select.value = context.current.id;

    const currentBaseUrl = new URL(
      context.current.path ? `${context.current.path}/` : "./",
      pagesRootUrl,
    );
    const relativePage = relativePageForVersion(
      new URL(window.location.href),
      currentBaseUrl,
    );

    select.addEventListener("change", () => {
      const entry = entriesById.get(select.value);
      if (!entry || entry.id === context.current.id) {
        return;
      }
      const target = versionTargetUrl(
        entry,
        relativePage,
        pagesRootUrl,
        window.location.hash,
      );
      window.location.assign(target.href);
    });

    wrapper.append(label, select);
    versionContainer.replaceChildren(wrapper);
  } catch (_error) {
    // Installed and offline docs intentionally retain their static version text.
  }
};

const initChangedMethodFilter = () => {
  const cards = Array.from(document.querySelectorAll(".rpc-method-card"));
  if (cards.length === 0) {
    return;
  }

  const toggles = Array.from(
    document.querySelectorAll(".rpc-show-changed-only"),
  );

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
};

document.addEventListener("DOMContentLoaded", () => {
  void initVersionSelector();
  initChangedMethodFilter();
});

if (typeof window !== "undefined") {
  window.rpcDocsVersioning = {
    relativePageForVersion,
    versionTargetUrl,
  };
}
