cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
  RPCDOCS_SITE_DIR
  RPCDOCS_SITE_MODEL_PATH
  RPCDOCS_SITE_INDEX
  RPCDOCS_SEARCH_INDEX
)
  if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "Missing required variable: ${required_var}")
  endif()
endforeach()

set(total_methods "unknown")
set(new_methods "unknown")
set(surface_changed_methods "unknown")
set(semantic_changed_methods "unknown")

if(EXISTS "${RPCDOCS_SITE_MODEL_PATH}")
  file(READ "${RPCDOCS_SITE_MODEL_PATH}" rpcdocs_site_model_json)

  string(REGEX MATCH "\"total_methods\"[ \t\r\n]*:[ \t\r\n]*([0-9]+)" total_methods_match "${rpcdocs_site_model_json}")
  if(total_methods_match)
    set(total_methods "${CMAKE_MATCH_1}")
  endif()

  string(REGEX MATCH "\"new_since_v30_2\"[ \t\r\n]*:[ \t\r\n]*([0-9]+)" new_methods_match "${rpcdocs_site_model_json}")
  if(new_methods_match)
    set(new_methods "${CMAKE_MATCH_1}")
  endif()

  string(REGEX MATCH "\"surface_changed_since_v30_2\"[ \t\r\n]*:[ \t\r\n]*([0-9]+)" surface_changed_methods_match "${rpcdocs_site_model_json}")
  if(surface_changed_methods_match)
    set(surface_changed_methods "${CMAKE_MATCH_1}")
  endif()

  string(REGEX MATCH "\"semantic_changed_since_v30_2\"[ \t\r\n]*:[ \t\r\n]*([0-9]+)" semantic_changed_methods_match "${rpcdocs_site_model_json}")
  if(semantic_changed_methods_match)
    set(semantic_changed_methods "${CMAKE_MATCH_1}")
  endif()
endif()

file(REMOVE_RECURSE "${RPCDOCS_SITE_DIR}")
file(MAKE_DIRECTORY "${RPCDOCS_SITE_DIR}/assets")
file(MAKE_DIRECTORY "${RPCDOCS_SITE_DIR}/search")

file(WRITE "${RPCDOCS_SITE_DIR}/assets/site.css" [=[
:root {
  color-scheme: light;
  font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
  line-height: 1.5;
}

body {
  margin: 0;
  background: linear-gradient(180deg, #f7f4eb 0%, #fbfaf7 100%);
  color: #1f2933;
}

.page {
  max-width: 56rem;
  margin: 0 auto;
  padding: 4rem 1.5rem 5rem;
}

.eyebrow {
  margin: 0 0 0.75rem;
  color: #8c2f1b;
  font-size: 0.85rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

h1 {
  margin: 0;
  font-size: clamp(2.5rem, 6vw, 4rem);
  line-height: 1.05;
}

.summary {
  max-width: 42rem;
  margin: 1rem 0 2rem;
  font-size: 1.05rem;
}

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
  gap: 1rem;
  padding: 0;
  margin: 0 0 2rem;
  list-style: none;
}

.stats li {
  padding: 1rem 1.2rem;
  background: rgba(255, 255, 255, 0.78);
  border: 1px solid rgba(140, 47, 27, 0.15);
  border-radius: 0.9rem;
  box-shadow: 0 10px 30px rgba(31, 41, 51, 0.06);
}

.stats strong {
  display: block;
  font-size: 1.5rem;
}

.panel {
  padding: 1.2rem;
  background: rgba(255, 255, 255, 0.84);
  border-radius: 1rem;
  border: 1px solid rgba(31, 41, 51, 0.1);
}

code {
  font-family: "SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}
]=])

file(WRITE "${RPCDOCS_SITE_DIR}/assets/site.js" [=[
window.addEventListener("DOMContentLoaded", async () => {
  const status = document.getElementById("search-status");
  if (!status) {
    return;
  }

  try {
    const response = await fetch("search/search_index.json");
    const payload = await response.json();
    const count = Array.isArray(payload.docs) ? payload.docs.length : 0;
    status.textContent = `Search index ready (${count} document${count === 1 ? "" : "s"}).`;
  } catch (error) {
    status.textContent = "Search index unavailable.";
  }
});
]=])

file(WRITE "${RPCDOCS_SEARCH_INDEX}" [=[
{
  "config": {
    "lang": ["en"],
    "separator": "[\\s\\-]+"
  },
  "docs": [
    {
      "location": "",
      "title": "qbit RPC docs",
      "text": "Fixture-backed RPC docs site used to validate build, install, and artifact plumbing."
    }
  ]
}
]=])

file(WRITE "${RPCDOCS_SITE_INDEX}"
  "<!doctype html>\n"
  "<html lang=\"en\">\n"
  "<head>\n"
  "  <meta charset=\"utf-8\">\n"
  "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
  "  <title>qbit RPC docs</title>\n"
  "  <link rel=\"stylesheet\" href=\"assets/site.css\">\n"
  "</head>\n"
  "<body>\n"
  "  <main class=\"page\">\n"
  "    <p class=\"eyebrow\">qbit RPC docs artifact</p>\n"
  "    <h1>RPC reference plumbing is wired.</h1>\n"
  "    <p class=\"summary\">\n"
  "      This placeholder site keeps the build, install, and CI artifact contract stable\n"
  "      until the finalized manifest and renderer branches are rebased into place.\n"
  "    </p>\n"
  "    <ul class=\"stats\">\n"
  "      <li><strong>${total_methods}</strong>Total methods in sample model</li>\n"
  "      <li><strong>${new_methods}</strong>New since v30.2</li>\n"
  "      <li><strong>${surface_changed_methods}</strong>Changed params/results since v30.2</li>\n"
  "      <li><strong>${semantic_changed_methods}</strong>Changed behavior since v30.2</li>\n"
  "    </ul>\n"
  "    <section class=\"panel\">\n"
  "      <p>\n"
  "        Machine-readable outputs are generated under <code>build/doc/rpc/</code>,\n"
  "        published in the separate <code>rpc-docs-data</code> artifact, and installed\n"
  "        under <code>share/doc/qbit/rpc/data/</code>.\n"
  "      </p>\n"
  "      <p>\n"
  "        The site artifact is self-contained, uses relative asset paths, and ships\n"
  "        without any external CDN dependency.\n"
  "      </p>\n"
  "      <p id=\"search-status\">Loading search index...</p>\n"
  "      <p><code>Manifest path:</code> build/doc/rpc/rpc-docs.json</p>\n"
  "    </section>\n"
  "  </main>\n"
  "  <script src=\"assets/site.js\"></script>\n"
  "</body>\n"
  "</html>\n"
)
