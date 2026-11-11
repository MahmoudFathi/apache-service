// Greeter front end. config.js (written at deploy time) sets window.APP_CONFIG = { apiUrl, env }.
(function () {
  const cfg = window.APP_CONFIG || {};
  const api = (cfg.apiUrl || "").replace(/\/$/, "");
  const $ = (id) => document.getElementById(id);

  $("env").textContent = cfg.env || "local";

  async function call(path) {
    const res = await fetch(api + path);
    const body = await res.json().catch(() => ({}));
    return { ok: res.ok, body };
  }

  // Version comes from the API, so the page proves the front end and back end are connected
  call("/health")
    .then(({ ok, body }) => { $("version").textContent = ok ? body.version : "unavailable"; })
    .catch(() => { $("version").textContent = "unavailable"; });

  $("greet-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("result").textContent = "";
    $("error").textContent = "";
    const name = $("name").value;
    try {
      const { ok, body } = await call("/greet?name=" + encodeURIComponent(name));
      // textContent (never innerHTML): user input is shown as text, so HTML cannot be injected
      if (ok) $("result").innerHTML = body.message;
      else $("error").textContent = body.error || "Something went wrong.";
    } catch (err) {
      $("error").textContent = "Could not reach the API.";
    }
  });
})();
