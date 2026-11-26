/* qa/tauri-shim.js: window.__TAURI__ on top of the `foca serve` e2e harness (crates/foca-cli/src/serve.rs).
 * The shape is what ui/js/api.js reads: core.invoke("foca", { cmd, args }) → Promise (a core error is
 * reject({ code, message, targets? }), as in Tauri), event.listen(name, cb) → Promise<unlisten>,
 * cb({ event, payload }). Events come from SSE /events: { event: "scan://event"|"net", payload }.
 * Injected before the page loads (Playwright addInitScript, qa/shoot.mjs --real). */
(function () {
  if (window.__TAURI__) return;
  const base = location.origin;
  const listeners = {};
  let es = null;
  const open = () => {
    if (es) return;
    es = new EventSource(base + "/events");
    es.onmessage = m => {
      let d; try { d = JSON.parse(m.data); } catch (e) { return; }
      (listeners[d.event] || []).slice().forEach(cb => { try { cb({ event: d.event, payload: d.payload, id: 0 }); } catch (e) { console.error(e); } });
    };
  };
  window.__FOCA_E2E__ = { calls: 0, errors: [] };
  window.__TAURI__ = {
    core: {
      invoke(name, payload) {
        if (name !== "foca") return Promise.reject({ code: "unknown_command", message: name });
        const { cmd, args } = payload || {};
        window.__FOCA_E2E__.calls++;
        return fetch(base + "/invoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cmd, args: args || {} }) })
          .then(r => r.json().then(j => {
            if (r.ok && !j.error) return j.result;
            window.__FOCA_E2E__.errors.push({ cmd, error: j.error });
            throw j.error || { code: "internal", message: "HTTP " + r.status };
          }), e => { throw { code: "platform", message: "harness unavailable: " + e.message }; });
      },
    },
    event: {
      listen(name, cb) {
        (listeners[name] = listeners[name] || []).push(cb);
        open();
        return Promise.resolve(() => { listeners[name] = (listeners[name] || []).filter(x => x !== cb); });
      },
    },
  };
})();
