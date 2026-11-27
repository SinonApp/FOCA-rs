/*
 * Loads the demo backend only outside Tauri (plain browser demo, QA screenshots). Inside the app
 * window.__TAURI__ is injected before page scripts (withGlobalTauri), so the 0.5 MB demo core is never
 * parsed on the phone. document.write keeps the load synchronous: api.js reads FOCA_DEMO_BACKEND at once.
 */
(function () {
  const tauri = !!(window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke);
  if (!tauri) document.write('<script src="js/demo-backend.js"></' + "script>");
})();
