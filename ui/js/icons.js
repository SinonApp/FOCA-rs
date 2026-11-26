// Shared SVG icon sprite. Screens can register additional symbols via FOCA.addIcons('<symbol ...>').
(function () {
  const base = `<symbol id="i-minus" viewBox="0 0 16 16"><path d="M3 8h10"/></symbol>
<symbol id="i-trash"
  viewBox="0 0 16 16"><path d="M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.6 9h5.8l.6-9M7 7v4.5M9 7v4.5"/></symbol>
<symbol id="i-spark"
  viewBox="0 0 16 16"><path d="M8 2.5 9.3 6.7 13.5 8 9.3 9.3 8 13.5 6.7 9.3 2.5 8l4.2-1.3zM12.5 2v2.5M11.2 3.2h2.6"/></symbol>
<symbol id="i-zoom-in" viewBox="0 0 16 16"><circle cx="7" cy="7"
  r="4.5"/><path d="M10.5 10.5 14 14M5 7h4M7 5v4"/></symbol>
<symbol id="i-zoom-out" viewBox="0 0 16 16"><circle cx="7" cy="7"
  r="4.5"/><path d="M10.5 10.5 14 14M5 7h4"/></symbol>
<symbol id="i-plus" viewBox="0 0 16 16"><path d="M8 3v10M3 8h10"/></symbol>
<symbol id="i-folder"
  viewBox="0 0 16 16"><path d="M2 4.5A1.5 1.5 0 0 1 3.5 3h3l1.5 1.5h4.5A1.5 1.5 0 0 1 14 6v5.5a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 2 11.5z"/></symbol>
<symbol id="i-save"
  viewBox="0 0 16 16"><path d="M3 2.5h8l2.5 2.5v8a.5.5 0 0 1-.5.5H3a.5.5 0 0 1-.5-.5V3a.5.5 0 0 1 .5-.5z"/><path d="M5 2.5v3h5v-3M5 13.5V9.5h6v4"/></symbol>
<symbol id="i-search" viewBox="0 0 16 16"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 14 14"/></symbol>
<symbol id="i-download" viewBox="0 0 16 16"><path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.5h10"/></symbol>
<symbol id="i-scan"
  viewBox="0 0 16 16"><path d="M2.5 5V3.5a1 1 0 0 1 1-1H5M11 2.5h1.5a1 1 0 0 1 1 1V5M13.5 11v1.5a1 1 0 0 1-1 1H11M5 13.5H3.5a1 1 0 0 1-1-1V11M5 6h6M5 8h6M5 10h4"/></symbol>
<symbol id="i-globe" viewBox="0 0 16 16"><circle cx="8" cy="8"
  r="5.5"/><path d="M2.5 8h11M8 2.5c1.6 1.6 2.3 3.4 2.3 5.5S9.6 11.9 8 13.5C6.4 11.9 5.7 10.1 5.7 8S6.4 4.1 8 2.5z"/></symbol>
<symbol id="i-report"
  viewBox="0 0 16 16"><path d="M4 2.5h5.5L12 5v8.5H4z"/><path d="M6 8h4M6 10.5h4M9.5 2.5V5H12"/></symbol>
<symbol id="i-theme" viewBox="0 0 16 16"><circle cx="8" cy="8"
  r="5.5"/><path d="M8 2.5v11a5.5 5.5 0 0 0 0-11z" fill="currentColor" stroke="none"/></symbol>
<symbol id="i-tasks"
  viewBox="0 0 16 16"><path d="M6.5 4h7M6.5 8h7M6.5 12h7M2.5 4l1 1 1.5-2M2.5 8l1 1 1.5-2M3 12h1"/></symbol>
<symbol id="i-log" viewBox="0 0 16 16"><path d="M3 3.5h10M3 6.5h10M3 9.5h7M3 12.5h5"/></symbol>
<symbol id="i-shield" viewBox="0 0 16 16"><path d="M8 2 13 4v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4z"/></symbol>
<symbol id="i-chev-down" viewBox="0 0 16 16"><path d="m4 6 4 4 4-4"/></symbol>
<symbol id="i-chev" viewBox="0 0 16 16"><path d="m6 4 4 4-4 4"/></symbol>
<symbol id="i-dot" viewBox="0 0 16 16"><circle cx="8" cy="8" r="4" fill="currentColor"
  stroke="none"/></symbol>
<symbol id="i-db" viewBox="0 0 16 16"><ellipse cx="8" cy="4" rx="5"
  ry="1.8"/><path d="M3 4v8c0 1 2.2 1.8 5 1.8s5-.8 5-1.8V4M3 8c0 1 2.2 1.8 5 1.8S13 9 13 8"/></symbol>
<symbol id="i-check" viewBox="0 0 16 16"><path d="m3.5 8.5 3 3 6-7"/></symbol>
<symbol id="i-home"
  viewBox="0 0 16 16"><path d="M2.5 7 8 2.5 13.5 7v6a.5.5 0 0 1-.5.5H9.5v-4h-3v4H3a.5.5 0 0 1-.5-.5z"/></symbol>
<symbol id="i-doc" viewBox="0 0 16 16"><path d="M4 2.5h5.5L12 5v8.5H4z"/><path d="M9.5 2.5V5H12"/></symbol>
<symbol id="i-user" viewBox="0 0 16 16"><circle cx="8" cy="5.5"
  r="2.5"/><path d="M3 13.5c.6-2.6 2.6-4 5-4s4.4 1.4 5 4"/></symbol>
<symbol id="i-users" viewBox="0 0 16 16"><circle cx="6" cy="6"
  r="2.2"/><path d="M2 13c.5-2.2 2-3.5 4-3.5s3.5 1.3 4 3.5"/><path d="M10.5 4a2 2 0 1 1 0 4M11.5 9.6c1.3.4 2.2 1.6 2.5 3.4"/></symbol>
<symbol id="i-app" viewBox="0 0 16 16"><rect x="2.5" y="2.5" width="4.5" height="4.5" rx="1"/><rect x="9"
  y="2.5" width="4.5" height="4.5" rx="1"/><rect x="2.5" y="9" width="4.5" height="4.5" rx="1"/><rect x="9"
  y="9" width="4.5" height="4.5" rx="1"/></symbol>
<symbol id="i-printer"
  viewBox="0 0 16 16"><path d="M4.5 6V2.5h7V6M4.5 11h-2V6.5h11V11h-2M4.5 9h7v4.5h-7z"/></symbol>
<symbol id="i-mail" viewBox="0 0 16 16"><rect x="2" y="3.5" width="12" height="9"
  rx="1"/><path d="m2.5 4.5 5.5 4 5.5-4"/></symbol>
<symbol id="i-key" viewBox="0 0 16 16"><circle cx="5.5" cy="10.5"
  r="3"/><path d="m7.6 8.4 5.9-5.9M11.5 4.5l1.5 1.5"/></symbol>
<symbol id="i-server" viewBox="0 0 16 16"><rect x="2.5" y="2.5" width="11" height="4.5"
  rx="1"/><rect x="2.5" y="9" width="11" height="4.5" rx="1"/><path d="M5 4.7h.01M5 11.2h.01"/></symbol>
<symbol id="i-monitor" viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="8"
  rx="1"/><path d="M6 13.5h4M8 11v2.5"/></symbol>
<symbol id="i-path"
  viewBox="0 0 16 16"><path d="M2 4.5A1.5 1.5 0 0 1 3.5 3h3l1.5 1.5h4.5A1.5 1.5 0 0 1 14 6v5.5a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 2 11.5z"/><path d="M5.5 9h5"/></symbol>
<symbol id="i-net" viewBox="0 0 16 16"><circle cx="8" cy="3.5" r="1.5"/><circle cx="3.5" cy="12"
  r="1.5"/><circle cx="12.5" cy="12" r="1.5"/><path d="M8 5v3M8 8 4.3 10.7M8 8l3.7 2.7"/></symbol>
<symbol id="i-domain"
  viewBox="0 0 16 16"><path d="M2.5 8a5.5 5.5 0 1 0 11 0 5.5 5.5 0 0 0-11 0zM2.5 8h11"/><path d="M8 2.5v11"/></symbol>
<symbol id="i-bug" viewBox="0 0 16 16"><rect x="5" y="5" width="6" height="8"
  rx="3"/><path d="M6 5V4a2 2 0 0 1 4 0v1M2.5 8H5M11 8h2.5M3 12l2-1M13 12l-2-1M3 4.5l2 1.5M13 4.5 11 6"/></symbol>
<symbol id="i-graph" viewBox="0 0 16 16"><circle cx="4" cy="4" r="1.8"/><circle cx="12" cy="5"
  r="1.8"/><circle cx="7" cy="12"
  r="1.8"/><path d="M5.7 4.3 10.2 4.8M4.8 5.6 6.3 10.3M11 6.5 8.2 10.6"/></symbol>
<symbol id="i-pin"
  viewBox="0 0 16 16"><path d="M8 14s4.5-4.2 4.5-7.5a4.5 4.5 0 0 0-9 0C3.5 9.8 8 14 8 14z"/><circle cx="8"
  cy="6.5" r="1.6"/></symbol>
<symbol id="i-plug"
  viewBox="0 0 16 16"><path d="M6 2.5v3M10 2.5v3M4.5 5.5h7V8a3.5 3.5 0 0 1-7 0zM8 11.5v2"/></symbol>
<symbol id="i-gear" viewBox="0 0 16 16"><circle cx="8" cy="8"
  r="2"/><path d="M8 1.8v1.7M8 12.5v1.7M14.2 8h-1.7M3.5 8H1.8M12.4 3.6l-1.2 1.2M4.8 11.2l-1.2 1.2M12.4 12.4l-1.2-1.2M4.8 4.8 3.6 3.6"/></symbol>
<symbol id="i-clock" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5"/><path d="M8 5v3l2 1.5"/></symbol>
<symbol id="i-alert" viewBox="0 0 16 16"><path d="M8 2.5 14 13H2z"/><path d="M8 6.5v3M8 11.3h.01"/></symbol>
<symbol id="i-filter" viewBox="0 0 16 16"><path d="M2.5 3.5h11L9.5 8.5v4l-3 1.5V8.5z"/></symbol>
<symbol id="i-export" viewBox="0 0 16 16"><path d="M8 10V2.5M5 5.5l3-3 3 3M3 9.5v3.5h10V9.5"/></symbol>
<symbol id="i-x" viewBox="0 0 16 16"><path d="m4 4 8 8M12 4l-8 8"/></symbol>
<symbol id="i-stop" viewBox="0 0 16 16"><rect x="4" y="4" width="8" height="8" rx="1.5"/></symbol>
<symbol id="i-spin" viewBox="0 0 16 16"><path d="M8 2.5a5.5 5.5 0 1 0 5.5 5.5"/></symbol>
<symbol id="i-eraser"
  viewBox="0 0 16 16"><path d="m6.5 13.5-4-4 7-7 5 5-5.5 5.5zM5 7l5 5M6.5 13.5h7"/></symbol>
<symbol id="i-back" viewBox="0 0 16 16"><path d="M13 8H3.5M7.5 4 3.5 8l4 4"/></symbol>
<symbol id="i-more" viewBox="0 0 16 16"><circle cx="8" cy="3.5" r=".9" fill="currentColor"/><circle cx="8"
  cy="8" r=".9" fill="currentColor"/><circle cx="8" cy="12.5" r=".9" fill="currentColor"/></symbol>
<symbol id="i-grid" viewBox="0 0 16 16"><rect x="2.5" y="2.5" width="4.5" height="4.5" rx="1"/><rect x="9"
  y="2.5" width="4.5" height="4.5" rx="1"/><rect x="2.5" y="9" width="4.5" height="4.5" rx="1"/><rect x="9"
  y="9" width="4.5" height="4.5" rx="1"/></symbol>
<symbol id="i-open" viewBox="0 0 16 16"><path d="M9 2.5h4.5V7M13.5 2.5 7.5 8.5M11.5 9.5v4h-9v-9h4"/></symbol>
  <symbol id="i-lock" viewBox="0 0 16 16"><rect x="3.5" y="7" width="9" height="6.5"
    rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></symbol>
  <symbol id="i-eye"
    viewBox="0 0 16 16"><path d="M1.5 8S4 3.5 8 3.5 14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z"/><circle cx="8"
    cy="8" r="2"/></symbol>
  <symbol id="i-eye-off"
    viewBox="0 0 16 16"><path d="M2.5 2.5l11 11M6.6 6.6a2 2 0 0 0 2.8 2.8M4.3 4.9C2.6 6.1 1.5 8 1.5 8S4 12.5 8 12.5c1.3 0 2.5-.5 3.5-1.1M7 3.6c.3 0 .7-.1 1-.1 4 0 6.5 4.5 6.5 4.5s-.6 1.1-1.7 2.3"/></symbol>
  <symbol id="i-copy" viewBox="0 0 16 16"><rect x="5.5" y="5.5" width="8" height="8"
    rx="1.2"/><path d="M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"/></symbol>
  <symbol id="i-share" viewBox="0 0 16 16"><circle cx="12" cy="3.5" r="1.8"/><circle cx="4" cy="8"
    r="1.8"/><circle cx="12" cy="12.5" r="1.8"/><path d="m5.6 7.1 4.8-2.7M5.6 8.9l4.8 2.7"/></symbol>
  <symbol id="i-pause" viewBox="0 0 16 16"><path d="M5.5 3.5v9M10.5 3.5v9"/></symbol>
  <symbol id="i-play" viewBox="0 0 16 16"><path d="M5 3.2v9.6L12.5 8z"/></symbol>
  <symbol id="i-refresh" viewBox="0 0 16 16"><path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9M13.5 2.5v3h-3"/></symbol>
  <symbol id="i-wifi-off"
    viewBox="0 0 16 16"><path d="M2 2l12 12M8 12.5h.01M5.8 10.2a3.2 3.2 0 0 1 4.4 0M3.5 7.8a6.5 6.5 0 0 1 2.4-1.5M10 6.3a6.5 6.5 0 0 1 2.5 1.5M1.5 5.4A9.6 9.6 0 0 1 4 3.7M8 3a9.6 9.6 0 0 1 6.5 2.4"/></symbol>
  <symbol id="i-sort"
    viewBox="0 0 16 16"><path d="M5 3v10M2.5 10.5 5 13l2.5-2.5M11 13V3M8.5 5.5 11 3l2.5 2.5"/></symbol>
  <symbol id="i-chev-left" viewBox="0 0 16 16"><path d="m10 4-4 4 4 4"/></symbol>
  <symbol id="i-chev-up" viewBox="0 0 16 16"><path d="m4 10 4-4 4 4"/></symbol>
  <symbol id="i-info" viewBox="0 0 16 16"><circle cx="8" cy="8"
    r="5.5"/><path d="M8 7.2V11M8 5h.01"/></symbol>
  <symbol id="i-link"
    viewBox="0 0 16 16"><path d="M6.8 9.2a2.5 2.5 0 0 0 3.5 0l2-2a2.5 2.5 0 0 0-3.5-3.5l-.6.6M9.2 6.8a2.5 2.5 0 0 0-3.5 0l-2 2a2.5 2.5 0 0 0 3.5 3.5l.6-.6"/></symbol>
  <symbol id="i-target" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.5"/><circle cx="8" cy="8"
    r="2.5"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2"/></symbol>
  <symbol id="i-contract"
    viewBox="0 0 16 16"><path d="M4 2.5h5.5L12 5v8.5H4z"/><path d="M9.5 2.5V5H12M6 8.5l1.3 1.3L10 7"/></symbol>
  <symbol id="i-battery" viewBox="0 0 16 16"><rect x="1.5" y="5" width="11.5" height="6"
    rx="1.2"/><path d="M14.5 7v2M3.5 7v2"/></symbol>
  <symbol id="i-finger"
    viewBox="0 0 16 16"><path d="M5 13.5c-.6-1.5-1-3.2-1-5a4 4 0 0 1 8 0v1M8 8.5v2.5c0 1 .3 1.8.8 2.5M6 8.5a2 2 0 0 1 4 0c0 1.5.3 3 1 4.3"/></symbol>
  <symbol id="i-camera"
    viewBox="0 0 16 16"><path d="M2.5 5.5h2.2l1-1.5h4.6l1 1.5h2.2v7h-11z"/><circle cx="8" cy="9"
    r="2.2"/></symbol>
  <symbol id="i-note"
    viewBox="0 0 16 16"><path d="M3 2.5h10v8l-3 3H3z"/><path d="M10 13.5v-3h3M5.5 6h5M5.5 8.5h3"/></symbol>
  <symbol id="i-history"
    viewBox="0 0 16 16"><path d="M2.5 8a5.5 5.5 0 1 0 1.6-3.9M2.5 2.5v3h3M8 5v3l2 1.3"/></symbol>
  <symbol id="i-moon"
    viewBox="0 0 16 16"><path d="M13 9.5A5.5 5.5 0 1 1 6.5 3a4.5 4.5 0 0 0 6.5 6.5z"/></symbol>
  <symbol id="i-sun" viewBox="0 0 16 16"><circle cx="8" cy="8"
    r="2.8"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1"/></symbol>
  <symbol id="i-flag" viewBox="0 0 16 16"><path d="M3.5 14V2.5M3.5 3h8l-1.5 3 1.5 3h-8"/></symbol>
  <symbol id="i-swipe"
    viewBox="0 0 16 16"><path d="M2 5h8M7.5 2.5 10 5 7.5 7.5M14 11H6M8.5 8.5 6 11l2.5 2.5"/></symbol>
  <symbol id="i-hash"
    viewBox="0 0 16 16"><path d="M3 6h10.5M2.5 10H13M6.5 2.5 5 13.5M11 2.5 9.5 13.5"/></symbol>
  <symbol id="i-paste" viewBox="0 0 16 16"><rect x="3.5" y="3" width="9" height="11"
    rx="1.2"/><path d="M6 3V2h4v1"/></symbol>`;
  const host = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  host.setAttribute("width", "0");
  host.setAttribute("height", "0");
  host.style.position = "absolute";
  host.innerHTML = base;
  document.addEventListener("DOMContentLoaded", () => document.body.prepend(host));
  window.FOCA = window.FOCA || {};
  FOCA.addIcons = s => {
    host.insertAdjacentHTML("beforeend", s);
  };
})();
