// Defaults for embedded asciinema players.
//
// Deep View docs embed asciinema recordings through <div class="asciinema-cast"
// data-cast="path/to/file.cast"> markers. This script hydrates them into
// AsciinemaPlayer instances with a consistent set of defaults so individual
// pages don't need to repeat the boilerplate.
//
// Expectations:
//   - The asciinema-player script + CSS are loaded globally (mkdocs.yml
//     extra_javascript / extra_css pull them from a CDN or vendored copy).
//   - Each placeholder carries data-cast (required) and optionally
//     data-rows, data-cols, data-speed, data-poster, data-autoplay, data-loop.
//
// Defaults chosen to match the look of the rest of the docs:
//   - autoplay on (docs recordings are short demos, < 60s)
//   - loop on
//   - idle-time-limit capped at 1.5s so long pauses don't drag
//   - font-size "medium" (matches body copy better than the default "small")
//   - theme "monokai" recolored through CSS variables in extra.css

(function () {
  "use strict";

  const DEFAULTS = {
    autoPlay: true,
    loop: true,
    idleTimeLimit: 1.5,
    fontSize: "medium",
    theme: "monokai",
    speed: 1.0,
    preload: true,
    poster: "npt:0:1",
  };

  function parseBool(value, fallback) {
    if (value === undefined || value === null || value === "") return fallback;
    if (value === "true" || value === "1") return true;
    if (value === "false" || value === "0") return false;
    return fallback;
  }

  function parseNum(value, fallback) {
    if (value === undefined || value === null || value === "") return fallback;
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  }

  function mountPlayer(el) {
    if (el.dataset.mounted === "1") return;
    const castUrl = el.dataset.cast;
    if (!castUrl) {
      console.warn("[deepview] asciinema-cast placeholder missing data-cast", el);
      return;
    }
    if (typeof window.AsciinemaPlayer === "undefined") {
      // Player library not loaded yet; retry once DOM is idle.
      return;
    }
    const opts = {
      autoPlay: parseBool(el.dataset.autoplay, DEFAULTS.autoPlay),
      loop: parseBool(el.dataset.loop, DEFAULTS.loop),
      idleTimeLimit: parseNum(el.dataset.idleLimit, DEFAULTS.idleTimeLimit),
      fontSize: el.dataset.fontSize || DEFAULTS.fontSize,
      theme: el.dataset.theme || DEFAULTS.theme,
      speed: parseNum(el.dataset.speed, DEFAULTS.speed),
      preload: parseBool(el.dataset.preload, DEFAULTS.preload),
      poster: el.dataset.poster || DEFAULTS.poster,
    };
    const rows = parseNum(el.dataset.rows, null);
    const cols = parseNum(el.dataset.cols, null);
    if (rows) opts.rows = rows;
    if (cols) opts.cols = cols;
    try {
      window.AsciinemaPlayer.create(castUrl, el, opts);
      el.dataset.mounted = "1";
    } catch (err) {
      console.error("[deepview] asciinema mount failed for", castUrl, err);
    }
  }

  function mountAll() {
    document.querySelectorAll(".asciinema-cast").forEach(mountPlayer);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountAll);
  } else {
    mountAll();
  }
  // Also retry after full load in case the player lib is async.
  window.addEventListener("load", mountAll);
})();
