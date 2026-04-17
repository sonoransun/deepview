// Configure mermaid for catppuccin-mocha aesthetics + click-to-zoom.
//
// MkDocs-material auto-loads the mermaid library when pymdownx.superfences
// custom_fences is set up; this file augments the default config.
window.mermaidConfig = {
  startOnLoad: true,
  theme: "base",
  themeVariables: {
    primaryColor: "#1e1e2e",
    primaryTextColor: "#cdd6f4",
    primaryBorderColor: "#cba6f7",
    lineColor: "#94e2d5",
    secondaryColor: "#181825",
    tertiaryColor: "#11111b",
    fontFamily: "Inter, sans-serif",
    fontSize: "14px",
  },
  flowchart: {
    curve: "basis",
    htmlLabels: true,
  },
  sequence: {
    diagramMarginX: 30,
    diagramMarginY: 16,
    actorMargin: 80,
    messageFontSize: 14,
  },
};

// Click-to-zoom: wrap each rendered .mermaid in a clickable div.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".mermaid").forEach(diagram => {
    diagram.style.cursor = "zoom-in";
    diagram.addEventListener("click", () => {
      const isZoomed = diagram.classList.toggle("mermaid-zoomed");
      document.body.style.overflow = isZoomed ? "hidden" : "";
    });
  });
});
