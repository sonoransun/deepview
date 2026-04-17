// Adds a "Copy as one-liner" button to every CLI code block.
//
// A CLI code block is any <pre><code> whose first non-empty line starts with
// "$ deepview" or "deepview". The button copies the command with any leading
// "$ " prompt stripped and multi-line continuations ("\\\n") folded so the
// result is safe to paste into a shell as a single command.
//
// The script also adds a .deepview-cli class + .deepview-prompt / .deepview-cmd
// spans so stylesheets/cli-block.css can restyle the prompt / command tokens.

(function () {
  "use strict";

  const CLI_RE = /^\s*\$?\s*deepview\b/;

  function isCliBlock(codeEl) {
    const text = codeEl.textContent || "";
    const firstLine = text.split("\n").find(l => l.trim().length > 0) || "";
    return CLI_RE.test(firstLine);
  }

  function stripPromptLine(line) {
    return line.replace(/^\s*\$\s?/, "");
  }

  function foldContinuations(text) {
    // Join backslash-newline line-continuations into a single logical line.
    return text.replace(/\\\s*\r?\n\s*/g, " ").replace(/\s+/g, " ").trim();
  }

  function extractOneLiner(codeEl) {
    const raw = codeEl.textContent || "";
    const lines = raw.split("\n").map(stripPromptLine);
    // Keep only lines that look like commands (drop empty + obvious output).
    // Heuristic: a CLI block usually has a single command; if it has multiple,
    // we join the ones starting with "deepview" or continuing the previous.
    const cmdLines = [];
    let inCmd = false;
    for (const line of lines) {
      if (/^\s*deepview\b/.test(line)) {
        cmdLines.push(line);
        inCmd = /\\\s*$/.test(line);
      } else if (inCmd) {
        cmdLines.push(line);
        inCmd = /\\\s*$/.test(line);
      }
    }
    const joined = cmdLines.length ? cmdLines.join("\n") : lines.join("\n");
    return foldContinuations(joined);
  }

  function highlightPromptTokens(codeEl) {
    // Wrap "$" prompts and the "deepview" token in spans so CSS can style them
    // without re-running a syntax highlighter. Operates on text nodes only to
    // avoid clobbering existing highlight spans.
    const walker = document.createTreeWalker(codeEl, NodeFilter.SHOW_TEXT, null);
    const targets = [];
    let node;
    while ((node = walker.nextNode())) {
      if (/\$|deepview/.test(node.nodeValue)) targets.push(node);
    }
    for (const n of targets) {
      const frag = document.createDocumentFragment();
      const parts = n.nodeValue.split(/(\bdeepview\b|\$)/g);
      for (const part of parts) {
        if (part === "$") {
          const s = document.createElement("span");
          s.className = "deepview-prompt";
          s.textContent = "$";
          frag.appendChild(s);
        } else if (part === "deepview") {
          const s = document.createElement("span");
          s.className = "deepview-cmd";
          s.textContent = "deepview";
          frag.appendChild(s);
        } else if (part) {
          frag.appendChild(document.createTextNode(part));
        }
      }
      n.parentNode.replaceChild(frag, n);
    }
  }

  function makeButton(onClick) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "deepview-copy-oneliner";
    btn.setAttribute("aria-label", "Copy command as one-liner");
    btn.title = "Copy as one-liner";
    btn.textContent = "copy";
    btn.addEventListener("click", onClick);
    return btn;
  }

  function flashButton(btn, label, ms) {
    const original = btn.textContent;
    btn.textContent = label;
    btn.classList.add("deepview-copy-flash");
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("deepview-copy-flash");
    }, ms || 1200);
  }

  function enhanceBlock(pre) {
    if (pre.dataset.deepviewCli === "1") return;
    const code = pre.querySelector("code");
    if (!code || !isCliBlock(code)) return;
    pre.dataset.deepviewCli = "1";
    pre.classList.add("deepview-cli");
    highlightPromptTokens(code);
    const btn = makeButton(() => {
      const oneLiner = extractOneLiner(code);
      if (!oneLiner) return;
      const finish = ok => flashButton(btn, ok ? "copied" : "failed", 1200);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(oneLiner).then(
          () => finish(true),
          () => finish(false),
        );
      } else {
        // Fallback for older browsers.
        const ta = document.createElement("textarea");
        ta.value = oneLiner;
        ta.setAttribute("readonly", "");
        ta.style.position = "absolute";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        let ok = false;
        try { ok = document.execCommand("copy"); } catch (_e) { ok = false; }
        document.body.removeChild(ta);
        finish(ok);
      }
    });
    pre.appendChild(btn);
  }

  function enhanceAll() {
    document.querySelectorAll("pre").forEach(enhanceBlock);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", enhanceAll);
  } else {
    enhanceAll();
  }

  // Re-run after MkDocs-material instant-loading navigations.
  if (typeof window.document$ !== "undefined" && window.document$.subscribe) {
    window.document$.subscribe(enhanceAll);
  }
})();
