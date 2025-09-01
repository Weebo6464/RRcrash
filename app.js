/* Retro Rewind Crash Explanation — app.js (universal parser, no rules.json required) */
(function () {
  const $ = (sel, parent=document) => parent.querySelector(sel);
  const $$ = (sel, parent=document) => Array.from(parent.querySelectorAll(sel));

  // Theme toggle
  const themeToggle = $("#themeToggle");
  const current = localStorage.getItem("rr_theme") || "dark";
  document.documentElement.setAttribute("data-theme", current);
  themeToggle.addEventListener("click", () => {
    const now = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", now);
    localStorage.setItem("rr_theme", now);
  });
  $("#year").textContent = new Date().getFullYear();

  // Tabs
  $$(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".tab").forEach(b => b.classList.remove("active"));
      $$(".tab-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      $("#" + btn.dataset.tab).classList.add("active");
    });
  });

  // File + drag&drop
  const fileInput = $("#fileInput");
  const dropZone = $("#dropZone");
  const rawOut = $("#rawOut");
  const copyRaw = $("#copyRaw");

  dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.style.borderColor = "var(--accent)"; });
  dropZone.addEventListener("dragleave", () => { dropZone.style.borderColor = "var(--border)"; });
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault(); dropZone.style.borderColor = "var(--border)";
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      readFile(e.dataTransfer.files[0]);
    }
  });
  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      readFile(e.target.files[0]);
    }
  });

  copyRaw.addEventListener("click", async () => {
    const txt = rawOut.textContent || "";
    if (!txt) return;
    await navigator.clipboard.writeText(txt);
    copyRaw.textContent = "Copied!";
    setTimeout(() => (copyRaw.textContent = "Copy Raw"), 1000);
  });

  // Paste handling
  const pasteInput = $("#pasteInput");
  $("#analyzePaste").addEventListener("click", () => {
    const text = pasteInput.value.trim();
    if (text) analyzeText(text);
  });
  $("#clearPaste").addEventListener("click", () => { pasteInput.value = ""; });

  async function readFile(file) {
    const text = await file.text();
    analyzeText(text);
  }

  // ----------- Main pipeline -----------
  async function analyzeText(text) {
    rawOut.textContent = text;
    const parsed = parseDump(text);
    renderParsed(parsed);
    const result = analyze(parsed);
    renderSummary(result);
  }

  // ----------- Parsing -----------
  function parseDump(text) {
    const region = (text.match(/Region:\s*([A-Z])/i) || [])[1] || null;

    const ssr0Match = text.match(/SSR0:\s*(0x[0-9a-fA-F]+)\s*,?\s*(.*)/);
    const ssr0 = ssr0Match ? { addr: ssr0Match[1], symbol: (ssr0Match[2] || "").trim() || null } : null;

    const lrMatch = text.match(/^\s*LR:\s*(0x[0-9a-fA-F]+)\s*,?\s*(.*)$/m);
    const lr = lrMatch ? { addr: lrMatch[1], symbol: (lrMatch[2] || "").trim() || null } : null;

    const msr = (text.match(/MSR:\s*(0x[0-9a-fA-F]+)/) || [])[1] || null;
    const cr  = (text.match(/CR:\s*(0x[0-9a-fA-F]+)/) || [])[1] || null;
    const ssr1= (text.match(/SSR1:\s*(0x[0-9a-fA-F]+)/) || [])[1] || null;

    // GPRs
    const gpr = {};
    const gprBlock = text.split(/GPRs/i)[1]?.split(/FPRs/i)[0] || "";
    (gprBlock.match(/R(\d{2}):\s*(0x[0-9a-fA-F]+)/g) || []).forEach(line => {
      const m = line.match(/R(\d{2}):\s*(0x[0-9a-fA-F]+)/);
      if (m) gpr["R" + m[1]] = m[2];
    });

    // FPRs
    const fpr = {};
    const fprBlock = text.split(/FPRs/i)[1]?.split(/Stack Frame/i)[0] || "";
    (fprBlock.match(/F(\d{2}):\s*[-+0-9.eE]+/g) || []).forEach(line => {
      const m = line.match(/F(\d{2}):\s*([-+0-9.eE]+)/);
      if (m) fpr["F" + m[1]] = m[2];
    });
    const fscr = (text.match(/FSCR:\s*(0x[0-9a-fA-F]+)/) || [])[1] || null;

    // Stack frames
    const stack = [];
    const stackRe = /^\s*SP:\s*(0x[0-9a-fA-F]+),\s*LR:\s*(0x[0-9a-fA-F]+),\s*(.*)$/gm;
    let sm;
    while ((sm = stackRe.exec(text)) !== null) {
      stack.push({ sp: sm[1], lr: sm[2], symbol: (sm[3] || "").trim() });
    }

    const meta = {
      region, msr, cr, ssr1, fscr,
      nullLR: stack.some(s => s.lr.toLowerCase() === "0x00000000"),
      unresolved: stack.some(s => /Failed to resolve|Unable to parse/i.test(s.symbol)),
    };

    return { region, ssr0, lr, msr, cr, ssr1, gpr, fpr, fscr, stack, meta, raw: text };
  }

  // ----------- Analysis (no rules.json) -----------
  function analyze(parsed) {
    const findings = [];
    const headSym = parsed?.ssr0?.symbol && parsed.ssr0.symbol !== parsed.ssr0.addr
      ? parsed.ssr0.symbol
      : (parsed.stack.find(s => s.symbol && !/Failed to resolve/i.test(s.symbol))?.symbol || null);

    if (parsed.region) {
      const regionLabel = { E: "USA", P: "Europe/PAL", J: "Japan", K: "Korea" }[parsed.region] || parsed.region;
      findings.push(`Region ${parsed.region} (${regionLabel})`);
    }
    if (parsed.meta.nullLR) findings.push("Null return address (0x00000000) in stack");
    if (parsed.meta.unresolved) findings.push("Unresolved symbols in stack trace");

    // Recursion / stack overflow detection
    const symList = parsed.stack.map(s => s.symbol).filter(Boolean);
    if (symList.length > 5 && new Set(symList).size < symList.length / 2) {
      findings.push("Possible infinite recursion / stack overflow");
    }

    const callChain = symList.slice(0, 6).join(" → ");
    const summary = headSym
      ? `Crash in <strong>${headSym}</strong>. ${findings.join("; ")}`
      : `Crash detected. ${findings.join("; ")}`;

    return { summary, findings, headSym, callChain };
  }

  // ----------- Rendering -----------
  function renderParsed(parsed) {
    const core = [
      ["Region", parsed.region || "—"],
      ["SSR0", parsed?.ssr0?.addr || "—"],
      ["SSR0 Sym", parsed?.ssr0?.symbol || "—"],
      ["LR", parsed?.lr?.addr || "—"],
      ["LR Sym", parsed?.lr?.symbol || "—"],
      ["MSR", parsed.msr || "—"],
      ["CR", parsed.cr || "—"],
      ["SSR1", parsed.ssr1 || "—"],
      ["FSCR", parsed.fscr || "—"],
    ];
    renderTable($("#coreRegs"), core);

    const gprs = Object.keys(parsed.gpr).sort().map(k => [k, parsed.gpr[k]]);
    renderTable($("#gprRegs"), gprs);

    const fprs = Object.keys(parsed.fpr).sort().map(k => [k, parsed.fpr[k]]);
    renderTable($("#fprRegs"), fprs);

    const tbody = $("#stackTable tbody");
    tbody.innerHTML = "";
    parsed.stack.forEach((f, i) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${i}</td><td>${f.sp}</td><td>${f.lr}</td><td>${escapeHtml(f.symbol || "")}</td>`;
      tbody.appendChild(tr);
    });

    const metaRows = [
      ["Null return address", parsed.meta.nullLR ? "Yes" : "No"],
      ["Unresolved symbols", parsed.meta.unresolved ? "Yes" : "No"],
      ["Frames parsed", String(parsed.stack.length)],
    ];
    renderTable($("#metaTable"), metaRows);
  }

  function renderSummary(result) {
    $("#summary").innerHTML = result.summary;
    const ul = $("#signals");
    ul.innerHTML = "";
    result.findings.forEach(f => {
      const li = document.createElement("li");
      li.textContent = f;
      ul.appendChild(li);
    });
    if (!result.findings.length) {
      const li = document.createElement("li");
      li.textContent = "No obvious issues detected.";
      ul.appendChild(li);
    }
  }

  function renderTable(table, rows) {
    table.innerHTML = "";
    if (!rows.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="muted">No data</td><td></td>`;
      table.appendChild(tr);
      return;
    }
    rows.forEach(([k, v]) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${k}</td><td>${escapeHtml(String(v))}</td>`;
      table.appendChild(tr);
    });
  }

  function escapeHtml(str) {
    return str.replace(/[&<>"'`=\/]/g, s => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      "/": "&#x2F;", "`": "&#x60;", "=": "&#x3D;",
    })[s]);
  }
})();