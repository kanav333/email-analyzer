const form = document.getElementById("upload-form");
const fileInput = document.getElementById("file-input");
const dropzone = document.getElementById("dropzone");
const fileNameEl = document.getElementById("file-name");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");

let selectedFile = null;

function setFile(file) {
  if (!file || !file.name.toLowerCase().endsWith(".eml")) {
    showStatus("Please select a .eml file.", true);
    return;
  }
  selectedFile = file;
  fileNameEl.textContent = file.name;
  analyzeBtn.disabled = false;
  hideStatus();
}

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => {
  dropzone.classList.remove("dragover");
});

dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});

function showStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.remove("hidden", "error");
  if (isError) statusEl.classList.add("error");
}

function hideStatus() {
  statusEl.classList.add("hidden");
}

function authBadge(value) {
  const v = (value || "not found").toLowerCase();
  if (v === "pass") return `<span class="badge pass">${value}</span>`;
  if (["fail", "softfail"].includes(v)) return `<span class="badge fail">${value}</span>`;
  if (["not found", "none", "neutral"].includes(v)) return `<span class="badge warn">${value}</span>`;
  return `<span class="badge neutral">${value}</span>`;
}

function renderReport(data) {
  const { headers, auth_results, mismatch, sender_domain, domain_age,
    lookalike_warnings, urls, llm, url_reports, risk_notes } = data;

  const riskClass = risk_notes.length ? "risk" : "safe";
  const riskTitle = risk_notes.length
    ? `${risk_notes.length} risk signal${risk_notes.length > 1 ? "s" : ""} detected`
    : "No major warnings found";

  let html = `
    <div class="card ${riskClass}">
      <h2>${riskTitle}</h2>
      ${risk_notes.length
        ? `<ul>${risk_notes.map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ul>`
        : `<p class="muted">This email passed basic checks, but always verify unexpected messages.</p>`}
    </div>

    <div class="card">
      <h2>Headers</h2>
      <dl class="kv">
        <dt>From</dt><dd>${escapeHtml(headers.From || "—")}</dd>
        <dt>Reply-To</dt><dd>${escapeHtml(headers["Reply-To"] || "—")}</dd>
        <dt>Subject</dt><dd>${escapeHtml(headers.Subject || "—")}</dd>
        <dt>Date</dt><dd>${escapeHtml(headers.Date || "—")}</dd>
      </dl>
    </div>

    <div class="card">
      <h2>Authentication</h2>
      <dl class="kv">
        <dt>SPF</dt><dd>${authBadge(auth_results.SPF)}</dd>
        <dt>DKIM</dt><dd>${authBadge(auth_results.DKIM)}</dd>
        <dt>DMARC</dt><dd>${authBadge(auth_results.DMARC)}</dd>
        <dt>From / Reply-To</dt><dd>${mismatch.found ? '<span class="badge fail">Mismatch</span>' : '<span class="badge pass">Match</span>'} — ${escapeHtml(mismatch.message)}</dd>
      </dl>
    </div>

    <div class="card">
      <h2>Sender Domain</h2>
      <dl class="kv">
        <dt>Domain</dt><dd>${escapeHtml(sender_domain || "—")}</dd>
        <dt>Age</dt><dd>${escapeHtml(String(domain_age.days))} days — ${escapeHtml(domain_age.message)}</dd>
      </dl>
      ${lookalike_warnings.length
        ? `<ul style="margin-top:0.75rem">${lookalike_warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul>`
        : ""}
    </div>
  `;

  if (llm.error) {
    html += `<div class="card"><h2>LLM Analysis</h2><p class="muted">${escapeHtml(llm.error)}</p></div>`;
  } else if (llm.result) {
    const r = llm.result;
    const flags = [
      ["Urgency / fear tactics", r.urgency_or_fear_tactics],
      ["Impersonation", r.impersonation],
      ["Authority pressure", r.authority_pressure],
      ["Requests credentials / action", r.requests_credentials_or_action],
    ];
    html += `
      <div class="card">
        <h2>LLM Analysis</h2>
        ${flags.map(([label, val]) => `
          <div class="flag">
            <span>${label}</span>
            ${val ? '<span class="badge fail">Yes</span>' : '<span class="badge pass">No</span>'}
          </div>
        `).join("")}
        <p style="margin-top:0.75rem"><strong>Summary:</strong> ${escapeHtml(r.summary)}</p>
      </div>
    `;
  }

  if (urls.length) {
    html += `<div class="card"><h2>URLs (${urls.length})</h2>`;
    url_reports.forEach(({ url, report }) => {
      let detail = "";
      if (report.status === "found") {
        detail = `${report.malicious}/${report.total_engines} engines flagged malicious`;
      } else if (report.status === "not_scanned") {
        detail = "Not previously scanned; submitted to VirusTotal";
      } else if (report.status === "skipped") {
        detail = "Skipped (VIRUSTOTAL_API_KEY not set)";
      } else if (report.status === "error") {
        detail = `Error: ${report.message}`;
      }
      html += `
        <div class="url-item">
          <a href="${escapeHtml(url)}" target="_blank" rel="noopener">${escapeHtml(url)}</a>
          <div class="muted">${escapeHtml(detail)}</div>
        </div>
      `;
    });
    html += `</div>`;
  }

  resultsEl.innerHTML = html;
  resultsEl.classList.remove("hidden");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!selectedFile) return;

  analyzeBtn.disabled = true;
  resultsEl.classList.add("hidden");
  showStatus("Analyzing email… this may take a moment if VirusTotal checks are enabled.");

  const formData = new FormData();
  formData.append("file", selectedFile);

  try {
    const res = await fetch("/api/analyze", { method: "POST", body: formData });
    const data = await res.json();

    if (!res.ok) {
      showStatus(data.error || "Analysis failed.", true);
      return;
    }

    hideStatus();
    renderReport(data);
  } catch {
    showStatus("Network error. Is the server running?", true);
  } finally {
    analyzeBtn.disabled = false;
  }
});
