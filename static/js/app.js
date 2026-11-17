/* APK Scanner UI — all APK/file content is rendered with textContent,
   never innerHTML, so a malicious filename or string cannot inject HTML. */

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function renderResult(data) {
  const section = document.getElementById("results");
  section.hidden = false;

  const verdict = document.getElementById("verdict");
  verdict.textContent = data.verdict + " — score " + data.score + "/100";
  verdict.className = data.verdict;
  document.getElementById("summary").textContent = data.summary;

  const appTable = document.getElementById("app-table");
  appTable.replaceChildren();
  const app = data.app || {};
  const rows = [
    ["Package", app.package],
    ["Version", (app.version_name || "") + " (" + (app.version_code ?? "") + ")"],
    ["Min SDK / Target SDK", (app.min_sdk ?? "") + " / " + (app.target_sdk ?? "")],
    ["Debuggable", String(app.debuggable)],
    ["Allow backup", String(app.allow_backup)],
    ["Cleartext traffic", String(app.uses_cleartext_traffic)],
    ["Signed", String(app.signed)],
    ["Debug signed", String(app.debug_signed)],
  ];
  for (const [key, value] of rows) {
    const tr = document.createElement("tr");
    tr.appendChild(el("th", key));
    tr.appendChild(el("td", value));
    appTable.appendChild(tr);
  }

  const fileTable = document.getElementById("file-table");
  fileTable.replaceChildren();
  const file = data.file || {};
  for (const [key, value] of [
    ["File", file.name], ["Size", file.size + " bytes"],
    ["MD5", file.md5], ["SHA-1", file.sha1], ["SHA-256", file.sha256],
    ["classes.dex SHA-256", file.dex_sha256],
    ["classes.dex entropy", file.entropy],
  ]) {
    const tr = document.createElement("tr");
    tr.appendChild(el("th", key));
    tr.appendChild(el("td", value));
    fileTable.appendChild(tr);
  }

  const perms = document.getElementById("permissions");
  perms.replaceChildren();
  if ((app.permissions || []).length === 0) {
    perms.appendChild(el("li", "No permissions requested."));
  } else {
    for (const perm of app.permissions) perms.appendChild(el("li", perm));
  }

  const findings = document.getElementById("findings");
  findings.replaceChildren();
  if (data.findings.length === 0) {
    findings.appendChild(el("p", "No findings. Nothing suspicious was found by these checks."));
    return;
  }
  for (const f of data.findings) {
    const box = el("div", null, "finding " + f.severity);
    const title = el("strong", "[" + f.severity.toUpperCase() + "] " + f.id + " — " + f.title);
    box.appendChild(title);
    if (f.evidence) {
      const p = document.createElement("p");
      p.appendChild(el("span", "Evidence: "));
      p.appendChild(el("code", f.evidence));
      box.appendChild(p);
    }
    box.appendChild(el("p", f.explanation));
    box.appendChild(el("p", "Fix: " + f.fix));
    findings.appendChild(box);
  }
}

async function loadJson(response) {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "request failed");
  return data;
}

async function runScan(formData) {
  const status = document.getElementById("status");
  status.textContent = "Scanning…";
  try {
    const response = await fetch("/api/scan", { method: "POST", body: formData });
    renderResult(await loadJson(response));
    status.textContent = "";
  } catch (err) {
    status.textContent = "Error: " + err.message;
  }
}

document.getElementById("scan-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = document.getElementById("file-input");
  if (!input.files.length) return;
  const formData = new FormData();
  formData.append("file", input.files[0]);
  runScan(formData);
});

async function loadExample(name) {
  const status = document.getElementById("status");
  status.textContent = "Loading example…";
  try {
    const response = await fetch("/api/example/" + name);
    renderResult(await loadJson(response));
    status.textContent = "";
  } catch (err) {
    status.textContent = "Error: " + err.message;
  }
}

document.getElementById("example-benign").addEventListener("click", () => loadExample("benign"));
document.getElementById("example-malicious").addEventListener("click", () => loadExample("malicious"));
