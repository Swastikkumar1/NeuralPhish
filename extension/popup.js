const API_BASE = "http://127.0.0.1:5000";

const connStatus = document.getElementById("connStatus");
const tabMsg = document.getElementById("tabMsg");
const tabUrl = document.getElementById("tabUrl");
const paneMsg = document.getElementById("paneMsg");
const paneUrl = document.getElementById("paneUrl");

const msgInput = document.getElementById("msgInput");
const btnScanMsg = document.getElementById("btnScanMsg");

const urlInput = document.getElementById("urlInput");
const btnScanUrl = document.getElementById("btnScanUrl");
const btnScanCurrentTab = document.getElementById("btnScanCurrentTab");

const resultBox = document.getElementById("resultBox");
const resBadge = document.getElementById("resBadge");
const resScore = document.getElementById("resScore");
const resSummary = document.getElementById("resSummary");

// Check server connectivity
async function checkServer() {
  try {
    const res = await fetch(`${API_BASE}/api/health`, { method: "GET" });
    if (res.ok) {
      connStatus.textContent = "Engine Online";
      connStatus.className = "status-badge online";
      return true;
    }
  } catch (e) {
    // offline
  }
  connStatus.textContent = "Offline (Start App)";
  connStatus.className = "status-badge offline";
  return false;
}

// Tab navigation
tabMsg.addEventListener("click", () => {
  tabMsg.classList.add("active");
  tabUrl.classList.remove("active");
  paneMsg.style.display = "block";
  paneUrl.style.display = "none";
});

tabUrl.addEventListener("click", () => {
  tabUrl.classList.add("active");
  tabMsg.classList.remove("active");
  paneUrl.style.display = "block";
  paneMsg.style.display = "none";
});

function showResult(data) {
  resultBox.style.display = "block";
  resultBox.className = `result-box ${data.status}`;

  resBadge.textContent = data.verdict;
  resBadge.className = `badge ${data.status}`;
  resScore.textContent = `Risk: ${data.risk_score}/100`;

  let details = data.summary;
  if (data.urls_found) {
    details += ` (${data.urls_found} link(s) evaluated)`;
  }
  if (data.social_engineering && data.social_engineering.has_brand_impersonation) {
    details += "\n⚠️ Brand Impersonation Flagged!";
  }
  resSummary.innerText = details;
}

btnScanMsg.addEventListener("click", async () => {
  const text = msgInput.value.trim();
  if (!text) {
    alert("Please paste a message or chat excerpt to scan.");
    return;
  }
  btnScanMsg.disabled = true;
  btnScanMsg.textContent = "Scanning Message...";

  try {
    const res = await fetch(`${API_BASE}/api/scan-message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text })
    });
    const json = await res.json();
    if (json.success && json.data) {
      showResult(json.data);
    } else {
      alert("Analysis error: " + (json.error || "Unknown error"));
    }
  } catch (err) {
    alert("Could not contact NeuralPhish engine. Ensure server is running on http://127.0.0.1:5000");
  } finally {
    btnScanMsg.disabled = false;
    btnScanMsg.textContent = "Scan Message";
  }
});

btnScanUrl.addEventListener("click", async () => {
  const url = urlInput.value.trim();
  if (!url) {
    alert("Please enter a URL to scan.");
    return;
  }
  btnScanUrl.disabled = true;
  btnScanUrl.textContent = "Scanning...";

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    const json = await res.json();
    if (json.success && json.data) {
      showResult(json.data);
    } else {
      alert("Analysis error: " + (json.error || "Unknown error"));
    }
  } catch (err) {
    alert("Could not contact NeuralPhish engine. Ensure server is running on http://127.0.0.1:5000");
  } finally {
    btnScanUrl.disabled = false;
    btnScanUrl.textContent = "Scan URL";
  }
});

btnScanCurrentTab.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      urlInput.value = tabs[0].url;
      btnScanUrl.click();
    }
  });
});

// Check if there was a recent scan stored
chrome.storage.local.get(["lastScan"], (res) => {
  if (res && res.lastScan) {
    showResult(res.lastScan);
  }
});

checkServer();
