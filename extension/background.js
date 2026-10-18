/**
 * NeuralPhish Background Service Worker
 * Handles context menu actions for WhatsApp Web, Gmail, and browser links.
 */

const API_BASE = "http://127.0.0.1:5000";

// Register right-click context menus on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "neuralphish-scan-link",
    title: "🛡️ Scan Link with NeuralPhish",
    contexts: ["link"]
  });

  chrome.contextMenus.create({
    id: "neuralphish-scan-selection",
    title: "🛡️ Scan Message with NeuralPhish",
    contexts: ["selection"]
  });
});

// Handle Context Menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "neuralphish-scan-link" && info.linkUrl) {
    await scanUrl(info.linkUrl);
  } else if (info.menuItemId === "neuralphish-scan-selection" && info.selectionText) {
    await scanMessage(info.selectionText);
  }
});

async function scanUrl(url) {
  try {
    const response = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`Server returned status ${response.status}`);
    }

    const json = await response.json();
    const data = json.data;

    await chrome.storage.local.set({ lastScan: data });

    let title = "✅ NeuralPhish: Link is SAFE";
    let icon = "icons/icon48.png";
    let message = `Legitimate URL (Risk: ${data.risk_score}/100)\n${data.url}`;

    if (data.status === "danger") {
      title = "🚨 DANGEROUS PHISHING LINK DETECTED!";
      message = `Risk: ${data.risk_score}/100\nDO NOT open this link. It appears malicious.\n${data.summary}`;
    } else if (data.status === "warning") {
      title = "⚠️ SUSPICIOUS LINK DETECTED";
      message = `Risk: ${data.risk_score}/100\nWarning signs found: ${data.threat_indicators.slice(0, 2).join(", ")}`;
    }

    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/svg+xml;charset=utf-8," + encodeURIComponent(getSvgIcon(data.status)),
      title: title,
      message: message,
      priority: 2
    });
  } catch (err) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/svg+xml;charset=utf-8," + encodeURIComponent(getSvgIcon("warning")),
      title: "NeuralPhish Server Offline",
      message: "Could not connect to local NeuralPhish server at http://127.0.0.1:5000. Please start the app.",
      priority: 1
    });
  }
}

async function scanMessage(text) {
  try {
    const response = await fetch(`${API_BASE}/api/scan-message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text })
    });

    if (!response.ok) {
      throw new Error(`Server returned status ${response.status}`);
    }

    const json = await response.json();
    const data = json.data;

    await chrome.storage.local.set({ lastScan: data });

    let title = "✅ NeuralPhish: Message is CLEAN";
    let message = `${data.summary}`;

    if (data.status === "danger") {
      title = "🚨 DANGEROUS MESSAGE ALERT!";
      message = `Risk: ${data.risk_score}/100. Phishing link detected!\n${data.recommendations[0] || "Do not click links in this message."}`;
    } else if (data.status === "warning") {
      title = "⚠️ SUSPICIOUS MESSAGE ALERT";
      message = `Risk: ${data.risk_score}/100\n${data.summary}`;
    }

    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/svg+xml;charset=utf-8," + encodeURIComponent(getSvgIcon(data.status)),
      title: title,
      message: message,
      priority: 2
    });
  } catch (err) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/svg+xml;charset=utf-8," + encodeURIComponent(getSvgIcon("warning")),
      title: "NeuralPhish Server Offline",
      message: "Please launch NeuralPhish on your PC to enable instant messenger scanning.",
      priority: 1
    });
  }
}

function getSvgIcon(status) {
  let color = "#10b981";
  if (status === "danger") color = "#ef4444";
  if (status === "warning") color = "#f59e0b";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="${color}"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>`;
}
