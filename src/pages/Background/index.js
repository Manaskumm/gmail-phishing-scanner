console.log('Gmail Phishing Scanner - Background script loaded!');

// Background script for Gmail Phishing Scanner
// This handles extension lifecycle and can be extended for API calls

// Extension installation/update
chrome.runtime.onInstalled.addListener((details) => {
    console.log('Gmail Phishing Scanner installed/updated:', details.reason);

    // Set default settings
    chrome.storage.local.set({
        extensionSettings: {
            autoScan: true,
            riskThreshold: 20,
            showNotifications: true,
            lastScanTime: null
        }
    });
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Background received message:', request);

    switch (request.action) {
        case 'scanComplete':
            // Handle scan completion
            handleScanComplete(request.data, sender.tab);
            break;

        case 'getSettings':
            // Return current settings
            chrome.storage.local.get(['extensionSettings'], (result) => {
                sendResponse(result.extensionSettings || {});
            });
            return true; // Keep message channel open for async response

        case 'updateSettings':
            // Update extension settings
            chrome.storage.local.set({ extensionSettings: request.settings }, () => {
                sendResponse({ success: true });
            });
            return true;

        default:
            sendResponse({ error: 'Unknown action' });
    }
});

// Handle scan completion
function handleScanComplete(scanData, tab) {
    console.log('Scan completed:', scanData);

    // Store scan results
    const scanKey = `scan_${Date.now()}`;
    chrome.storage.local.set({
        [scanKey]: {
            timestamp: Date.now(),
            tabId: tab.id,
            url: tab.url,
            results: scanData
        }
    });

    // Update last scan time
    chrome.storage.local.get(['extensionSettings'], (result) => {
        const settings = result.extensionSettings || {};
        settings.lastScanTime = Date.now();
        chrome.storage.local.set({ extensionSettings: settings });
    });

    // Show notification if high risk detected
    if (scanData.riskScore >= 70 && scanData.suspiciousEmails > 0) {
        showHighRiskNotification(scanData);
    }
}

// Show notification for high-risk emails
function showHighRiskNotification(scanData) {
    chrome.storage.local.get(['extensionSettings'], (result) => {
        const settings = result.extensionSettings || {};

        if (settings.showNotifications) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon-128.png',
                title: '⚠️ High Risk Phishing Detected!',
                message: `Found ${scanData.suspiciousEmails} suspicious email(s) with risk score ${scanData.riskScore}/100`,
                priority: 2
            });
        }
    });
}

// Handle tab updates to auto-scan Gmail pages
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.includes('mail.google.com')) {
        // Auto-scan when Gmail page loads (if enabled)
        chrome.storage.local.get(['extensionSettings'], (result) => {
            const settings = result.extensionSettings || {};
            if (settings.autoScan) {
                // Send message to content script to start auto-scan
                setTimeout(() => {
                    chrome.tabs.sendMessage(tabId, { action: 'autoScan' }).catch(() => {
                        // Content script might not be ready yet, ignore error
                    });
                }, 3000);
            }
        });
    }
});

// Clean up old scan results periodically
setInterval(() => {
    chrome.storage.local.get(null, (data) => {
        const now = Date.now();
        const keysToRemove = [];

        Object.keys(data).forEach(key => {
            if (key.startsWith('scan_') && data[key].timestamp) {
                // Remove scans older than 7 days
                if (now - data[key].timestamp > 7 * 24 * 60 * 60 * 1000) {
                    keysToRemove.push(key);
                }
            }
        });

        if (keysToRemove.length > 0) {
            chrome.storage.local.remove(keysToRemove);
            console.log(`Cleaned up ${keysToRemove.length} old scan results`);
        }
    });
}, 24 * 60 * 60 * 1000); // Run daily

console.log('Gmail Phishing Scanner background script initialized successfully!');
