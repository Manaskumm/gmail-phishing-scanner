import { printLine } from './modules/print';

console.log('Gmail Phishing Scanner - Content script loaded!');

// Simple phishing detection without complex module patterns
window.GmailPhishingScanner = {
    config: {
        // Only flag truly suspicious shorteners (not commonly used legitimate ones)
        suspiciousDomains: ['clck.ru', 'cutt.ly', 'shorturl.at'],
        // More specific and contextual phishing phrases
        suspiciousKeywords: [
            'verify your account immediately',
            'confirm your password now',
            'account will be suspended',
            'immediate action required to prevent',
            'click here to verify your account',
            'urgent security alert',
            'account will be closed today',
            'verify payment information',
            'confirm your identity now',
            'suspended due to suspicious activity',
            'verify to avoid account closure'
        ],
        // Only flag the most suspicious TLDs
        suspiciousTlds: ['.tk', '.ml', '.ga', '.cf'],
        // Expanded list of trusted domains
        trustedDomains: [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'youtube.com', 'netflix.com', 'spotify.com', 'dropbox.com', 'slack.com',
            'zoom.us', 'teams.microsoft.com', 'office.com', 'outlook.com', 'gmail.com',
            'yahoo.com', 'hotmail.com', 'live.com', 'icloud.com', 'me.com',
            'adobe.com', 'salesforce.com', 'hubspot.com', 'mailchimp.com', 'constantcontact.com',
            'shopify.com', 'stripe.com', 'square.com', 'venmo.com', 'cashapp.com',
            'uber.com', 'lyft.com', 'airbnb.com', 'booking.com', 'expedia.com',
            'bankofamerica.com', 'wellsfargo.com', 'chase.com', 'citibank.com',
            'nike.com', 'adidas.com', 'target.com', 'walmart.com', 'bestbuy.com',
            'ebay.com', 'etsy.com', 'pinterest.com', 'instagram.com', 'tiktok.com',
            'discord.com', 'twitch.tv', 'reddit.com', 'medium.com', 'substack.com'
        ],
        // Expanded list of legitimate shorteners
        legitimateShorteners: [
            't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'youtu.be', 'fb.me',
            'bit.ly', 'tinyurl.com', 'short.link', 'is.gd', 'v.gd',
            'rebrand.ly', 'shorturl.com', 'tiny.cc', 'short.to'
        ]
    },

    analyzeUrl: function (url) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();

            if (this.config.trustedDomains.some(domain => hostname.endsWith(domain))) {
                return { suspicious: false, reason: 'Trusted domain' };
            }

            if (this.config.legitimateShorteners.some(shortener => hostname.includes(shortener))) {
                return { suspicious: false, reason: 'Legitimate shortener' };
            }

            if (this.config.suspiciousDomains.some(domain => hostname.includes(domain))) {
                return { suspicious: true, reason: 'Suspicious shortener domain' };
            }

            if (this.config.suspiciousTlds.some(tld => hostname.endsWith(tld))) {
                return { suspicious: true, reason: 'Suspicious TLD' };
            }

            if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
                return { suspicious: true, reason: 'IP address instead of domain' };
            }

            const commonDomains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com'];
            for (const domain of commonDomains) {
                const baseName = domain.replace('.com', '');
                if (hostname.includes(baseName) && !hostname.endsWith(domain) &&
                    (hostname.includes(baseName + '.') || hostname.endsWith(baseName + '.tk') ||
                        hostname.endsWith(baseName + '.ml') || hostname.endsWith(baseName + '.ga'))) {
                    return { suspicious: true, reason: 'Possible typosquatting' };
                }
            }

            return { suspicious: false, reason: 'Clean' };
        } catch (e) {
            return { suspicious: true, reason: 'Invalid URL format' };
        }
    },

    isVerifiedEmail: function (emailElement) {
        // Check for Gmail's blue verification checkmark
        const verificationSelectors = [
            // Gmail's verification checkmark
            '[data-tooltip*="verified"]',
            '[aria-label*="verified"]',
            '[title*="verified"]',
            '.verified',
            '.verified-sender',
            '[class*="verified"]',

            // Blue checkmark indicators
            '.blue-check',
            '.verified-check',
            '[class*="blue-check"]',
            '[class*="verified-check"]',

            // Gmail's sender verification
            '.sender-verified',
            '.email-verified',
            '[data-verified="true"]',

            // Common verification patterns
            'svg[class*="verified"]',
            'svg[class*="check"]',
            'i[class*="verified"]',
            'i[class*="check"]',

            // Gmail's specific verification elements
            '.gmail-verified',
            '.sender-verification',
            '.email-verification'
        ];

        // Check if any verification indicators exist
        for (const selector of verificationSelectors) {
            if (emailElement.querySelector(selector)) {
                return true;
            }
        }

        // Check parent elements for verification indicators
        let parentElement = emailElement.parentElement;
        let depth = 0;
        while (parentElement && depth < 5) {
            for (const selector of verificationSelectors) {
                if (parentElement.querySelector(selector)) {
                    return true;
                }
            }
            parentElement = parentElement.parentElement;
            depth++;
        }

        // Check for verification text patterns
        const emailText = emailElement.textContent.toLowerCase();
        const verificationTextPatterns = [
            'verified sender',
            'verified email',
            'authenticated sender',
            'verified by gmail',
            'sender verified',
            'email verified'
        ];

        for (const pattern of verificationTextPatterns) {
            if (emailText.includes(pattern)) {
                return true;
            }
        }

        return false;
    },

    analyzeEmail: function (emailElement) {
        const results = {
            suspiciousLinks: [],
            suspiciousText: [],
            riskScore: 0,
            isVerified: false
        };

        // Check if email is verified first
        results.isVerified = this.isVerifiedEmail(emailElement);

        // If email is verified, return safe results
        if (results.isVerified) {
            console.log('Gmail Phishing Scanner: Verified email detected - skipping analysis');
            return results;
        }

        const links = emailElement.querySelectorAll('a[href]');
        links.forEach(link => {
            const href = link.getAttribute('href');
            const text = link.textContent.trim();

            if (href) {
                const urlCheck = this.analyzeUrl(href);
                if (urlCheck.suspicious) {
                    results.suspiciousLinks.push({
                        url: href,
                        text: text,
                        reason: urlCheck.reason
                    });
                    results.riskScore += 25; // Reduced from 30
                }
            }
        });

        const emailText = emailElement.textContent.toLowerCase();
        this.config.suspiciousKeywords.forEach(keyword => {
            if (emailText.includes(keyword)) {
                results.suspiciousText.push(keyword);
                results.riskScore += 6; // Reduced from 8
            }
        });

        // More conservative risk assessment - require multiple strong indicators
        const hasMultipleSuspiciousElements = results.suspiciousLinks.length > 0 && results.suspiciousText.length > 0;
        const hasUrgentLanguage = emailText.includes('urgent') || emailText.includes('immediately') || emailText.includes('asap');
        const hasAccountLanguage = emailText.includes('account') || emailText.includes('password') || emailText.includes('login');
        const hasMultipleSuspiciousLinks = results.suspiciousLinks.length >= 2;
        const hasMultipleSuspiciousKeywords = results.suspiciousText.length >= 2;

        // Only add bonus points if there are multiple strong indicators
        if (hasMultipleSuspiciousElements && (hasUrgentLanguage || hasAccountLanguage) && (hasMultipleSuspiciousLinks || hasMultipleSuspiciousKeywords)) {
            results.riskScore += 15; // Increased bonus for multiple indicators
        }

        results.riskScore = Math.min(results.riskScore, 100);
        return results;
    },

    addWarning: function (emailElement, scanResults) {
        // Don't show warnings for verified emails
        if (scanResults.isVerified) {
            return;
        }

        if (scanResults.riskScore > 50) {
            const warningBanner = document.createElement('div');
            warningBanner.className = 'phishing-warning-banner';
            warningBanner.style.cssText = 'position: relative !important; z-index: 9999 !important; margin: 10px 0 !important;';
            warningBanner.innerHTML = `
        <div style="
          background: linear-gradient(135deg, #ff6b6b, #ee5a24);
          color: white;
          padding: 10px 15px;
          margin: 10px 0;
          border-radius: 8px;
          font-family: 'Google Sans', Arial, sans-serif;
          font-size: 14px;
          font-weight: 500;
          box-shadow: 0 2px 8px rgba(255, 107, 107, 0.3);
          border-left: 4px solid #ff4757;
          position: relative;
          z-index: 10000;
        ">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 18px;">⚠️</span>
            <div>
              <strong>Potential Phishing Email Detected!</strong>
              <div style="font-size: 12px; margin-top: 4px; opacity: 0.9;">
                Risk Score: ${scanResults.riskScore}/100
                ${scanResults.suspiciousLinks.length > 0 ? ` • ${scanResults.suspiciousLinks.length} suspicious link(s)` : ''}
                ${scanResults.suspiciousText.length > 0 ? ` • ${scanResults.suspiciousText.length} suspicious keyword(s)` : ''}
              </div>
            </div>
          </div>
        </div>
      `;

            let inserted = false;
            const mainContentArea = emailElement.querySelector('[role="main"]') ||
                emailElement.querySelector('.message-content') ||
                emailElement.querySelector('.email-content') ||
                emailElement.querySelector('.email-body') ||
                emailElement.querySelector('.message-body');

            if (mainContentArea) {
                mainContentArea.insertBefore(warningBanner, mainContentArea.firstChild);
                inserted = true;
            }

            if (!inserted) {
                emailElement.insertBefore(warningBanner, emailElement.firstChild);
                inserted = true;
            }

            if (!inserted && emailElement.offsetHeight < 100) {
                let parentElement = emailElement.parentElement;
                while (parentElement && parentElement.offsetHeight < 200) {
                    parentElement = parentElement.parentElement;
                }
                if (parentElement) {
                    parentElement.insertBefore(warningBanner, parentElement.firstChild);
                    inserted = true;
                }
            }

            scanResults.suspiciousLinks.forEach(linkInfo => {
                const allLinks = emailElement.querySelectorAll('a[href]');
                allLinks.forEach(link => {
                    if (link.getAttribute('href') === linkInfo.url) {
                        link.style.cssText = `
              background: rgba(255, 107, 107, 0.2) !important;
              border: 2px solid #ff6b6b !important;
              border-radius: 4px !important;
              padding: 2px 4px !important;
              position: relative !important;
              z-index: 10001 !important;
            `;
                        link.title = `⚠️ Suspicious Link: ${linkInfo.reason}`;
                    }
                });
            });
        }
    },

    scanAllEmails: function () {
        const selectors = [
            '[role="main"] [data-message-id]',
            '[role="main"] .yW',
            '.nH .yW',
            '[data-legacy-thread-id]',
            '.thread .message',
            '.thread .email',
            '[data-thread-id] .message',
            '.email-content',
            '.message-content',
            '.email-body',
            '.message-body',
            '[data-message-id]',
            '.message',
            '.email',
            '.conversation .message',
            '.conversation .email',
            '.compact .message',
            '.compact .email',
            '.search-result .message',
            '.search-result .email',
            '[class*="message"]',
            '[class*="email"]',
            '[class*="thread"]'
        ];

        let totalScanned = 0;

        selectors.forEach(selector => {
            try {
                const elements = document.querySelectorAll(selector);
                elements.forEach(element => {
                    if (!element.dataset.phishingScanned && element.textContent.trim().length > 50) {
                        const scanResults = this.analyzeEmail(element);
                        this.addWarning(element, scanResults);
                        element.dataset.phishingScanned = 'true';
                        totalScanned++;

                        chrome.storage.local.set({
                            [`scan_${Date.now()}_${totalScanned}`]: {
                                timestamp: Date.now(),
                                results: scanResults,
                                emailPreview: element.textContent.substring(0, 100) + '...'
                            }
                        });
                    }
                });
            } catch (error) {
                console.log('Error with selector:', selector, error);
            }
        });

        const allContentAreas = document.querySelectorAll('div[class*="content"], div[class*="body"], div[class*="message"]');
        allContentAreas.forEach(contentArea => {
            if (!contentArea.dataset.phishingScanned &&
                contentArea.textContent.trim().length > 100 &&
                contentArea.querySelector('a[href]')) {
                const scanResults = this.analyzeEmail(contentArea);
                if (scanResults.riskScore > 0) {
                    this.addWarning(contentArea, scanResults);
                    contentArea.dataset.phishingScanned = 'true';
                    totalScanned++;

                    chrome.storage.local.set({
                        [`scan_${Date.now()}_${totalScanned}`]: {
                            timestamp: Date.now(),
                            results: scanResults,
                            emailPreview: contentArea.textContent.substring(0, 100) + '...'
                        }
                    });
                }
            }
        });

        if (totalScanned > 0) {
            console.log(`Gmail Phishing Scanner: Scanned ${totalScanned} emails`);
        }
    }
};

// Initialize scanning when page loads
if (window.location.hostname === 'mail.google.com') {
    setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 1000);
    setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 3000);
    setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 5000);

    const observer = new MutationObserver((mutations) => {
        let shouldScan = false;
        mutations.forEach((mutation) => {
            if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        const hasEmailContent = node.querySelector && (
                            node.querySelector('a[href]') ||
                            node.querySelector('[class*="message"]') ||
                            node.querySelector('[class*="email"]') ||
                            node.textContent.length > 100
                        );
                        if (hasEmailContent) {
                            shouldScan = true;
                        }
                    }
                });
            }
        });

        if (shouldScan) {
            setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 500);
            setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 1500);
            setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 3000);
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    let currentUrl = window.location.href;
    setInterval(() => {
        if (window.location.href !== currentUrl) {
            currentUrl = window.location.href;
            setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 1000);
            setTimeout(() => window.GmailPhishingScanner.scanAllEmails(), 3000);
        }
    }, 1000);

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === 'scanEmails') {
            window.GmailPhishingScanner.scanAllEmails();
            sendResponse({ success: true });
        }
    });
}

printLine("Gmail Phishing Scanner initialized successfully!");