import React, { useState, useEffect } from 'react';
import './Popup.css';

const Popup = () => {
  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [totalEmails, setTotalEmails] = useState(0);
  const [suspiciousEmails, setSuspiciousEmails] = useState(0);

  useEffect(() => {
    loadScanResults();
  }, []);

  const loadScanResults = async () => {
    try {
      const data = await chrome.storage.local.get(null);
      const results = Object.entries(data)
        .filter(([key]) => key.startsWith('scan_'))
        .map(([key, value]) => ({ id: key, ...value }))
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 10); // Show last 10 scans

      setScanResults(results);

      const total = results.length;
      const suspicious = results.filter(r => r.results.riskScore > 50).length;
      setTotalEmails(total);
      setSuspiciousEmails(suspicious);
    } catch (error) {
      console.error('Error loading scan results:', error);
    }
  };

  const triggerScan = async () => {
    setIsScanning(true);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (tab.url.includes('mail.google.com')) {
        await chrome.tabs.sendMessage(tab.id, { action: 'scanEmails' });
        setTimeout(() => {
          loadScanResults();
          setIsScanning(false);
        }, 2000);
      } else {
        alert('Please navigate to Gmail to scan emails');
        setIsScanning(false);
      }
    } catch (error) {
      console.error('Error triggering scan:', error);
      setIsScanning(false);
    }
  };

  const clearResults = async () => {
    try {
      const data = await chrome.storage.local.get(null);
      const keysToRemove = Object.keys(data).filter(key => key.startsWith('scan_'));
      await chrome.storage.local.remove(keysToRemove);
      setScanResults([]);
      setTotalEmails(0);
      setSuspiciousEmails(0);
    } catch (error) {
      console.error('Error clearing results:', error);
    }
  };

  const getRiskColor = (score) => {
    if (score >= 80) return '#ff4757';
    if (score >= 60) return '#ffa502';
    if (score >= 50) return '#ff6348';
    return '#2ed573';
  };

  const getRiskLabel = (score) => {
    if (score >= 80) return 'High Risk';
    if (score >= 60) return 'Medium Risk';
    if (score >= 50) return 'Low Risk';
    return 'Safe';
  };

  return (
    <div className="popup-container">
      <div className="popup-header">
        <div className="header-content">
          <div className="logo-section">
            <div className="shield-icon">🛡️</div>
            <div className="title-section">
              <h1>Gmail Phishing Scanner</h1>
              <p>Protect yourself from phishing attacks</p>
            </div>
          </div>
        </div>
      </div>

      <div className="popup-stats">
        <div className="stat-card">
          <div className="stat-number">{totalEmails}</div>
          <div className="stat-label">Emails Scanned</div>
        </div>
        <div className="stat-card">
          <div className="stat-number" style={{ color: suspiciousEmails > 0 ? '#ff4757' : '#2ed573' }}>
            {suspiciousEmails}
          </div>
          <div className="stat-label">Suspicious Found</div>
        </div>
      </div>

      <div className="popup-actions">
        <button
          className={`scan-button ${isScanning ? 'scanning' : ''}`}
          onClick={triggerScan}
          disabled={isScanning}
        >
          {isScanning ? (
            <>
              <div className="spinner"></div>
              Scanning...
            </>
          ) : (
            <>
              🔍 Scan Current Page
            </>
          )}
        </button>

        {scanResults.length > 0 && (
          <button className="clear-button" onClick={clearResults}>
            🗑️ Clear Results
          </button>
        )}
      </div>

      {scanResults.length > 0 && (
        <div className="scan-results">
          <h3>Recent Scan Results</h3>
          <div className="results-list">
            {scanResults.map((result) => (
              <div key={result.id} className="result-item">
                <div className="result-header">
                  <div
                    className="risk-indicator"
                    style={{ backgroundColor: result.results.isVerified ? '#2ed573' : getRiskColor(result.results.riskScore) }}
                  >
                    {result.results.isVerified ? 'Verified' : getRiskLabel(result.results.riskScore)}
                  </div>
                  <div className="risk-score">
                    {result.results.isVerified ? 'Trusted Email' : `Risk: ${result.results.riskScore}/100`}
                  </div>
                </div>

                <div className="result-preview">
                  {result.results.isVerified && (
                    <div style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      background: '#2ed573',
                      color: 'white',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontWeight: 'bold',
                      marginBottom: '4px'
                    }}>
                      ✓ Verified Email
                    </div>
                  )}
                  {result.emailPreview}
                </div>

                {result.results.suspiciousLinks.length > 0 && (
                  <div className="suspicious-links">
                    <strong>Suspicious Links:</strong>
                    <ul>
                      {result.results.suspiciousLinks.map((link, index) => (
                        <li key={index}>
                          <span className="link-url">{link.url}</span>
                          <span className="link-reason">({link.reason})</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.results.suspiciousText.length > 0 && (
                  <div className="suspicious-keywords">
                    <strong>Suspicious Keywords:</strong>
                    <div className="keyword-tags">
                      {result.results.suspiciousText.map((keyword, index) => (
                        <span key={index} className="keyword-tag">{keyword}</span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="result-timestamp">
                  {new Date(result.timestamp).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {scanResults.length === 0 && !isScanning && (
        <div className="empty-state">
          <div className="empty-icon">📧</div>
          <h3>No scans yet</h3>
          <p>Navigate to Gmail and click "Scan Current Page" to start detecting phishing emails.</p>
        </div>
      )}

      <div className="popup-footer">
        <div className="footer-info">
          <span>🛡️ Gmail Phishing Scanner v1.0</span>
        </div>
      </div>
    </div>
  );
};

export default Popup;
