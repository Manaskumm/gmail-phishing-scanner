# Gmail Phishing Scanner

This Chrome extension automatically scans Gmail emails to detect phishing attempts and suspicious content. It analyzes links, keywords, and email patterns to provide risk scores and visual warnings for potentially dangerous emails.

## Technologies Used

**React 18**: Modern UI framework for the popup interface.

**Webpack 5**: Build system and module bundler.

**Chrome Extension Manifest V3**: Latest Chrome extension platform.

**CSS3**: Modern styling.

**JavaScript**: Content script for Gmail scanning and analysis.

## Usage

**Install Dependencies:**
```bash
npm install
```

**Build the Extension:**
```bash
npm run build
```

**Load in Chrome:**
- Go to `chrome://extensions/`
- Enable "Developer mode"
- Click "Load unpacked" and select the `build` folder

**Start Scanning:**
- Navigate to Gmail
- The extension automatically scans emails for phishing indicators
- Click the extension icon to view scan results and statistics

**Detection Features:**
- Identifies suspicious URL shorteners and domains
- Detects typosquatting attempts
- Analyzes email content for phishing keywords
- Automatically trusts verified emails with blue checkmarks
- Provides risk scores from 0-100 with color-coded warnings

**Run the Code:**
Clone the repository, install dependencies, build the extension, and load it in Chrome to start protecting your Gmail from phishing attacks.
