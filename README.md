# 🔒 SiteOrigin Checker

A browser extension that evaluates the authenticity and trustworthiness of websites by analyzing domain age, SSL/TLS certificates, cipher suites, DNS configuration, and computing a comprehensive trust score.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Chrome](https://img.shields.io/badge/Chrome-Compatible-brightgreen)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [What's New in v2.0](#whats-new-in-v20)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Scoring Logic](#scoring-logic)
- [Testing](#testing)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Privacy & Security](#privacy--security)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## 🎯 Overview

**SiteOrigin Checker** helps users make informed decisions about website trustworthiness by automatically evaluating search results and displaying color-coded trust indicators. The extension analyzes domain registration history, SSL certificate validity, encryption strength, and DNS configuration to provide a comprehensive authenticity score.

### Key Benefits

- **Comprehensive Security Analysis**: Evaluates 4 key security dimensions
- **Instant Trust Assessment**: See trust scores at a glance while browsing search results
- **Detailed Reports**: Access comprehensive domain, SSL, cipher, and DNS information with one click
- **Privacy-Focused**: Only analyzes URLs you visit; no browsing history is stored
- **Free & Open Source**: No subscriptions, no hidden costs

## ✨ Features

### Core Functionality

- **Automatic Search Result Analysis**: Detects and evaluates websites listed in Google, Bing, and other search engines
- **Visual Trust Indicators**: Color-coded badges (Green/Yellow/Red) show trust levels
- **Domain Age Verification**: Checks WHOIS/RDAP data for domain creation dates
- **SSL/TLS Certificate Validation**: Verifies certificate validity, issuer, and expiration
- **🆕 Cipher Suite Analysis**: Identifies weak encryption and outdated TLS protocols
- **🆕 DNS Configuration Check**: Verifies DNS records and email security (SPF, DMARC, DKIM)
- **Composite Trust Score**: Weighted scoring algorithm (0-100) combines multiple factors
- **Real-time Updates**: Loading spinners show analysis progress
- **Caching System**: Reduces API calls and improves performance (7-day cache)

### Detailed Reports

Click any trust badge to view:
- Domain registration age and registrar information
- SSL certificate status, issuer, and expiration date
- **🆕 TLS protocol version and supported cipher suites**
- **🆕 Weak cipher detection with warnings**
- **🆕 DNS record completeness (A, AAAA, MX, NS records)**
- **🆕 Email security configuration (SPF, DMARC, DKIM)**
- Trust score breakdown with individual component scores
- Security recommendations

## 🆕 What's New in v2.0

### Enhanced Security Analysis

**Cipher Suite Checker**
- Detects TLS versions (1.0, 1.1, 1.2, 1.3)
- Identifies weak ciphers (RC4, 3DES, DES, etc.)
- Recognizes modern strong ciphers (AES-GCM, ChaCha20-Poly1305)
- Provides encryption strength score (0-100)
- Warns about outdated protocols and weak encryption

**DNS Configuration Checker**
- Queries A, AAAA, MX, NS, and TXT records
- Verifies DNS reliability and completeness
- Detects SPF records (email spoofing prevention)
- Checks DMARC policy records (email authentication)
- Probes for DKIM configuration (email integrity)
- Provides DNS reliability score (0-100)

### Updated Scoring Algorithm

New weighted formula for more comprehensive evaluation:
- **Domain Age**: 35% (was 60%)
- **SSL Validity**: 25% (was 40%)
- **Cipher Strength**: 20% (NEW)
- **DNS Configuration**: 20% (NEW)

### Enhanced User Interface

- New cipher security section with expandable details
- DNS configuration display with email security status
- Visual indicators for weak ciphers and missing security records
- Expanded recommendations based on all security metrics

## 🔍 How It Works

1. **User performs a web search** (Google, Bing, etc.)
2. **Extension detects search results page loading**
3. **Loading spinner appears** next to each search result
4. **Backend API is called** with each result URL
5. **Domain age is checked** via WHOIS/RDAP APIs
6. **SSL certificate is validated** through TLS handshake
7. **🆕 Cipher suites are analyzed** to detect encryption strength
8. **🆕 DNS records are queried** for configuration completeness
9. **Composite score is calculated** using weighted formula
10. **Trust badge is displayed** (color-coded: Green/Yellow/Red)
11. **User can click badge** for detailed security report

## 🚀 Installation

### Prerequisites

- **Browser**: Chrome, Edge, Brave, or other Chromium-based browsers
- **Python**: 3.8 or higher
- **Node.js**: (Optional, for development)

### Backend Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/jacksonmativo/siteorigin-checker.git
   cd siteorigin-checker
   ```

2. **Install Python dependencies**:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

   Key dependencies:
   - `flask` - Web framework
   - `python-whois` - Domain age checking
   - `pyOpenSSL` - SSL certificate validation
   - `dnspython` - DNS record queries (NEW)
   - `redis` - Caching (optional)

3. **Configure environment variables** (optional):
   ```bash
   cp .env.example .env
   # Edit .env with your API keys if using WhoisXML API
   ```

4. **Start the Flask backend**:
   ```bash
   python app.py
   ```

   The backend will run on `http://localhost:5000`

### Extension Installation

1. **Open your browser** and navigate to extensions page:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
   - Brave: `brave://extensions`

2. **Enable Developer Mode** (toggle in top-right corner)

3. **Click "Load unpacked"**

4. **Select the `extension` folder** from the cloned repository

5. **Verify installation**: The SiteOrigin Checker icon should appear in your toolbar

## 📖 Usage

### Basic Usage

1. **Perform a web search** on Google, Bing, or another search engine
2. **Wait for badges to appear** next to each search result
3. **Interpret the colors**:
   - 🟢 **Green** (Score 80-100): High trust, established website
   - 🟡 **Yellow** (Score 60-79): Moderate trust, exercise caution
   - 🔴 **Red** (Score 0-59): Low trust, avoid entering sensitive data

### Viewing Detailed Reports

1. **Click any trust badge** or the extension icon
2. **Review the popup report** showing:
   - Overall trust score
   - Domain age and registrar
   - SSL certificate details
   - **🆕 Cipher suite information and protocol version**
   - **🆕 DNS record completeness**
   - **🆕 Email security configuration (SPF, DMARC, DKIM)**
   - Security recommendations

### Understanding the New Metrics

**Cipher Score (0-100)**
- 80-100: Strong modern encryption (TLS 1.2/1.3 with AES-GCM or ChaCha20)
- 50-79: Medium encryption (some weak ciphers detected)
- 0-49: Weak encryption (outdated protocols or weak ciphers like RC4, 3DES)

**DNS Score (0-100)**
- 80-100: Excellent DNS configuration with security records
- 60-79: Good DNS setup with some missing records
- 40-59: Basic DNS with missing important records
- 0-39: Incomplete DNS configuration

### Refreshing Data

- Click the **"Refresh Analysis"** button in the popup to force a new analysis
- Cached data expires after 7 days automatically
- Clear cache from extension settings if needed

## 🛠️ Technology Stack

### Frontend (Browser Extension)

- **Manifest Version**: V3 (Chrome Extension)
- **Languages**: HTML5, CSS3, JavaScript (ES6+)
- **Browser APIs**:
  - `chrome.tabs` - Detect search pages
  - `chrome.storage` - Cache results
  - `chrome.runtime` - Background communication

### Backend (Python)

- **Framework**: Flask
- **Libraries**:
  - `python-whois` - WHOIS queries
  - `ssl` & `socket` - Certificate validation
  - `pyOpenSSL` - Advanced SSL analysis
  - `dnspython` - DNS record queries (NEW)
  - `requests` - HTTP client
  - `flask-cors` - Cross-origin support
  - `redis` - Caching layer (optional)

### APIs Used

- **WHOIS/RDAP APIs**:
  - Primary: who-dat (free, fast)
  - Fallback: rdap.net
  - Last resort: WhoisXML API (500 free/month)

- **DNS Queries**: Direct DNS resolution via dnspython (no external API)

## 📁 Project Structure

```
SiteOriginChecker/
├── extension/
│   ├── manifest.json              # Extension configuration
│   ├── background.js              # Service worker (API communication)
│   ├── contentScript.js           # DOM manipulation (badges/spinners)
│   ├── popup/
│   │   ├── popup.html            # Popup interface (UPDATED)
│   │   ├── popup.js              # Popup logic (UPDATED)
│   │   └── popup.css             # Popup styling (UPDATED)
│   ├── icons/
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   └── styles/
│       └── content.css           # Content script styles
│
├── backend/
│   ├── app.py                    # Flask entry point (UPDATED)
│   ├── whois_checker.py          # Domain age verification
│   ├── ssl_checker.py            # Certificate validation
│   ├── cipher_checker.py         # Cipher suite analysis (NEW)
│   ├── dns_checker.py            # DNS record verification (NEW)
│   ├── score_calculator.py       # Composite scoring algorithm (UPDATED)
│   ├── requirements.txt          # Python dependencies (UPDATED)
│   └── tests/
│       ├── test_whois_checker.py
│       ├── test_ssl_checker.py
│       ├── test_cipher_dns_checkers.py  # (NEW)
│       └── test_score_calculator.py
│
├── .env.example                  # Environment variables template
├── .gitignore                    # Git ignore rules
├── LICENSE                       # MIT License
├── README.md                     # This file (UPDATED)
└── USAGE_EXAMPLES.md             # Detailed usage guide (NEW)
```

## 🔌 API Documentation

### POST /check

Analyzes a given URL and returns comprehensive trust metrics.

**Endpoint**: `POST http://localhost:5000/check`

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "url": "https://example.com"
}
```

**Response** (200 OK):
```json
{
  "domain": "example.com",
  "domain_age_years": 7.5,
  "registrar": "Example Registrar, Inc.",
  "ssl_valid": true,
  "ssl_issuer": "Let's Encrypt",
  "ssl_expiry": "2025-12-31",
  "ssl_days_remaining": 180,

  "cipher_score": 0.95,
  "cipher_strength": "strong",
  "protocol_version": "TLSv1.3",
  "supported_ciphers": [
    "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_AES_256_GCM_SHA384"
  ],
  "weak_ciphers_found": [],
  "cipher_recommendations": [
    "Excellent: Using TLS 1.3 with modern ciphers"
  ],

  "dns_score": 0.90,
  "dns_reliability": "high",
  "a_records": ["93.184.216.34"],
  "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
  "mx_records": [
    {"priority": 10, "host": "mail1.example.com"}
  ],
  "ns_records": ["ns1.example.com", "ns2.example.com"],
  "spf_record": "v=spf1 include:_spf.example.com ~all",
  "dmarc_record": "v=DMARC1; p=reject",
  "dkim_configured": true,
  "dns_recommendations": [
    "Excellent DNS configuration with security features"
  ],

  "score": 88.5,
  "trust_level": "high",
  "checked_at": "2025-01-15T10:30:00"
}
```

**Response** (400 Bad Request):
```json
{
  "error": "Invalid URL provided"
}
```

**Response** (500 Internal Server Error):
```json
{
  "error": "Failed to retrieve domain information"
}
```

## 💻 Development

### Setting Up Development Environment

1. **Clone and install dependencies** (see Installation section)

2. **Run backend in development mode**:
   ```bash
   cd backend
   export FLASK_ENV=development  # Linux/Mac
   set FLASK_ENV=development     # Windows
   python app.py
   ```

3. **Load extension in developer mode** (see Extension Installation)

4. **Enable extension debugging**:
   - Open Chrome DevTools in the extension popup
   - Check background service worker logs in `chrome://extensions`
   - Monitor network requests in the Network tab

### Making Changes

**Backend Changes**:
- Edit Python files in `backend/` directory
- Restart Flask server to apply changes
- Run tests: `python -m pytest tests/`

**Extension Changes**:
- Edit files in `extension/` directory
- Click "Reload" button on `chrome://extensions` page
- Refresh the page you're testing on

### Running Tests

```bash
cd backend

# Run all tests
python -m pytest tests/ -v

# Run specific test files
python -m pytest tests/test_cipher_dns_checkers.py -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html
```

## 📊 Scoring Logic

### Composite Score Formula (v2.0)

```
Composite Score = (Domain Age × 0.35) + (SSL × 0.25) + (Cipher × 0.20) + (DNS × 0.20)
```

### Domain Age Score

| Domain Age       | Score | Risk Level |
|-----------------|-------|------------|
| > 5 years       | 100   | Very Low   |
| 3-5 years       | 70    | Low        |
| 1-3 years       | 50    | Medium     |
| < 1 year        | 20    | High       |

### SSL Certificate Score

| SSL Status              | Score | Security Level |
|------------------------|-------|----------------|
| Valid + Strong Cipher  | 100   | Excellent      |
| Valid + Medium Cipher  | 70    | Good           |
| Valid + Weak Cipher    | 70    | Fair           |
| Expiring < 30 days     | 50    | Warning        |
| Invalid/Self-signed    | 0     | Critical       |

### Cipher Suite Score (NEW)

| Cipher Configuration    | Score | Strength |
|------------------------|-------|----------|
| TLS 1.3 + Modern Ciphers | 90-100 | Strong |
| TLS 1.2 + AES-GCM       | 70-89  | Medium |
| TLS 1.0/1.1 or Weak Ciphers | 0-50 | Weak |

**Weak Cipher Detection**:
- RC4, 3DES, DES, MD5
- Export-grade ciphers
- Anonymous Diffie-Hellman
- NULL ciphers

### DNS Configuration Score (NEW)

| DNS Configuration | Score | Reliability |
|------------------|-------|-------------|
| Complete + Security Records | 80-100 | High |
| Good Setup + Some Records | 60-79 | Medium |
| Basic Setup | 40-59 | Low |
| Incomplete | 0-39 | Very Low |

**Scoring Factors**:
- A records (20%)
- AAAA records (10%)
- MX records (15%)
- NS records (20%)
- SPF record (10%)
- DMARC record (15%)
- DKIM configuration (10%)

### Trust Level Classification

| Score Range | Badge Color | Trust Level | Recommendation |
|-------------|-------------|-------------|----------------|
| 80-100      | 🟢 Green    | High        | Safe to use    |
| 60-79       | 🟡 Yellow   | Medium      | Exercise caution |
| 0-59        | 🔴 Red      | Low         | Avoid sensitive data |

### Weight Customization

You can adjust weights in `backend/score_calculator.py`:
```python
DOMAIN_WEIGHT = 0.35  # Domain age importance
SSL_WEIGHT = 0.25     # SSL validity importance
CIPHER_WEIGHT = 0.20  # Cipher strength importance
DNS_WEIGHT = 0.20     # DNS configuration importance
```

## 🧪 Testing

### Running Backend Tests

```bash
cd backend
python -m pytest tests/ -v
```

### Running Specific Test Files

```bash
# Test cipher and DNS checkers
python -m pytest tests/test_cipher_dns_checkers.py -v

# Test score calculator
python -m pytest tests/test_score_calculator.py -v
```

### Test Coverage

Generate coverage report:
```bash
pip install pytest-cov
python -m pytest tests/ --cov=. --cov-report=html
```

View coverage report: Open `htmlcov/index.html` in your browser

### Manual Testing Checklist

- [ ] Extension loads without errors
- [ ] Badges appear on Google search results
- [ ] Loading spinners display during analysis
- [ ] Correct badge colors for known sites
- [ ] Popup opens and displays all new data (cipher, DNS)
- [ ] Cipher details expand/collapse correctly
- [ ] DNS email security section displays properly
- [ ] Cache works (second visit shows instant results)
- [ ] Error handling for invalid URLs
- [ ] Backend API responds within 5 seconds

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the `backend/` directory:

```bash
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=True
PORT=5000

# API Keys (Optional)
WHOISXML_API_KEY=your_api_key_here

# Cache Settings
CACHE_TTL=1800  # 30 minutes in seconds
DOMAIN_CACHE_TTL=604800  # 7 days for domain data

# DNS Settings
DNS_TIMEOUT=10  # DNS query timeout in seconds

# Cipher Check Settings
CIPHER_TIMEOUT=10  # TLS handshake timeout

# Rate Limiting
MAX_REQUESTS_PER_MINUTE=60

# CORS Settings
ALLOWED_ORIGINS=chrome-extension://*
```

### Extension Settings

Edit `extension/manifest.json` for extension configuration:

```json
{
  "name": "SiteOrigin Checker",
  "version": "2.0.0",
  "permissions": [
    "activeTab",
    "storage",
    "tabs"
  ],
  "host_permissions": [
    "http://localhost:5000/*"
  ]
}
```

## 🔧 Troubleshooting

### Common Issues

**Issue**: Extension doesn't appear after installation
- **Solution**: Refresh the extensions page and ensure "Developer mode" is enabled

**Issue**: Badges don't show on search results
- **Solution**:
  - Check that backend is running on `http://localhost:5000`
  - Open browser console and check for CORS errors
  - Verify content script is injected (check DevTools > Sources)

**Issue**: "Failed to fetch" errors
- **Solution**:
  - Ensure backend server is running
  - Check firewall settings (allow port 5000)
  - Verify `host_permissions` in manifest.json

**Issue**: Cipher or DNS check fails
- **Solution**:
  - Check network connectivity
  - Increase timeout values in `.env`
  - Verify `dnspython` is installed: `pip install dnspython`

**Issue**: Wrong trust scores
- **Solution**:
  - Clear cache: Right-click extension icon > Options > Clear Cache
  - Check backend logs for API errors
  - Verify WHOIS/DNS APIs are accessible

**Issue**: Slow performance
- **Solution**:
  - Enable caching in backend
  - Reduce `MAX_REQUESTS_PER_MINUTE` if rate-limited
  - Use local Redis for caching instead of in-memory

### Debug Mode

Enable verbose logging:

**Backend**:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Extension**:
```javascript
// In background.js or contentScript.js
const DEBUG = true;
if (DEBUG) console.log('Debug message');
```

### Getting Help

- **Report bugs**: [GitHub Issues](https://github.com/jacksonmativo/siteorigin-checker/issues)
- **Ask questions**: [GitHub Discussions](https://github.com/jacksonmativo/siteorigin-checker/discussions)

## 🔒 Privacy & Security

### Data Collection

**What we collect**:
- ✅ URLs of websites you search for (temporarily, only for analysis)
- ✅ Domain age, SSL, cipher, and DNS data (cached locally)

**What we DON'T collect**:
- ❌ Browsing history
- ❌ Personal information
- ❌ Passwords or credentials
- ❌ Search queries or typed text

### Data Storage

- **Local Storage**: All data is stored locally in your browser
- **Cache Duration**: 30 minutes for analysis results, 7 days for domain data
- **No Cloud Sync**: Nothing is sent to external servers except WHOIS/DNS APIs

### Security Best Practices

- Backend runs locally (localhost only)
- HTTPS required for all external API calls
- No third-party analytics or tracking
- Open source code for transparency
- Regular security audits

### Permissions Explained

| Permission | Purpose |
|-----------|---------|
| `activeTab` | Read current tab URL for analysis |
| `storage` | Cache results locally |
| `tabs` | Detect search result pages |

## 🗺️ Roadmap

### Version 2.1 (Q2 2025)
- [ ] Firefox extension support
- [ ] Safari extension support
- [ ] Certificate Transparency Log checking
- [ ] HSTS preload list verification
- [ ] Export reports as PDF

### Version 2.2 (Q3 2025)
- [ ] Real-time phishing detection
- [ ] Machine learning-based risk scoring
- [ ] Historical domain ownership tracking
- [ ] Browser notification system
- [ ] Multi-language support

### Version 3.0 (Q4 2025)
- [ ] Enterprise features (team management)
- [ ] Custom scoring rules
- [ ] API access for developers
- [ ] Mobile app companion
- [ ] Advanced reporting dashboard

### Community Requests
- [ ] Dark mode for popup
- [ ] Customizable badge colors
- [ ] Whitelist/blacklist functionality
- [ ] Integration with password managers

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Ways to Contribute

1. **Report Bugs**: Open an issue with detailed reproduction steps
2. **Suggest Features**: Share your ideas in Discussions
3. **Submit Pull Requests**: Fix bugs or add features
4. **Improve Documentation**: Help make our docs better
5. **Spread the Word**: Share with friends and colleagues

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** and commit: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Coding Standards

**Python**:
- Follow PEP 8 style guide
- Add docstrings to all functions
- Write unit tests for new features
- Run `flake8` and `black` before committing

**JavaScript**:
- Use ES6+ syntax
- Follow Airbnb JavaScript style guide
- Add JSDoc comments
- Use meaningful variable names

### Commit Message Format

```
type(scope): subject

body

footer
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Example**:
```
feat(dns): add DNSSEC verification support

- Implemented DS record checking
- Added DNSSEC validation in dns_checker.py
- Updated tests for DNSSEC functionality

Closes #45
```

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 SiteOrigin Checker Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

## 🙏 Acknowledgments

### Open Source Libraries

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [python-whois](https://github.com/richardpenman/whois) - WHOIS parsing
- [dnspython](https://www.dnspython.org/) - DNS toolkit (NEW)
- [pyOpenSSL](https://www.pyopenssl.org/) - SSL/TLS wrapper
- [Chrome Extensions API](https://developer.chrome.com/docs/extensions/) - Browser integration

### APIs & Services

- [who-dat](https://who-dat.as93.net/) - Free WHOIS service
- [rdap.net](https://about.rdap.org/) - RDAP protocol
- [Let's Encrypt](https://letsencrypt.org/) - Free SSL certificates

### Inspiration

This project was inspired by the need for better online security awareness and tools that help users make informed decisions about website trustworthiness. Special thanks to the security community for guidance on cipher suite evaluation and DNS security best practices.

---

## 📞 Contact & Support

- **Email**: jacksonmativo@gmail.com
- **GitHub**: [github.com/jacksonmativo/siteorigin-checker](https://github.com/jacksonmativo/siteorigin-checker)

### Support the Project

If you find this project useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting features
- 🔀 Contributing code
- 📢 Sharing with others

---

## 📈 Version History

### v2.0.0 (January 2025)
- ✨ **NEW**: Cipher suite analysis with TLS version detection
- ✨ **NEW**: DNS configuration verification
- ✨ **NEW**: Email security checking (SPF, DMARC, DKIM)
- 🔄 Updated scoring algorithm with 4 components
- 🎨 Enhanced UI with expandable sections
- 📚 Comprehensive documentation and usage examples

### v1.0.0 (December 2024)
- 🎉 Initial release
- ✅ Domain age verification
- ✅ SSL certificate validation
- ✅ Basic trust scoring
- ✅ Browser extension for Chrome

---

**Made with ❤️ by Jackson Mativo**

*Helping users browse safer, one search at a time.*

**Version 2.0.0** - Now with comprehensive encryption and DNS analysis!