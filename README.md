# 🔒 SiteOrigin Checker

A browser extension that evaluates the authenticity and trustworthiness of websites by analyzing domain age, SSL/TLS certificates, and computing a composite trust score.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Chrome](https://img.shields.io/badge/Chrome-Compatible-brightgreen)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
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

**SiteOrigin Checker** helps users make informed decisions about website trustworthiness by automatically evaluating search results and displaying color-coded trust indicators. The extension analyzes domain registration history and SSL certificate validity to provide a comprehensive authenticity score.

### Key Benefits

- **Instant Trust Assessment**: See trust scores at a glance while browsing search results
- **Detailed Reports**: Access comprehensive domain and SSL information with one click
- **Privacy-Focused**: Only analyzes URLs you visit; no browsing history is stored
- **Free & Open Source**: No subscriptions, no hidden costs

## ✨ Features

### Core Functionality

- **Automatic Search Result Analysis**: Detects and evaluates websites listed in Google, Bing, and other search engines
- **Visual Trust Indicators**: Color-coded badges (Green/Yellow/Red) show trust levels
- **Domain Age Verification**: Checks WHOIS/RDAP data for domain creation dates
- **SSL/TLS Certificate Validation**: Verifies certificate validity, issuer, and expiration
- **Composite Trust Score**: Weighted scoring algorithm (0-100) combines multiple factors
- **Real-time Updates**: Loading spinners show analysis progress
- **Caching System**: Reduces API calls and improves performance (7-day cache)

### Detailed Reports

Click any trust badge to view:
- Domain registration age
- Domain registrar information
- SSL certificate status and issuer
- Certificate expiration date
- Trust score breakdown
- Security recommendations

## 🔍 How It Works

1. **User performs a web search** (Google, Bing, etc.)
2. **Extension detects search results page loading**
3. **Loading spinner appears** next to each search result
4. **Backend API is called** with each result URL
5. **Domain age is checked** via WHOIS/RDAP APIs
6. **SSL certificate is validated** through TLS handshake
7. **Composite score is calculated** using weighted formula
8. **Trust badge is displayed** (color-coded: Green/Yellow/Red)
9. **User can click badge** for detailed security report

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
   - Security recommendations

### Refreshing Data

- Click the **"Retry Analysis"** button in the popup to force a new analysis
- Cached data expires after 30 minutes automatically
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

- **Framework**: Flask / FastAPI
- **Libraries**:
  - `python-whois` - WHOIS queries
  - `ssl` & `socket` - Certificate validation
  - `requests` - HTTP client
  - `flask-cors` - Cross-origin support

### APIs Used

- **WHOIS/RDAP APIs**:
  - Primary: who-dat (free, fast)
  - Fallback: rdap.net
  - Last resort: WhoisXML API (500 free/month)

## 📁 Project Structure

```
SiteOriginChecker/
├── extension/
│   ├── manifest.json              # Extension configuration
│   ├── background.js              # Service worker (API communication)
│   ├── contentScript.js           # DOM manipulation (badges/spinners)
│   ├── popup/
│   │   ├── popup.html            # Popup interface
│   │   ├── popup.js              # Popup logic
│   │   └── popup.css             # Popup styling
│   ├── icons/
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   └── styles/
│       └── content.css           # Content script styles
│
├── backend/
│   ├── app.py                    # Flask/FastAPI entry point
│   ├── whois_checker.py          # Domain age verification
│   ├── ssl_checker.py            # Certificate validation
│   ├── score_calculator.py       # Composite scoring algorithm
│   ├── requirements.txt          # Python dependencies
│   └── tests/
│       ├── test_whois_checker.py
│       ├── test_ssl_checker.py
│       └── test_score_calculator.py
│
├── .env.example                  # Environment variables template
├── .gitignore                    # Git ignore rules
├── LICENSE                       # MIT License
└── README.md                     # This file
```

## 🔌 API Documentation

### POST /check

Analyzes a given URL and returns trust metrics.

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
  "ssl_strength": "strong",
  "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
  "protocol_version": "TLSv1.3",
  "days_until_expiry": 180,
  "score": 93,
  "trust_level": "high"
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

### Hot Reload (Optional)

Install `flask-reload` for automatic server restarts:
```bash
pip install flask-reload
```

## 📊 Scoring Logic

### Composite Score Formula

```
Composite Score = (Domain Age Score × 0.6) + (SSL Score × 0.4)
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

### Trust Level Classification

| Score Range | Badge Color | Trust Level | Recommendation |
|-------------|-------------|-------------|----------------|
| 80-100      | 🟢 Green    | High        | Safe to use    |
| 60-79       | 🟡 Yellow   | Medium      | Exercise caution |
| 0-59        | 🔴 Red      | Low         | Avoid sensitive data |

### Weight Customization

You can adjust weights in `backend/score_calculator.py`:
```python
DOMAIN_WEIGHT = 0.6  # Default: 60% weight on domain age
SSL_WEIGHT = 0.4     # Default: 40% weight on SSL validity
```

## 🧪 Testing

### Running Backend Tests

```bash
cd backend
python -m pytest tests/ -v
```

### Running Specific Test Files

```bash
# Test WHOIS checker
python -m pytest tests/test_whois_checker.py -v

# Test SSL checker
python -m pytest tests/test_ssl_checker.py -v

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
- [ ] Popup opens and displays data correctly
- [ ] Cache works (second visit shows instant results)
- [ ] Error handling for invalid URLs
- [ ] Backend API responds within 2 seconds

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
  "version": "1.0.0",
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

**Issue**: Wrong trust scores
- **Solution**:
  - Clear cache: Right-click extension icon > Options > Clear Cache
  - Check backend logs for API errors
  - Verify WHOIS/RDAP APIs are accessible

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

- **Report bugs, Ask questions**: [GitHub Issues](https://github.com/jacksonmativo/siteorigin-checker/issues)


## 🔒 Privacy & Security

### Data Collection

**What we collect**:
- ✅ URLs of websites you search for (temporarily, only for analysis)
- ✅ Domain age and SSL certificate data (cached locally)

**What we DON'T collect**:
- ❌ Browsing history
- ❌ Personal information
- ❌ Passwords or credentials
- ❌ Search queries or typed text

### Data Storage

- **Local Storage**: All data is stored locally in your browser
- **Cache Duration**: 30 minutes for analysis results, 7 days for domain data
- **No Cloud Sync**: Nothing is sent to external servers except WHOIS/SSL APIs

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

### Version 1.1 (Q1 2025)
- [ ] Firefox extension support
- [ ] Safari extension support
- [ ] Advanced SSL analysis (cipher suites, protocols)
- [ ] Domain reputation API integration
- [ ] Export reports as PDF

### Version 1.2 (Q2 2025)
- [ ] Real-time phishing detection
- [ ] Machine learning-based risk scoring
- [ ] Historical domain ownership tracking
- [ ] Browser notification system
- [ ] Multi-language support

### Version 2.0 (Q3 2025)
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
feat(ssl): add support for ECC certificates

- Implemented elliptic curve certificate validation
- Added tests for ECC cipher suites
- Updated documentation

Closes #123
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
- [Chrome Extensions API](https://developer.chrome.com/docs/extensions/) - Browser integration

### APIs & Services

- [who-dat](https://who-dat.as93.net/) - Free WHOIS service
- [rdap.net](https://about.rdap.org/) - RDAP protocol
- [Let's Encrypt](https://letsencrypt.org/) - Free SSL certificates



### Inspiration

This project was inspired by the need for better online security awareness and tools that help users make informed decisions about website trustworthiness.

---

## 📞 Contact & Support

- **Email**: jacksonmativo@gmail.com
- **GitHub**: [github.com/jacksonmativo/siteorigin-checker](https://github.com/jacksonmatio/siteorigin-checker)


### Support the Project

If you find this project useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting features
- 🔀 Contributing code
- 📢 Sharing with others

---

**Made with ❤️ by the Jackson Mativo**

*Helping users browse safer, one search at a time.*