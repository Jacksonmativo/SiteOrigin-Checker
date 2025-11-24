// ===========================
// DOM ELEMENT REFERENCES
// ===========================
const loadingState = document.getElementById('loading');
const contentState = document.getElementById('content');
const errorState = document.getElementById('error');

const scoreCircle = document.getElementById('scoreCircle');
const scoreValue = document.getElementById('scoreValue');
const scoreLabel = document.getElementById('scoreLabel');

const domainName = document.getElementById('domainName');
const domainAge = document.getElementById('domainAge');
const registrar = document.getElementById('registrar');

// Cipher elements
const cipherScore = document.getElementById('cipherScore');
const cipherStrength = document.getElementById('cipherStrength');
const protocolVersion = document.getElementById('protocolVersion');
const supportedCiphers = document.getElementById('supportedCiphers');
const weakCiphers = document.getElementById('weakCiphers');

// DNS elements
const dnsScoreEl = document.getElementById('dnsScore');
const dnsReliability = document.getElementById('dnsReliability');
const aRecordsEl = document.getElementById('aRecords');
const aaaaRecordsEl = document.getElementById('aaaaRecords');
const mxRecordsEl = document.getElementById('mxRecords');
const nsRecordsEl = document.getElementById('nsRecords');
const spfRecordEl = document.getElementById('spfRecord');
const dmarcRecordEl = document.getElementById('dmarcRecord');
const dkimConfiguredEl = document.getElementById('dkimConfigured');

const sslStatus = document.getElementById('sslStatus');
const sslIssuer = document.getElementById('sslIssuer');
const sslExpiry = document.getElementById('sslExpiry');

const recommendation = document.getElementById('recommendation');
const recommendationText = document.getElementById('recommendationText');
const errorMessage = document.getElementById('errorMessage');

const refreshBtn = document.getElementById('refreshBtn');
const settingsLink = document.getElementById('settingsLink');
const aboutLink = document.getElementById('aboutLink');

// ===========================
// CONFIGURATION
// ===========================
const CONFIG = {
    BACKEND_URL: 'https://siteorigin-checker-5.onrender.com',
    CACHE_DURATION: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
    REQUEST_TIMEOUT: 30000 // 30 seconds
};

// ===========================
// INITIALIZATION
// ===========================
async function init() {
    showLoading();

    try {
        // Get current active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.url) {
            showError('No active tab found');
            return;
        }

        const url = new URL(tab.url);

        // Check if URL is valid for checking
        if (!isValidUrl(url)) {
            showError('Cannot check this type of page (chrome://, about:, file://, etc.)');
            return;
        }

        // Check if we have cached data
        const cached = await getCachedData(url.hostname);

        if (cached && !isExpired(cached.timestamp)) {
            console.log('Using cached data for', url.hostname);
            displayResults(cached.data);
        } else {
            console.log('Fetching fresh data for', url.href);
            // Fetch fresh data from backend
            await fetchAndDisplayResults(url.href);
        }

    } catch (error) {
        console.error('Initialization error:', error);
        showError('Failed to analyze page: ' + error.message);
    }
}

// ===========================
// URL VALIDATION
// ===========================
function isValidUrl(url) {
    const invalidProtocols = [
        'chrome:',
        'about:',
        'file:',
        'chrome-extension:',
        'edge:',
        'brave:',
        'opera:'
    ];

    return !invalidProtocols.some(protocol => url.protocol.startsWith(protocol));
}

// ===========================
// BACKEND COMMUNICATION
// ===========================
async function fetchAndDisplayResults(url) {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

        const response = await fetch(`${CONFIG.BACKEND_URL}/check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `Backend returned ${response.status}`);
        }

        const data = await response.json();

        // Cache the results
        const hostname = new URL(url).hostname;
        await cacheData(hostname, data);

        displayResults(data);

    } catch (error) {
        console.error('Fetch error:', error);

        if (error.name === 'AbortError') {
            showError('Request timed out. The backend might be slow or unresponsive.');
        } else if (error.message.includes('Failed to fetch')) {
            showError('Cannot connect to backend. Please ensure the backend is running on https://siteorigin-checker-5.onrender.com');
        } else {
            showError(`Error: ${error.message}`);
        }
    }
}

// ===========================
// DISPLAY RESULTS
// ===========================
function displayResults(data) {
    hideLoading();
    showContent();

    // Display score
    const score = data.score || 0;
    scoreValue.textContent = Math.round(score);
    scoreCircle.style.setProperty('--score', score);

    // Set score color class
    scoreCircle.classList.remove('low', 'medium', 'high');
    if (score >= 75) {
        scoreCircle.classList.add('high');
    } else if (score >= 50) {
        scoreCircle.classList.add('medium');
    } else {
        scoreCircle.classList.add('low');
    }

    // Display domain information
    domainName.textContent = data.domain || 'Unknown';
    domainName.title = data.domain || 'Unknown'; // Tooltip for long domains

    if (data.domain_age_years !== undefined && data.domain_age_years !== null) {
        const years = data.domain_age_years;
        if (years >= 1) {
            const yearCount = Math.floor(years);
            domainAge.textContent = `${yearCount} year${yearCount !== 1 ? 's' : ''} old`;
        } else {
            const months = Math.floor(years * 12);
            domainAge.textContent = `${months} month${months !== 1 ? 's' : ''} old`;
        }
    } else {
        domainAge.textContent = 'Unknown';
    }

    registrar.textContent = data.registrar || 'Unknown';
    registrar.title = data.registrar || 'Unknown'; // Tooltip for long registrar names

    // Display SSL information
    sslStatus.classList.remove('valid', 'invalid', 'warning');

    if (data.ssl_valid === true) {
        sslStatus.textContent = '✓ Valid';
        sslStatus.classList.add('valid');
    } else if (data.ssl_valid === false) {
        sslStatus.textContent = '✗ Invalid';
        sslStatus.classList.add('invalid');
    } else {
        sslStatus.textContent = 'Unknown';
        sslStatus.classList.add('warning');
    }

    sslIssuer.textContent = data.ssl_issuer || 'Unknown';
    sslIssuer.title = data.ssl_issuer || 'Unknown'; // Tooltip

    if (data.ssl_expiry) {
        try {
            const expiryDate = new Date(data.ssl_expiry);
            const daysUntilExpiry = Math.floor((expiryDate - new Date()) / (1000 * 60 * 60 * 24));

            if (daysUntilExpiry < 30 && daysUntilExpiry > 0) {
                sslExpiry.textContent = `${expiryDate.toLocaleDateString()} (${daysUntilExpiry} days left)`;
                sslStatus.classList.remove('valid');
                sslStatus.classList.add('warning');
                sslStatus.textContent = '⚠️ Expiring Soon';
            } else if (daysUntilExpiry <= 0) {
                sslExpiry.textContent = `${expiryDate.toLocaleDateString()} (EXPIRED)`;
                sslStatus.classList.remove('valid', 'warning');
                sslStatus.classList.add('invalid');
                sslStatus.textContent = '✗ Expired';
            } else {
                sslExpiry.textContent = expiryDate.toLocaleDateString();
            }
        } catch (e) {
            console.error('Error parsing SSL expiry date:', e);
            sslExpiry.textContent = data.ssl_expiry;
        }
    } else {
        sslExpiry.textContent = 'Unknown';
    }

    // Cipher / TLS
    if (data.cipher_score !== undefined && data.cipher_score !== null) {
        cipherScore.textContent = `${Math.round((data.cipher_score || 0) * 100)}/100`;
    } else if (data.cipher_score_percent !== undefined) {
        cipherScore.textContent = `${Math.round(data.cipher_score_percent)}/100`;
    } else {
        cipherScore.textContent = '--';
    }

    cipherStrength.textContent = data.cipher_strength || data.cipher_strength_label || '--';
    protocolVersion.textContent = data.protocol_version || data.tls_version || '--';

    // Supported ciphers (comma-separated)
    if (Array.isArray(data.supported_ciphers) && data.supported_ciphers.length > 0) {
        supportedCiphers.textContent = data.supported_ciphers.join(', ');
    } else {
        supportedCiphers.textContent = '--';
    }

    if (Array.isArray(data.weak_ciphers_found) && data.weak_ciphers_found.length > 0) {
        weakCiphers.textContent = data.weak_ciphers_found.join(', ');
    } else {
        weakCiphers.textContent = '--';
    }

    // DNS information
    if (data.dns_score !== undefined && data.dns_score !== null) {
        dnsScoreEl.textContent = `${Math.round((data.dns_score || 0) * 100)}/100`;
    } else if (data.dns_score_percent !== undefined) {
        dnsScoreEl.textContent = `${Math.round(data.dns_score_percent)}/100`;
    } else {
        dnsScoreEl.textContent = '--';
    }

    dnsReliability.textContent = data.dns_reliability || '--';

    // Format record lists
    const formatList = (arr) => {
        if (!arr) return '--';
        if (Array.isArray(arr) && arr.length > 0) return arr.join(', ');
        return String(arr);
    };

    aRecordsEl.textContent = formatList(data.a_records);
    aaaaRecordsEl.textContent = formatList(data.aaaa_records);
    mxRecordsEl.textContent = formatList((data.mx_records || []).map(r => r.host ? `${r.host}(${r.priority})` : JSON.stringify(r)));
    nsRecordsEl.textContent = formatList(data.ns_records);
    spfRecordEl.textContent = data.spf_record || '--';
    dmarcRecordEl.textContent = data.dmarc_record || '--';
    dkimConfiguredEl.textContent = (data.dkim_configured === true) ? 'Yes' : (data.dkim_configured === false ? 'No' : '--');
    // Display recommendation
    displayRecommendation(score, data);
}

// ===========================
// DISPLAY RECOMMENDATION
// ===========================
function displayRecommendation(score, data) {
    recommendation.classList.remove('safe', 'caution', 'danger');

    if (score >= 75) {
        recommendation.classList.add('safe');
        recommendationText.textContent = '✓ This website appears trustworthy with a strong security profile and established history.';
    } else if (score >= 50) {
        recommendation.classList.add('caution');
        recommendationText.textContent = '⚠️ Exercise caution. This website has some trust indicators but may be relatively new or have security concerns.';
    } else {
        recommendation.classList.add('danger');
        recommendationText.textContent = '⚠️ High risk. This website has limited trust indicators. Avoid entering sensitive information.';
    }
}

// ===========================
// CACHE MANAGEMENT
// ===========================
async function cacheData(hostname, data) {
    try {
        const cacheKey = `cache_${hostname}`;
        const cacheItem = {
            data: data,
            timestamp: Date.now()
        };
        await chrome.storage.local.set({ [cacheKey]: cacheItem });
        console.log('Cached data for', hostname);
    } catch (error) {
        console.error('Error caching data:', error);
    }
}

async function getCachedData(hostname) {
    try {
        const cacheKey = `cache_${hostname}`;
        const result = await chrome.storage.local.get(cacheKey);
        return result[cacheKey] || null;
    } catch (error) {
        console.error('Error retrieving cached data:', error);
        return null;
    }
}

function isExpired(timestamp) {
    return (Date.now() - timestamp) > CONFIG.CACHE_DURATION;
}

async function clearCache(hostname) {
    try {
        const cacheKey = `cache_${hostname}`;
        await chrome.storage.local.remove(cacheKey);
        console.log('Cleared cache for', hostname);
    } catch (error) {
        console.error('Error clearing cache:', error);
    }
}

// ===========================
// UI STATE MANAGEMENT
// ===========================
function showLoading() {
    loadingState.classList.remove('content-hidden');
    contentState.classList.add('content-hidden');
    errorState.classList.add('content-hidden');
}

function hideLoading() {
    loadingState.classList.add('content-hidden');
}

function showContent() {
    contentState.classList.remove('content-hidden');
    errorState.classList.add('content-hidden');
}

function showError(message) {
    hideLoading();
    errorMessage.textContent = message;
    errorState.classList.remove('content-hidden');
    contentState.classList.add('content-hidden');
}

// ===========================
// EVENT LISTENERS
// ===========================
refreshBtn.addEventListener('click', async () => {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            const hostname = new URL(tab.url).hostname;
            await clearCache(hostname);
            init();
        }
    } catch (error) {
        console.error('Error refreshing:', error);
        showError('Failed to refresh: ' + error.message);
    }
});

settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    // TODO: Implement settings page
    alert('Settings page coming soon!\n\nPlanned features:\n• Backend URL configuration\n• Cache duration settings\n• Scoring weight customization\n• Display preferences');
});

aboutLink.addEventListener('click', (e) => {
    e.preventDefault();
    const aboutText = `SiteOrigin Checker v1.0

A browser extension that evaluates website authenticity based on:
• Domain Age (via WHOIS/RDAP)
• SSL/TLS Certificate Validation
• Composite Trust Scoring

Developed for security-conscious browsing.

GitHub: [Your Repository URL]
License: MIT`;

    alert(aboutText);
});

// ===========================
// STARTUP
// ===========================
document.addEventListener('DOMContentLoaded', () => {
    console.log('SiteOrigin Checker popup initialized');
    init();
});