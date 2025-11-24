// Backend API configuration
const API_BASE_URL = 'https://siteorigin-checker-5.onrender.com'; 
// Cache for storing check results
const resultCache = new Map();
const CACHE_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// Message listener for content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkSite') {
    checkSiteAuthenticity(request.url)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep message channel open for async response
  } else if (request.action === 'batchCheck') {
    batchCheckSites(request.urls)
      .then(results => sendResponse({ success: true, data: results }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  } else if (request.action === 'getSettings') {
    getSettings()
      .then(settings => sendResponse({ success: true, data: settings }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

// Check single site authenticity
async function checkSiteAuthenticity(url) {
  try {
    // Check cache first
    const cached = getCachedResult(url);
    if (cached) {
      console.log('Cache hit for:', url);
      return cached;
    }

    // Make API request
    const response = await fetch(`${API_BASE_URL}/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const result = await response.json();

    // Cache the result
    setCachedResult(url, result);

    return result;
  } catch (error) {
    console.error('Error checking site:', error);
    // Return a default error result
    return {
      url,
      score: 0,
      trust_level: 'error',
      error: error.message
    };
  }
}

// Batch check multiple sites
async function batchCheckSites(urls) {
  try {
    // Filter out already cached results
    const uncachedUrls = [];
    const results = [];

    for (const url of urls) {
      const cached = getCachedResult(url);
      if (cached) {
        results.push(cached);
      } else {
        uncachedUrls.push(url);
      }
    }

    // If all results are cached, return immediately
    if (uncachedUrls.length === 0) {
      return results;
    }

    // Make batch API request for uncached URLs
    const response = await fetch(`${API_BASE_URL}/batch-check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ urls: uncachedUrls })
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const batchResult = await response.json();

    // Cache the new results and add to results array
    if (batchResult.results) {
      for (const result of batchResult.results) {
        setCachedResult(result.url, result);
        results.push(result);
      }
    }

    return results;
  } catch (error) {
    console.error('Error batch checking sites:', error);
    // Return error results for all URLs
    return urls.map(url => ({
      url,
      score: 0,
      trust_level: 'error',
      error: error.message
    }));
  }
}

// Cache management functions
function getCachedResult(url) {
  const cached = resultCache.get(url);
  if (!cached) return null;

  const now = Date.now();
  if (now - cached.timestamp > CACHE_DURATION) {
    resultCache.delete(url);
    return null;
  }

  return cached.data;
}

function setCachedResult(url, data) {
  resultCache.set(url, {
    data,
    timestamp: Date.now()
  });

  // Clean up old cache entries if cache is too large
  if (resultCache.size > 1000) {
    const entries = Array.from(resultCache.entries());
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);

    // Remove oldest 200 entries
    for (let i = 0; i < 200; i++) {
      resultCache.delete(entries[i][0]);
    }
  }
}

// Settings management
async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({
      enabled: true,
      showBadges: true,
      showPopup: true,
      autoCheck: true,
      apiUrl: API_BASE_URL
    }, resolve);
  });
}

async function saveSettings(settings) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(settings, resolve);
  });
}

// Initialize extension on install
chrome.runtime.onInstalled.addListener(() => {
  console.log('SiteOrigin Checker installed');

  // Set default settings
  chrome.storage.sync.set({
    enabled: true,
    showBadges: true,
    showPopup: true,
    autoCheck: true,
    apiUrl: API_BASE_URL
  });
});

// Handle tab updates to clear cache for specific domains if needed
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Could implement cache clearing logic here if needed
  }
});

// Periodic cache cleanup
setInterval(() => {
  const now = Date.now();
  for (const [url, cached] of resultCache.entries()) {
    if (now - cached.timestamp > CACHE_DURATION) {
      resultCache.delete(url);
    }
  }
}, 60 * 60 * 1000); // Run every hour