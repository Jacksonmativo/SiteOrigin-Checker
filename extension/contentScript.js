/* Content script for SiteOrigin Checker */
(function() {
'use strict';

// Debounce function to prevent excessive API calls
function debounce(func, wait) {
let timeout;
return function executedFunction(...args) {
const later = () => {
clearTimeout(timeout);
func(...args);
};
clearTimeout(timeout);
timeout = setTimeout(later, wait);
};
}

// Search engine selectors configuration
const searchEngineSelectors = {
google: {
results: 'div.g:not(.related-question-pair)',
link: 'a[href]:first-of-type',
titleContainer: 'h3',
insertPosition: 'afterbegin'
},
bing: {
results: 'li.b_algo',
link: 'h2 a',
titleContainer: 'h2',
insertPosition: 'afterbegin'
},
duckduckgo: {
results: 'article[data-testid="result"]',
link: 'a[data-testid="result-title-a"]',
titleContainer: 'h2',
insertPosition: 'afterbegin'
},
yahoo: {
results: 'div.dd.algo',
link: 'h3.title a',
titleContainer: 'h3.title',
insertPosition: 'afterbegin'
},
baidu: {
results: 'div.result',
link: 'h3.t a',
titleContainer: 'h3.t',
insertPosition: 'afterbegin'
}
};

// Detect current search engine
function detectSearchEngine() {
const hostname = window.location.hostname;
if (hostname.includes('google.com')) return 'google';
if (hostname.includes('bing.com')) return 'bing';
if (hostname.includes('duckduckgo.com')) return 'duckduckgo';
if (hostname.includes('yahoo.com')) return 'yahoo';
if (hostname.includes('baidu.com')) return 'baidu';
return null;
}

// Create loading spinner element (safe DOM creation)
function createSpinner() {
const spinner = document.createElement('div');
spinner.className = 'soc-spinner';

const circle = document.createElement('div');
circle.className = 'soc-spinner-circle';

spinner.appendChild(circle);
return spinner;

}

// Create trust badge element (safe DOM creation, no innerHTML)
function createBadge(data) {
const badge = document.createElement('div');
badge.className = `soc-badge soc-badge-${data.trust_level || 'error'}`;
badge.setAttribute('role', 'button');
badge.setAttribute('tabindex', '0');

// Score and emoji (safe insertion)
const score = data.score || 0;
const emoji = getTrustEmoji(data.trust_level);

const emojiSpan = document.createElement('span');
emojiSpan.className = 'soc-badge-emoji';
emojiSpan.textContent = emoji;

const scoreSpan = document.createElement('span');
scoreSpan.className = 'soc-badge-score';
scoreSpan.textContent = `${Math.round(score)}%`;

badge.appendChild(emojiSpan);
badge.appendChild(scoreSpan);

// Add click handler for detailed popup
badge.addEventListener('click', (e) => {
  e.preventDefault();
  e.stopPropagation();
  showDetailedPopup(data);
});

// Keyboard accessibility (Enter & Space)
badge.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    showDetailedPopup(data);
  }
});

// Add hover tooltip (safe)
badge.title = getTrustMessage(data);

return badge;

}

// Get trust level emoji
function getTrustEmoji(trustLevel) {
const emojis = {
high: '✅',
medium: '⚠️',
low: '🔶',
very_low: '❌',
error: '❓'
};
return emojis[trustLevel] || '❓';
}

// Get trust message
function getTrustMessage(data) {
if (data.error) {
return `Unable to verify: ${data.error}`;
}

const messages = {
  high: 'High trust - Well-established and secure',
  medium: 'Medium trust - Generally reliable',
  low: 'Low trust - Exercise caution',
  very_low: 'Very low trust - Potential risk',
  error: 'Unable to verify site'
};

const msg = messages[data.trust_level] || 'Unknown trust level';
return `${msg} (Score: ${Math.round(data.score || 0)}/100)`;
// ...existing code...

}

// Helper: create labeled list item (<li><strong>Label:</strong> value</li>)
function createListItem(label, value) {
const li = document.createElement('li');

// ...existing code...
const strong = document.createElement('strong');
strong.textContent = `${label}: `; // includes colon and space

// value can be Node or text
if (value instanceof Node) {
  li.appendChild(strong);
  li.appendChild(value);
} else {
  li.appendChild(strong);
  const text = document.createTextNode(value);
  li.appendChild(text);
}

return li;

}

// Show detailed popup (fully built with DOM APIs)
function showDetailedPopup(data) {
// Remove any existing popup
const existingPopup = document.getElementById('soc-detailed-popup');
if (existingPopup) {
existingPopup.remove();
}


// Create popup container
const popup = document.createElement('div');
popup.id = 'soc-detailed-popup';
popup.className = 'soc-popup';
popup.setAttribute('role', 'dialog');
popup.setAttribute('aria-modal', 'true');

// Header
const header = document.createElement('div');
header.className = 'soc-popup-header';

const h3 = document.createElement('h3');
h3.textContent = 'Site Authenticity Report';

const closeBtn = document.createElement('button');
closeBtn.className = 'soc-popup-close';
closeBtn.setAttribute('aria-label', 'Close');
closeBtn.textContent = '×';

header.appendChild(h3);
header.appendChild(closeBtn);

// Content container
const content = document.createElement('div');
content.className = 'soc-popup-content';

// Domain row
const domainDiv = document.createElement('div');
domainDiv.className = 'soc-popup-domain';
domainDiv.textContent = data.domain || 'Unknown domain';

// Score block
const scoreBlock = document.createElement('div');
scoreBlock.className = 'soc-popup-score';

const scoreCircle = document.createElement('div');
const trustClass = `soc-score-${data.trust_level || 'unknown'}`;
scoreCircle.className = `soc-score-circle ${trustClass}`;

const scoreValue = document.createElement('span');
scoreValue.className = 'soc-score-value';
scoreValue.textContent = `${Math.round(data.score || 0)}`;

const scoreLabel = document.createElement('span');
scoreLabel.className = 'soc-score-label';
scoreLabel.textContent = 'Score';

scoreCircle.appendChild(scoreValue);
scoreCircle.appendChild(scoreLabel);

const trustLevelDiv = document.createElement('div');
trustLevelDiv.className = 'soc-trust-level';
const tlText = document.createElement('strong');
const tlStr = (data.trust_level || 'unknown').replace('_', ' ').toUpperCase();
tlText.textContent = tlStr;
trustLevelDiv.appendChild(document.createTextNode('Trust Level: '));
trustLevelDiv.appendChild(tlText);

scoreBlock.appendChild(scoreCircle);
scoreBlock.appendChild(trustLevelDiv);

// Details block
const details = document.createElement('div');
details.className = 'soc-popup-details';

const domainInfoHeader = document.createElement('h4');
domainInfoHeader.textContent = 'Domain Information';

const domainUl = document.createElement('ul');

const creationDate = data.domain_creation_date
  ? new Date(data.domain_creation_date).toLocaleDateString()
  : 'Unknown';

const domainAgeText = data.domain_age_years ? `${data.domain_age_years} years` : 'Unknown';
domainUl.appendChild(createListItem('Age', domainAgeText));
domainUl.appendChild(createListItem('Created', creationDate));
domainUl.appendChild(createListItem('Domain Score', `${Math.round(data.score_details?.domain_age_score || 0)}/100`));

// SSL block
const sslHeader = document.createElement('h4');
sslHeader.textContent = 'SSL Certificate';

const sslUl = document.createElement('ul');

sslUl.appendChild(createListItem('Expires', sslExpiry));
sslUl.appendChild(createListItem('Days Remaining', data.ssl_days_remaining || 'N/A'));
sslUl.appendChild(createListItem('SSL Score', `${Math.round(data.score_details?.ssl_score || 0)}/100`));

// Footer
const footer = document.createElement('div');
footer.className = 'soc-popup-footer';

const lastChecked = document.createElement('small');
lastChecked.textContent = `Last checked: ${new Date(data.checked_at || Date.now()).toLocaleString()}`;
footer.appendChild(lastChecked);

// Assemble content
details.appendChild(domainInfoHeader);
details.appendChild(domainUl);
details.appendChild(sslHeader);
details.appendChild(sslUl);

content.appendChild(domainDiv);
content.appendChild(scoreBlock);
content.appendChild(details);
content.appendChild(footer);

// Append header + content to popup
popup.appendChild(header);
popup.appendChild(content);

// Add to page
document.body.appendChild(popup);

// Display it (CSS will handle positioning)
popup.style.display = 'block';

// Close handlers
closeBtn.addEventListener('click', () => {
  popup.remove();
});

// Close on outside click (delay to avoid immediate close from event that opened it)
setTimeout(() => {
  function closePopup(e) {
    if (!popup.contains(e.target)) {
      popup.remove();
      document.removeEventListener('click', closePopup);
    }
  }
  document.addEventListener('click', closePopup);
}, 100);

// Optional: trap focus inside popup for accessibility (basic)
// Focus first interactive element
closeBtn.focus();


}

// Process search results
async function processSearchResults() {
const searchEngine = detectSearchEngine();
if (!searchEngine) {
// console.log('Search engine not supported');
return;
}


const selectors = searchEngineSelectors[searchEngine];
const results = document.querySelectorAll(selectors.results);

if (results.length === 0) {
  // console.log('No search results found');
  return;
}

// Collect all URLs to check
const urlsToCheck = [];
const resultElements = [];

results.forEach(result => {
  // Skip if already processed
  if (result.querySelector('.soc-spinner, .soc-badge')) {
    return;
  }

  const linkElement = result.querySelector(selectors.link);
  if (!linkElement || !linkElement.href) {
    return;
  }

  const url = linkElement.href;

  // Skip non-http(s) URLs
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return;
  }

  // Skip search engine's own URLs
  if (url.includes('google.com') || url.includes('bing.com') ||
      url.includes('yahoo.com') || url.includes('duckduckgo.com')) {
    return;
  }

  urlsToCheck.push(url);
  resultElements.push(result);

  // Add spinner
  const titleContainer = result.querySelector(selectors.titleContainer);
  if (titleContainer) {
    const spinner = createSpinner();
    titleContainer.insertAdjacentElement(selectors.insertPosition, spinner);
  }
});

if (urlsToCheck.length === 0) {
  return;
}

// Batch check URLs via background script
try {
  const response = await chrome.runtime.sendMessage({
    action: 'batchCheck',
    urls: urlsToCheck
  });

  if (response && response.success && response.data) {
    // Process results
    response.data.forEach((data, index) => {
      const result = resultElements[index];
      const titleContainer = result.querySelector(selectors.titleContainer);

      if (titleContainer) {
        // Remove spinner
        const spinner = titleContainer.querySelector('.soc-spinner');
        if (spinner) {
          spinner.remove();
        }

        // Add badge
        const badge = createBadge(data);
        titleContainer.insertAdjacentElement(selectors.insertPosition, badge);
      }
    });
  } else {
    // Remove spinners if response unsuccessful
    resultElements.forEach(result => {
      const spinner = result.querySelector('.soc-spinner');
      if (spinner) spinner.remove();
    });
  }
} catch (error) {
  console.error('Error checking sites:', error);

  // Remove all spinners on error
  resultElements.forEach(result => {
    const spinner = result.querySelector('.soc-spinner');
    if (spinner) {
      spinner.remove();
    }
  });
}
```

}

// Initialize when DOM is ready
function initialize() {
// Process initial results
processSearchResults();

```
// Watch for dynamic content changes (for infinite scroll)
const observer = new MutationObserver(debounce(() => {
  processSearchResults();
}, 500));

observer.observe(document.body, {
  childList: true,
  subtree: true
});


}

// Check if extension is enabled

chrome.runtime.sendMessage({ action: 'getSettings' }, (response) => {
  if (response && response.success && response.data && response.data.enabled) {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initialize);
    } else {
      initialize();
    }
  }
});

})();
