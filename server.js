const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(cors({
  origin: ['https://senior-project-phishing-detector-production.up.railway.app', 'http://localhost:3000']
}));
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));

const VT_API_KEY = process.env.VT_API_KEY;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const VT_BASE = 'https://www.virustotal.com/api/v3';
const ANTHROPIC_BASE = 'https://api.anthropic.com/v1/messages';

const BRAND_KEYWORDS = [
  'google', 'amazon', 'facebook', 'paypal', 'apple', 'microsoft', 'netflix',
  'instagram', 'dropbox', 'linkedin', 'twitter', 'xfinity', 'chase', 'wellsfargo',
  'bankofamerica', 'steam', 'ebay', 'spotify', 'adobe', 'coinbase', 'binance',
  'docusign', 'onedrive', 'office365'
];

const FREE_EMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
  'protonmail.com', 'proton.me', 'aol.com', 'live.com', 'msn.com'
];

const TRUSTED_DOMAINS = [
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
  'apple.com', 'google.com', 'microsoft.com', 'amazon.com', 'github.com',
  'proton.me', 'protonmail.com', 'linkedin.com', 'docusign.net'
];

const LOCAL_KEYWORDS = [
  'billing', 'invoice', 'payment', 'refund', 'verify', 'security', 'alert',
  'noreply', 'no-reply', 'support', 'helpdesk', 'admin', 'service', 'update',
  'confirm', 'account', 'team', 'notification', 'payroll', 'hr', 'it'
];

const DOMAIN_KEYWORDS = [
  'secure', 'verify', 'login', 'update', 'account', 'bank', 'paypal', 'confirm',
  'support', 'service', 'helpdesk', 'billing', 'password', 'recover', 'wallet',
  'signin', 'auth', 'unlock'
];

function vtUrlId(url) {
  return Buffer.from(url).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function getRootDomain(domain) {
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;

  const multiPartSuffixes = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'co.jp'];
  const lastTwo = parts.slice(-2).join('.');
  const lastThree = parts.slice(-3).join('.');
  if (multiPartSuffixes.includes(lastTwo) && parts.length >= 3) return lastThree;
  if (multiPartSuffixes.includes(parts.slice(-2).join('.')) && parts.length >= 3) return lastThree;
  return lastTwo;
}

function parseEmailInput(input) {
  const t = input.trim().toLowerCase().replace(/^\.+|\.+$/g, '');
  const emailMatch = t.match(/^([^@\s]+)@([a-z0-9.-]+\.[a-z]{2,})$/);
  if (emailMatch) {
    return {
      domain: emailMatch[2],
      original: t,
      isEmail: true,
      localPart: emailMatch[1]
    };
  }

  const domainMatch = t.match(/^([a-z0-9.-]+\.[a-z]{2,})$/);
  if (domainMatch) {
    return {
      domain: domainMatch[1],
      original: t,
      isEmail: false,
      localPart: ''
    };
  }

  return null;
}

function majorityVote(stats) {
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  const flagged = stats.malicious + stats.suspicious;
  const clean = stats.harmless + stats.undetected;
  const responding = total - (stats.timeout || 0);
  const majority = Math.floor(responding / 2) + 1;
  const vote =
    stats.malicious >= majority ? 'DANGEROUS' :
    flagged >= majority ? 'SUSPICIOUS' :
    stats.malicious > 0 ? 'SUSPICIOUS' :
    stats.suspicious > 0 ? 'SUSPICIOUS' :
    'SAFE';

  return {
    vote,
    flagged,
    clean,
    total: responding,
    ratio: responding > 0 ? Math.round((flagged / responding) * 100) : 0,
    stats
  };
}

function verdictFromScore(score) {
  if (score >= 75) return 'DANGEROUS';
  if (score >= 45) return 'SUSPICIOUS';
  if (score >= 15) return 'CAUTION';
  return 'SAFE';
}

function scoreImpact(status) {
  if (status === 'fail') return 'high';
  if (status === 'warn') return 'medium';
  return 'low';
}

function addCheck(checks, name, icon, status, detail, why) {
  const entry = { name, icon, status, detail };
  if (why) entry.why = why;
  entry.impact = scoreImpact(status);
  checks.push(entry);
}

function maybeAddTag(tags, text, type) {
  if (!tags.some(tag => tag.text === text)) tags.push({ text, type });
}

function runHeuristics(domain, localPart) {
  const checks = [];
  const tags = [];
  let score = 0;

  const d = domain.toLowerCase();
  const local = (localPart || '').toLowerCase();
  const parts = d.split('.');
  const rootDomain = getRootDomain(d);
  const tld = '.' + parts[parts.length - 1];
  const subdomain = d === rootDomain ? '' : d.slice(0, -(rootDomain.length + 1));
  const subdomainDepth = Math.max(0, parts.length - rootDomain.split('.').length);
  const brandHits = BRAND_KEYWORDS.filter(brand => d.includes(brand));
  const localBrandHits = BRAND_KEYWORDS.filter(brand => local.includes(brand));
  const localKeywordHits = LOCAL_KEYWORDS.filter(keyword => local.includes(keyword));
  const domainKeywordHits = DOMAIN_KEYWORDS.filter(keyword => d.includes(keyword));
  const riskyTlds = ['.xyz', '.tk', '.ml', '.cf', '.ga', '.top', '.click', '.download', '.gq', '.pw', '.icu', '.buzz', '.shop', '.live'];

  if (local) {
    if (localBrandHits.length && FREE_EMAIL_DOMAINS.includes(d)) {
      addCheck(
        checks,
        'Local Part Brand Spoof',
        '🎭',
        'fail',
        '"' + local + '" impersonates ' + localBrandHits.join(', ') + ' but sends from free provider ' + d,
        'Brand names in a personal mailbox are a common email-spoofing pattern.'
      );
      score += 8;
      maybeAddTag(tags, 'Local Part Spoofing', 'danger');
    } else if (localBrandHits.length) {
      addCheck(
        checks,
        'Local Part Brand Spoof',
        '🎭',
        'warn',
        'Sender name contains brand "' + localBrandHits[0] + '"',
        'A brand in the local part can be legitimate, but it deserves verification.'
      );
      score += 3;
      maybeAddTag(tags, 'Brand in Sender Name', 'warn');
    } else {
      addCheck(checks, 'Local Part Brand Spoof', '🎭', 'pass', 'No brand names detected in the sender address');
    }

    if (localKeywordHits.length >= 2) {
      addCheck(
        checks,
        'Suspicious Sender Name',
        '🎣',
        'fail',
        'High-risk keywords in sender name: "' + localKeywordHits.slice(0, 3).join('", "') + '"',
        'Operational words like billing or security are frequently used to pressure the recipient.'
      );
      score += 4;
      maybeAddTag(tags, 'Suspicious Sender Name', 'danger');
    } else if (localKeywordHits.length === 1) {
      addCheck(
        checks,
        'Suspicious Sender Name',
        '🎣',
        'warn',
        'Keyword in sender name: "' + localKeywordHits[0] + '"',
        'A single sensitive keyword is not proof, but it raises the risk.'
      );
      score += 2;
    } else {
      addCheck(checks, 'Suspicious Sender Name', '🎣', 'pass', 'No suspicious keywords in sender name');
    }

    if (FREE_EMAIL_DOMAINS.includes(d) && (localBrandHits.length || localKeywordHits.length)) {
      addCheck(
        checks,
        'Free Provider Mismatch',
        '📮',
        'fail',
        'Claims of business urgency are being sent from ' + d,
        'Real business alerts almost never come from consumer mailbox providers.'
      );
      score += 5;
      maybeAddTag(tags, 'Free Email Impersonation', 'danger');
    } else if (FREE_EMAIL_DOMAINS.includes(d)) {
      addCheck(checks, 'Free Provider Mismatch', '📮', 'info', 'Sent from free provider (' + d + ')');
    } else {
      addCheck(checks, 'Free Provider Mismatch', '📮', 'pass', 'Uses a custom domain');
    }

    const separatorCount = (local.match(/[._-]/g) || []).length;
    if (local.length >= 24 || separatorCount >= 3) {
      addCheck(
        checks,
        'Local Part Structure',
        '🧩',
        separatorCount >= 4 ? 'fail' : 'warn',
        'Sender name is unusually long or segmented (' + local.length + ' chars, ' + separatorCount + ' separators)',
        'Random-looking sender names are common in bulk phishing campaigns.'
      );
      score += separatorCount >= 4 ? 3 : 2;
      maybeAddTag(tags, 'Automated Sender Pattern', 'warn');
    } else {
      addCheck(checks, 'Local Part Structure', '🧩', 'pass', 'Sender name structure looks normal');
    }
  }

  if (d.length > 40) {
    addCheck(checks, 'Domain Length', '📏', 'fail', d.length + ' chars — unusually long', 'Long chained domains often try to bury the real root domain.');
    score += 3;
    maybeAddTag(tags, 'Long Domain', 'warn');
  } else if (d.length > 28) {
    addCheck(checks, 'Domain Length', '📏', 'warn', d.length + ' chars — longer than typical');
    score += 1;
  } else {
    addCheck(checks, 'Domain Length', '📏', 'pass', d.length + ' chars — normal');
  }

  if (subdomainDepth >= 3) {
    addCheck(checks, 'Subdomain Depth', '🌿', 'fail', subdomainDepth + ' levels deep', 'Attackers often hide a malicious root behind many trusted-looking prefixes.');
    score += 4;
    maybeAddTag(tags, 'Deep Subdomains', 'danger');
  } else if (subdomainDepth >= 2) {
    addCheck(checks, 'Subdomain Depth', '🌿', 'warn', subdomainDepth + ' levels — worth checking');
    score += 2;
  } else {
    addCheck(checks, 'Subdomain Depth', '🌿', 'pass', subdomainDepth + ' subdomain level(s)');
  }

  if (domainKeywordHits.length >= 2) {
    addCheck(
      checks,
      'Phishing Keywords',
      '🎣',
      'fail',
      'Found in domain: ' + domainKeywordHits.slice(0, 4).join(', '),
      'Stacking account or security words in a domain is a common phishing tactic.'
    );
    score += 4;
    maybeAddTag(tags, 'Phishing Keywords', 'danger');
  } else if (domainKeywordHits.length === 1) {
    addCheck(checks, 'Phishing Keywords', '🎣', 'warn', 'Found in domain: ' + domainKeywordHits[0]);
    score += 2;
  } else {
    addCheck(checks, 'Phishing Keywords', '🎣', 'pass', 'No phishing keywords in domain');
  }

  const spoofedBrands = BRAND_KEYWORDS.filter(brand => d.includes(brand) && !rootDomain.startsWith(brand + '.') && rootDomain !== brand + '.com');
  if (spoofedBrands.length) {
    addCheck(
      checks,
      'Domain Brand Spoof',
      '🏴',
      'fail',
      'Domain references ' + spoofedBrands.join(', ') + ' but resolves to root ' + rootDomain,
      'A brand mention outside the brand’s own root domain is a strong impersonation signal.'
    );
    score += 6;
    maybeAddTag(tags, 'Brand Spoofing', 'danger');
  } else {
    addCheck(checks, 'Domain Brand Spoof', '🏴', 'pass', 'No brand impersonation in domain');
  }

  if (subdomain && brandHits.length && !rootDomain.includes(brandHits[0])) {
    addCheck(
      checks,
      'Subdomain Camouflage',
      '🕵️',
      'fail',
      'Brand-like text appears in subdomain "' + subdomain + '" while root domain is "' + rootDomain + '"',
      'This is a classic way to make a malicious host look legitimate at a glance.'
    );
    score += 5;
    maybeAddTag(tags, 'Subdomain Camouflage', 'danger');
  } else {
    addCheck(checks, 'Subdomain Camouflage', '🕵️', 'pass', 'No misleading subdomain camouflage found');
  }

  if (riskyTlds.includes(tld)) {
    addCheck(checks, 'TLD Reputation', '🏳️', 'fail', '"' + tld + '" is frequently abused for phishing');
    score += 3;
    maybeAddTag(tags, 'Risky TLD', 'warn');
  } else {
    addCheck(checks, 'TLD Reputation', '🏳️', 'pass', '"' + tld + '" is a common TLD');
  }

  const typos = [/0(?=[a-z])|(?<=[a-z])0/g, /1(?=l|i)|(?<=l|i)1/g, /rn(?=\b)/g, /vv/g];
  if (d.includes('xn--')) {
    addCheck(
      checks,
      'Punycode Domain',
      '🌍',
      'fail',
      'Internationalized punycode detected (' + rootDomain + ')',
      'Punycode can be legitimate, but it is also used for lookalike-domain attacks.'
    );
    score += 5;
    maybeAddTag(tags, 'Punycode Lookalike Risk', 'danger');
  } else {
    addCheck(checks, 'Punycode Domain', '🌍', 'pass', 'No punycode encoding detected');
  }

  if (typos.some(pattern => pattern.test(d))) {
    addCheck(
      checks,
      'Typosquatting',
      '🔤',
      'fail',
      'Character substitution detected (for example 0 for o or vv for w)',
      'Lookalike characters are used to trick the eye while bypassing simple checks.'
    );
    score += 4;
    maybeAddTag(tags, 'Typosquatting', 'danger');
  } else {
    addCheck(checks, 'Typosquatting', '🔤', 'pass', 'No substitution patterns found');
  }

  const nums = (d.match(/\d/g) || []).length;
  if (nums >= 4) {
    addCheck(checks, 'Numeric Characters', '🔢', 'warn', nums + ' digits in domain');
    score += 2;
  } else {
    addCheck(checks, 'Numeric Characters', '🔢', 'pass', nums + ' digit(s) in domain');
  }

  const hyphens = (d.match(/-/g) || []).length;
  if (hyphens >= 3) {
    addCheck(
      checks,
      'Hyphen Count',
      '➖',
      'fail',
      hyphens + ' hyphens — common in fake domains',
      'Attackers often chain descriptive words with hyphens to mimic a workflow or brand.'
    );
    score += 3;
    maybeAddTag(tags, 'Hyphen Abuse', 'warn');
  } else if (hyphens === 2) {
    addCheck(checks, 'Hyphen Count', '➖', 'warn', '2 hyphens detected');
    score += 1;
  } else {
    addCheck(checks, 'Hyphen Count', '➖', 'pass', hyphens + ' hyphen(s) — normal');
  }

  const isTrusted = TRUSTED_DOMAINS.includes(d) || TRUSTED_DOMAINS.includes(rootDomain);
  const localRedFlags = Boolean(local && (localBrandHits.length || localKeywordHits.length));
  if (isTrusted && !localRedFlags) {
    score = Math.max(0, score - 12);
    addCheck(checks, 'Sender Reputation', '⭐', 'pass', rootDomain + ' is in the trusted sender list');
    maybeAddTag(tags, 'Trusted Domain', 'info');
  } else if (isTrusted) {
    addCheck(
      checks,
      'Sender Reputation',
      '⭐',
      'warn',
      rootDomain + ' is trusted, but the sender pattern still looks unusual',
      'A trusted root domain can still be abused when the local part is crafted to mislead users.'
    );
    score += 2;
  } else {
    addCheck(checks, 'Sender Reputation', '⭐', 'info', 'Not in the trusted sender list');
  }

  if (brandHits.length && domainKeywordHits.length) {
    addCheck(
      checks,
      'Brand + Action Combo',
      '⚠️',
      'fail',
      'Brand terms are mixed with action words in the domain',
      'This combination strongly suggests an impersonation landing page.'
    );
    score += 4;
    maybeAddTag(tags, 'Brand + Action Pattern', 'danger');
  } else {
    addCheck(checks, 'Brand + Action Combo', '⚠️', 'pass', 'No risky brand-plus-action pattern found');
  }

  const cautionNotes = [];
  if (!isTrusted) {
    cautionNotes.push({
      name: 'Unverified Sender',
      icon: '❓',
      status: 'info',
      detail: 'This sender has no trusted-domain reputation in the local ruleset.',
      impact: 'low'
    });
  }
  if (local && !localBrandHits.length && !localKeywordHits.length) {
    cautionNotes.push({
      name: 'Sender Name',
      icon: '👤',
      status: 'info',
      detail: 'Sender name "' + local + '" appears generic or personal.',
      impact: 'low'
    });
  }
  checks.push(...cautionNotes);

  const failCount = checks.filter(check => check.status === 'fail').length;
  const warnCount = checks.filter(check => check.status === 'warn').length;
  const infoCount = checks.filter(check => check.status === 'info').length;

  return {
    score,
    maxScore: local ? 52 : 40,
    checks,
    tags,
    domain,
    rootDomain,
    subdomain,
    tld,
    failCount,
    warnCount,
    infoCount
  };
}

function analyzeEmailBody(body, senderEmail, replyTo, senderDomain) {
  const flags = [];
  const text = body.toLowerCase();
  let bodyScore = 0;

  const urgencyPhrases = [
    'act now', 'act immediately', 'urgent', 'immediately', 'expires', 'expiring',
    'last chance', 'limited time', 'within 24 hours', 'within 48 hours',
    'account will be suspended', 'account suspended', 'access will be revoked',
    'respond immediately', 'failure to respond', 'legal action', 'final notice',
    'has been compromised', 'unauthorized access'
  ];
  const urgencyFound = urgencyPhrases.filter(phrase => text.includes(phrase));
  if (urgencyFound.length >= 2) {
    addCheck(flags, 'Urgency Language', '⏰', 'fail', 'Detected: "' + urgencyFound.slice(0, 3).join('", "') + '"', 'Phishing emails manufacture urgency so users click before thinking.');
    bodyScore += 22;
  } else if (urgencyFound.length === 1) {
    addCheck(flags, 'Urgency Language', '⏰', 'warn', 'Detected: "' + urgencyFound[0] + '"', 'Urgent wording can be a pressure tactic.');
    bodyScore += 10;
  } else {
    addCheck(flags, 'Urgency Language', '⏰', 'pass', 'No urgency phrases detected');
  }

  const credentialPhrases = [
    'enter your password', 'confirm your password', 'verify your password',
    'enter your credit card', 'credit card info', 'credit card information',
    'credit card details', 'card details', 'payment details', 'your social security',
    'provide your account number', 'confirm your details', 'update your billing',
    'verify your identity', 'enter your pin', 'banking details', 'confirm your login',
    'wallet recovery phrase', 'seed phrase', 'gift card', 'wire transfer',
    'debit card', 'cvv', 'security code'
  ];
  const credentialPatterns = [
    /credit\s*card\s*(info|information|details|number)?/i,
    /(type|enter|send|provide|submit|reply with|share)\s+(your\s+)?(password|pin|cvv|security code|card details|credit card|debit card|bank account)/i,
    /(verify|confirm|update)\s+(your\s+)?(identity|billing|payment|account details|card details)/i,
    /(social security|ssn|seed phrase|recovery phrase|gift card)/i
  ];
  const credentialFound = credentialPhrases.filter(phrase => text.includes(phrase));
  const credentialPatternHits = credentialPatterns.filter(pattern => pattern.test(body));
  if (credentialFound.length >= 2 || credentialPatternHits.length >= 2) {
    addCheck(flags, 'Credential Request', '🔑', 'fail', 'Requests sensitive information from the recipient', 'Legitimate companies do not request passwords, PINs, card data, or payment secrets by email.');
    bodyScore += 42;
  } else if (credentialFound.length === 1 || credentialPatternHits.length === 1) {
    addCheck(flags, 'Credential Request', '🔑', 'fail', 'Requests account, identity, or payment details', 'Any direct request for credentials or card information is a major red flag.');
    bodyScore += 34;
  } else {
    addCheck(flags, 'Credential Request', '🔑', 'pass', 'No credential requests detected');
  }

  const actionPhrases = [
    'click here', 'click below', 'open the link', 'use the link below',
    'review the document', 'view the shared document', 'open the secure message',
    'log in to review', 'sign in to review', 'download the attachment'
  ];
  const actionFound = actionPhrases.filter(phrase => text.includes(phrase));
  if (actionFound.length >= 2) {
    addCheck(flags, 'Action Prompt', '🖱️', 'fail', 'Pushes the recipient to open a link, document, or portal immediately', 'Phishing messages often center on getting you to click before you verify the sender.');
    bodyScore += 18;
  } else if (actionFound.length === 1) {
    addCheck(flags, 'Action Prompt', '🖱️', 'warn', 'Contains a direct click or review prompt');
    bodyScore += 7;
  } else {
    addCheck(flags, 'Action Prompt', '🖱️', 'pass', 'No aggressive click or portal prompt detected');
  }

  const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
  const links = body.match(urlPattern) || [];
  const suspiciousLinkPatterns = [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy/i,
    /\.xyz|\.tk|\.ml|\.top|\.click|\.icu|\.shop/i,
    /login|verify|secure|update|account|confirm|wallet|auth/i
  ];
  const suspiciousLinks = links.filter(link => suspiciousLinkPatterns.some(pattern => pattern.test(link)));
  if (suspiciousLinks.length) {
    addCheck(flags, 'Suspicious Links', '🔗', 'fail', suspiciousLinks.length + ' suspicious link(s): ' + suspiciousLinks[0].substring(0, 64) + '...', 'Links with IPs, shorteners, or credential-focused paths are common in phishing.');
    bodyScore += 24;
  } else if (links.length >= 3) {
    addCheck(flags, 'Suspicious Links', '🔗', 'warn', links.length + ' links found in body', 'High link density can increase the likelihood of a phishing lure.');
    bodyScore += 8;
  } else if (links.length) {
    addCheck(flags, 'Suspicious Links', '🔗', 'pass', links.length + ' link(s) found, none flagged');
  } else {
    addCheck(flags, 'Suspicious Links', '🔗', 'pass', 'No links found in body');
  }

  const attachmentWords = ['attached invoice', 'attached document', 'review the attachment', 'open the attachment', '.html attachment', '.zip attachment', 'shared document'];
  const attachmentFound = attachmentWords.filter(phrase => text.includes(phrase));
  if (attachmentFound.length) {
    addCheck(flags, 'Attachment Bait', '📎', 'warn', 'Attachment lure detected: "' + attachmentFound[0] + '"', 'Many phishing emails attempt to move the user into an attachment-based workflow.');
    bodyScore += 10;
  } else {
    addCheck(flags, 'Attachment Bait', '📎', 'pass', 'No obvious attachment lure detected');
  }

  const hrPhrases = [
    'hr department', 'human resources', 'payroll', 'benefits', 'employee handbook',
    'policy update', 'tax form', 'w-2', 'direct deposit', 'performance review',
    'onboarding', 'termination notice', 'salary adjustment'
  ];
  const hrFound = hrPhrases.filter(phrase => text.includes(phrase));
  if (hrFound.length >= 2 && (links.length > 0 || actionFound.length > 0)) {
    addCheck(flags, 'HR or Payroll Lure', '🧾', 'fail', 'Uses HR, payroll, or employee-admin language together with a prompt to click or review', 'Attackers often impersonate HR or payroll because employees are trained to respond quickly.');
    bodyScore += 22;
  } else if (hrFound.length >= 1 && (links.length > 0 || attachmentFound.length > 0)) {
    addCheck(flags, 'HR or Payroll Lure', '🧾', 'warn', 'Mentions HR or payroll topics alongside links or attachments');
    bodyScore += 10;
  } else {
    addCheck(flags, 'HR or Payroll Lure', '🧾', 'pass', 'No suspicious HR or payroll-style lure detected');
  }

  const impersonationPhrases = [
    'dear customer', 'dear user', 'dear account holder', 'dear valued customer',
    'dear member', 'your apple id', 'your google account', 'your microsoft account',
    'your paypal account', 'your amazon account', 'your bank account', 'it department',
    'help desk', 'security team', 'dear [name]', 'dear {name}', 'hello [first name]'
  ];
  const impersonationFound = impersonationPhrases.filter(phrase => text.includes(phrase));
  if (impersonationFound.length >= 2) {
    addCheck(flags, 'Impersonation Phrases', '🎭', 'fail', 'Found: "' + impersonationFound.slice(0, 3).join('", "') + '"', 'Generic greetings plus brand references are a classic mass-phishing pattern.');
    bodyScore += 18;
  } else if (impersonationFound.length === 1) {
    addCheck(flags, 'Impersonation Phrases', '🎭', 'warn', 'Found: "' + impersonationFound[0] + '"', 'Generic greetings can indicate bulk targeting.');
    bodyScore += 8;
  } else {
    addCheck(flags, 'Impersonation Phrases', '🎭', 'pass', 'No impersonation phrases found');
  }

  const grammarIndicators = [/\bplease to\b/i, /\bkindly do the needful\b/i, /[A-Z]{5,}/, /!{3,}/, /\${2,}/];
  const grammarFound = grammarIndicators.filter(pattern => pattern.test(body));
  if (grammarFound.length >= 2) {
    addCheck(flags, 'Grammar Anomalies', '✏️', 'fail', 'Multiple grammar or formatting anomalies detected', 'Poor grammar, odd capitalization, and excessive punctuation often appear in low-quality phishing templates.');
    bodyScore += 12;
  } else if (grammarFound.length === 1) {
    addCheck(flags, 'Grammar Anomalies', '✏️', 'warn', 'Minor grammar or formatting anomaly detected');
    bodyScore += 4;
  } else {
    addCheck(flags, 'Grammar Anomalies', '✏️', 'pass', 'No obvious grammar anomalies');
  }

  if (replyTo && senderEmail) {
    const senderRoot = getRootDomain(senderDomain || (senderEmail.split('@')[1] || ''));
    const replyToDomain = (replyTo.trim().toLowerCase().split('@')[1] || '').replace(/^\.+|\.+$/g, '');
    const replyRoot = replyToDomain ? getRootDomain(replyToDomain) : '';
    if (replyRoot && senderRoot && replyRoot !== senderRoot) {
      addCheck(flags, 'Reply-To Mismatch', '↩️', 'fail', 'Sender root: ' + senderRoot + ' vs reply-to root: ' + replyRoot, 'A mismatched reply-to can redirect the conversation to the attacker.');
      bodyScore += 26;
    } else {
      addCheck(flags, 'Reply-To Mismatch', '↩️', 'pass', 'Sender and reply-to domains align');
    }
  } else {
    addCheck(flags, 'Reply-To Mismatch', '↩️', 'info', 'No reply-to address provided to compare');
  }

  const brandMention = BRAND_KEYWORDS.find(brand => text.includes(brand));
  if (brandMention && senderDomain && !getRootDomain(senderDomain).includes(brandMention)) {
    addCheck(flags, 'Brand Claim Mismatch', '🏷️', 'warn', 'Email mentions "' + brandMention + '" but sender domain is "' + senderDomain + '"', 'A brand claim that does not match the sender domain is worth verifying.');
    bodyScore += 10;
  } else {
    addCheck(flags, 'Brand Claim Mismatch', '🏷️', 'pass', 'No obvious body-to-sender brand mismatch found');
  }

  const legitIndicators = [
    'please let me know if you have questions',
    'thanks,',
    'thank you,',
    'best regards',
    'regards,',
    'sincerely,',
    'see attached agenda',
    'meeting invite',
    'calendar invite',
    'no action needed'
  ];
  const legitFound = legitIndicators.filter(phrase => text.includes(phrase));
  if (legitFound.length >= 2 && !credentialPatternHits.length && !suspiciousLinks.length && urgencyFound.length === 0) {
    addCheck(flags, 'Legitimacy Signals', '✅', 'pass', 'Contains routine business language without matching phishing pressure patterns');
    bodyScore = Math.max(0, bodyScore - 10);
  } else if (legitFound.length === 1 && !credentialPatternHits.length && !suspiciousLinks.length) {
    addCheck(flags, 'Legitimacy Signals', '✅', 'info', 'Contains at least one routine business-language signal');
    bodyScore = Math.max(0, bodyScore - 4);
  } else {
    addCheck(flags, 'Legitimacy Signals', '✅', 'info', 'No strong legitimacy signals detected');
  }

  const failNames = flags.filter(flag => flag.status === 'fail').map(flag => flag.name);
  if (failNames.includes('HR or Payroll Lure') && failNames.includes('Suspicious Links')) {
    bodyScore += 12;
  }
  if (failNames.includes('Action Prompt') && failNames.includes('Credential Request')) {
    bodyScore += 10;
  }

  return {
    flags,
    bodyScore,
    links: links.length,
    suspiciousLinks,
    failCount: flags.filter(flag => flag.status === 'fail').length,
    warnCount: flags.filter(flag => flag.status === 'warn').length
  };
}

async function analyzeWithClaude(emailBody, senderEmail, domain, patternFlags) {
  if (!ANTHROPIC_KEY) return { success: false, reason: 'No Anthropic API key configured' };

  const flagSummary = patternFlags
    .filter(flag => flag.status === 'fail' || flag.status === 'warn')
    .map(flag => '- ' + flag.name + ': ' + flag.detail)
    .join('\n') || 'None detected';

  try {
    const response = await axios.post(ANTHROPIC_BASE, {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: 'You are a cybersecurity expert specializing in phishing email detection. Analyze email content and return ONLY a valid JSON object with no extra text, no markdown, no code fences.',
      messages: [{
        role: 'user',
        content: `Analyze this email for phishing indicators.\n\nSender: ${senderEmail || 'unknown'}\nDomain: ${domain}\nPattern flags:\n${flagSummary}\n\nEmail body:\n---\n${emailBody.substring(0, 3000)}\n---\n\nReturn ONLY this JSON:\n{\n  "verdict": "SAFE"|"CAUTION"|"SUSPICIOUS"|"DANGEROUS",\n  "confidence": "low"|"medium"|"high",\n  "summary": "2-3 sentence plain English summary",\n  "redFlags": ["red flag 1"],\n  "legitimacyIndicators": ["legit indicator 1"],\n  "recommendation": "One clear action sentence"\n}`
      }]
    }, {
      headers: {
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      timeout: 20000
    });

    const raw = response.data.content[0].text.trim();
    const parsed = JSON.parse(raw.replace(/```json|```/g, '').trim());
    return { success: true, ...parsed };
  } catch (err) {
    return { success: false, reason: err.message };
  }
}

function buildSummary(verdict, vtResult, domain, bodyAnalysis, heuristics) {
  const vtNote = vtResult
    ? `Scanned by ${vtResult.total} engines and ${vtResult.flagged} flagged the domain.`
    : 'No engine scan was available.';
  const heuristicNote = heuristics
    ? `Heuristics found ${heuristics.failCount} high-risk and ${heuristics.warnCount} medium-risk indicators.`
    : '';
  const bodyNote = bodyAnalysis
    ? ` Email content added ${bodyAnalysis.failCount} high-risk and ${bodyAnalysis.warnCount} medium-risk body signals.`
    : '';

  const verdictMessages = {
    SAFE: `${vtNote} ${heuristicNote} "${domain}" does not currently show major phishing markers, but unexpected email should still be verified independently.${bodyNote}`,
    CAUTION: `${vtNote} ${heuristicNote} "${domain}" has enough warning signs to justify a careful manual review before clicking anything.${bodyNote}`,
    SUSPICIOUS: `${vtNote} ${heuristicNote} "${domain}" shows multiple phishing-style signals. Avoid clicking links or sharing information until the sender is confirmed.${bodyNote}`,
    DANGEROUS: `${vtNote} ${heuristicNote} "${domain}" looks highly consistent with a phishing attempt. Do not interact with the message.${bodyNote}`
  };

  return verdictMessages[verdict] || verdictMessages.CAUTION;
}

function buildScoreModel(heuristics, bodyAnalysis, vtResult) {
  const heuristicNormalized = Math.round((heuristics.score / heuristics.maxScore) * 100);
  const heuristicContribution = Math.min(45, Math.round(heuristicNormalized * 0.45));
  const bodyContribution = bodyAnalysis ? Math.min(45, Math.round(bodyAnalysis.bodyScore * 0.55)) : 0;
  const vtContribution = vtResult ? Math.min(40, Math.round(vtResult.ratio * 0.4)) : 0;
  const totalScore = Math.min(100, heuristicContribution + bodyContribution + vtContribution);

  return {
    totalScore,
    contributions: {
      heuristics: heuristicContribution,
      body: bodyContribution,
      engines: vtContribution
    }
  };
}

app.post('/analyze', async (req, res) => {
  const { email, emailBody, replyTo } = req.body;
  if (!email) return res.status(400).json({ error: 'Email address is required' });

  const parsed = parseEmailInput(email);
  if (!parsed) {
    return res.status(400).json({ error: 'Invalid input. Please enter a valid email address or domain.' });
  }

  const { domain, original, isEmail, localPart } = parsed;
  const domainUrl = 'https://' + domain;

  const heuristics = runHeuristics(domain, localPart);
  heuristics.email = original;
  heuristics.domain = domain;
  heuristics.isEmail = isEmail;

  let bodyAnalysis = null;
  let aiAnalysis = null;
  if (emailBody && emailBody.trim().length > 10) {
    bodyAnalysis = analyzeEmailBody(emailBody.trim(), original, replyTo || '', domain);
    aiAnalysis = analyzeWithClaude(emailBody.trim(), original, domain, bodyAnalysis.flags);
  }

  if (!VT_API_KEY) {
    const ai = await (aiAnalysis || Promise.resolve(null));
    if (bodyAnalysis) bodyAnalysis.ai = ai;

    const scoreModel = buildScoreModel(heuristics, bodyAnalysis, null);
    let verdict = verdictFromScore(scoreModel.totalScore);
    const credentialRequestFlag = bodyAnalysis && bodyAnalysis.flags.some(flag => flag.name === 'Credential Request' && flag.status === 'fail');
    const suspiciousLinksFlag = bodyAnalysis && bodyAnalysis.flags.some(flag => flag.name === 'Suspicious Links' && flag.status === 'fail');
    if (credentialRequestFlag && verdict === 'SAFE') verdict = 'SUSPICIOUS';
    if (credentialRequestFlag && verdict === 'CAUTION') verdict = 'SUSPICIOUS';
    if (credentialRequestFlag && suspiciousLinksFlag) verdict = 'DANGEROUS';
    return res.json({
      email: original,
      domain,
      verdict,
      score: scoreModel.totalScore,
      source: 'heuristics_only',
      heuristics,
      bodyAnalysis,
      virustotal: null,
      engines: [],
      scoreModel: scoreModel.contributions,
      summary: buildSummary(verdict, null, domain, bodyAnalysis, heuristics)
    });
  }

  try {
    const urlId = vtUrlId(domainUrl);
    let vtData;

    try {
      const cached = await axios.get(`${VT_BASE}/urls/${urlId}`, { headers: { 'x-apikey': VT_API_KEY } });
      vtData = cached.data;
    } catch (e) {
      const submitted = await axios.post(
        `${VT_BASE}/urls`,
        new URLSearchParams({ url: domainUrl }),
        { headers: { 'x-apikey': VT_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      const analysisId = submitted.data.data.id;
      for (let i = 0; i < 5; i += 1) {
        await new Promise(resolve => setTimeout(resolve, 3000));
        const poll = await axios.get(`${VT_BASE}/analyses/${analysisId}`, { headers: { 'x-apikey': VT_API_KEY } });
        if (poll.data.data.attributes.status === 'completed') {
          const full = await axios.get(`${VT_BASE}/urls/${urlId}`, { headers: { 'x-apikey': VT_API_KEY } });
          vtData = full.data;
          break;
        }
      }
    }

    if (!vtData) throw new Error('Engine analysis timed out');

    const ai = await (aiAnalysis || Promise.resolve(null));
    if (bodyAnalysis) bodyAnalysis.ai = ai;

    const attrs = vtData.data.attributes;
    const stats = attrs.last_analysis_stats;
    const vtResult = majorityVote(stats);
    const scoreModel = buildScoreModel(heuristics, bodyAnalysis, vtResult);

    let finalVerdict = verdictFromScore(scoreModel.totalScore);
    const credentialRequestFlag = bodyAnalysis && bodyAnalysis.flags.some(flag => flag.name === 'Credential Request' && flag.status === 'fail');
    const suspiciousLinksFlag = bodyAnalysis && bodyAnalysis.flags.some(flag => flag.name === 'Suspicious Links' && flag.status === 'fail');
    const replyToMismatchFlag = bodyAnalysis && bodyAnalysis.flags.some(flag => flag.name === 'Reply-To Mismatch' && flag.status === 'fail');
    if (vtResult.vote === 'SUSPICIOUS' && finalVerdict === 'SAFE') finalVerdict = 'CAUTION';
    if (vtResult.vote === 'SUSPICIOUS' && finalVerdict === 'CAUTION') finalVerdict = 'SUSPICIOUS';
    if (vtResult.vote === 'DANGEROUS') finalVerdict = 'DANGEROUS';
    if (ai && ai.success && ai.verdict === 'DANGEROUS' && finalVerdict === 'CAUTION') finalVerdict = 'SUSPICIOUS';
    if (credentialRequestFlag && finalVerdict === 'SAFE') finalVerdict = 'SUSPICIOUS';
    if (credentialRequestFlag && finalVerdict === 'CAUTION') finalVerdict = 'SUSPICIOUS';
    if (credentialRequestFlag && replyToMismatchFlag && finalVerdict !== 'DANGEROUS') finalVerdict = 'SUSPICIOUS';
    if (credentialRequestFlag && suspiciousLinksFlag) finalVerdict = 'DANGEROUS';

    const engineResults = Object.entries(attrs.last_analysis_results || {})
      .map(([engine, detail]) => ({ engine, category: detail.category, result: detail.result }))
      .sort((a, b) =>
        ({ malicious: 0, suspicious: 1, harmless: 2, undetected: 3 }[a.category] ?? 4) -
        ({ malicious: 0, suspicious: 1, harmless: 2, undetected: 3 }[b.category] ?? 4)
      );

    return res.json({
      email: original,
      domain,
      verdict: finalVerdict,
      score: scoreModel.totalScore,
      source: 'virustotal',
      heuristics,
      bodyAnalysis,
      virustotal: {
        stats,
        vote: vtResult,
        reputation: attrs.reputation ?? null,
        categories: attrs.categories ?? {},
        lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null
      },
      engines: engineResults,
      scoreModel: scoreModel.contributions,
      summary: buildSummary(finalVerdict, vtResult, domain, bodyAnalysis, heuristics)
    });
  } catch (err) {
    console.error('Engine error:', err.response?.data || err.message);
    const ai = await (aiAnalysis || Promise.resolve(null));
    if (bodyAnalysis) bodyAnalysis.ai = ai;

    const scoreModel = buildScoreModel(heuristics, bodyAnalysis, null);
    const boostedScore = Math.min(100, scoreModel.totalScore + 8);
    let verdict = verdictFromScore(boostedScore);
    const credentialRequestFlag = bodyAnalysis && bodyAnalysis.flags.some(flag => flag.name === 'Credential Request' && flag.status === 'fail');
    const suspiciousLinksFlag = bodyAnalysis && bodyAnalysis.flags.some(flag => flag.name === 'Suspicious Links' && flag.status === 'fail');
    if (credentialRequestFlag && verdict === 'SAFE') verdict = 'SUSPICIOUS';
    if (credentialRequestFlag && verdict === 'CAUTION') verdict = 'SUSPICIOUS';
    if (credentialRequestFlag && suspiciousLinksFlag) verdict = 'DANGEROUS';

    return res.json({
      email: original,
      domain,
      verdict,
      score: boostedScore,
      source: 'heuristics_fallback',
      heuristics,
      bodyAnalysis,
      virustotal: null,
      engines: [],
      scoreModel: {
        heuristics: scoreModel.contributions.heuristics,
        body: scoreModel.contributions.body,
        engines: 0
      },
      summary: buildSummary(verdict, null, domain, bodyAnalysis, heuristics)
    });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', vtConfigured: !!VT_API_KEY, aiConfigured: !!ANTHROPIC_KEY }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Phish Me running on http://localhost:${PORT}`));
