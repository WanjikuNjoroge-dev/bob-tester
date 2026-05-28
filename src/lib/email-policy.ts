const DISPOSABLE_EMAIL_DOMAINS = new Set([
  "10minutemail.com",
  "20minutemail.com",
  "discard.email",
  "dispostable.com",
  "emailondeck.com",
  "fakeinbox.com",
  "getnada.com",
  "grr.la",
  "guerrillamail.biz",
  "guerrillamail.com",
  "guerrillamail.de",
  "guerrillamail.net",
  "guerrillamail.org",
  "maildrop.cc",
  "mailinator.com",
  "minuteinbox.com",
  "sharklasers.com",
  "temp-mail.io",
  "temp-mail.org",
  "tempmail.com",
  "tempmail.dev",
  "throwawaymail.com",
  "yopmail.com",
]);

const DISPOSABLE_DOMAIN_PATTERNS = [
  /10minute/i,
  /disposable/i,
  /fakeinbox/i,
  /guerrillamail/i,
  /mailinator/i,
  /minuteinbox/i,
  /temp-?mail/i,
  /throwaway/i,
  /yopmail/i,
];

function getEmailDomain(email: string) {
  const normalized = email.trim().toLowerCase();
  const atIndex = normalized.lastIndexOf("@");

  if (atIndex === -1 || atIndex === normalized.length - 1) {
    return "";
  }

  return normalized.slice(atIndex + 1);
}

export function isDisposableEmail(email: string) {
  const domain = getEmailDomain(email);
  if (!domain) {
    return false;
  }

  if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
    return true;
  }

  for (const blockedDomain of DISPOSABLE_EMAIL_DOMAINS) {
    if (domain.endsWith(`.${blockedDomain}`)) {
      return true;
    }
  }

  return DISPOSABLE_DOMAIN_PATTERNS.some((pattern) => pattern.test(domain));
}
