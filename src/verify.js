/**
 * Opt-in live verification — calls only each provider's own API with the detected credential.
 * Disabled by default; never sends secrets to third-party scanners.
 */

const TIMEOUT_MS = 8000;

async function fetchStatus(url, init) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: ac.signal });
    return res.status;
  } catch {
    return 0;
  } finally {
    clearTimeout(t);
  }
}

/** @returns {'live'|'dead'|'unknown'} */
export async function verifySecret(ruleId, secret) {
  switch (ruleId) {
    case 'github-token':
      return verifyGithub(secret);
    case 'stripe-secret-key':
    case 'stripe-test-secret-key':
      return verifyStripe(secret);
    case 'openai-api-key':
      return verifyOpenAi(secret);
    case 'anthropic-api-key':
      return verifyAnthropic(secret);
    case 'npm-token':
      return verifyNpm(secret);
    default:
      return 'unknown';
  }
}

async function verifyGithub(token) {
  const status = await fetchStatus('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'bundle-secret-guard-verify' },
  });
  if (status === 200) return 'live';
  if (status === 401 || status === 403) return 'dead';
  return 'unknown';
}

async function verifyStripe(key) {
  const status = await fetchStatus('https://api.stripe.com/v1/balance', {
    headers: { Authorization: `Bearer ${key}`, 'User-Agent': 'bundle-secret-guard-verify' },
  });
  if (status === 200) return 'live';
  if (status === 401) return 'dead';
  return 'unknown';
}

async function verifyOpenAi(key) {
  const status = await fetchStatus('https://api.openai.com/v1/models', {
    headers: { Authorization: `Bearer ${key}`, 'User-Agent': 'bundle-secret-guard-verify' },
  });
  if (status === 200) return 'live';
  if (status === 401) return 'dead';
  return 'unknown';
}

async function verifyAnthropic(key) {
  const status = await fetchStatus('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
      'User-Agent': 'bundle-secret-guard-verify',
    },
    body: JSON.stringify({ model: 'claude-3-5-haiku-20241022', max_tokens: 1, messages: [{ role: 'user', content: 'x' }] }),
  });
  if (status === 200) return 'live';
  if (status === 401 || status === 403) return 'dead';
  return 'unknown';
}

async function verifyNpm(token) {
  const status = await fetchStatus('https://registry.npmjs.org/-/whoami', {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'bundle-secret-guard-verify' },
  });
  if (status === 200) return 'live';
  if (status === 401) return 'dead';
  return 'unknown';
}

/** Verify unique findings; mutates finding objects with `verified` field. */
export async function verifyFindings(items, { concurrency = 3 } = {}) {
  const queue = [...items];
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length) {
      const { finding, secret } = queue.shift();
      finding.verified = await verifySecret(finding.id, secret);
    }
  });
  await Promise.all(workers);
}
