// URL handling shared by the signer and the verifier: finding and removing the CAT parameter,
// normalizing as CTA-5007-B §4.6.10 requires, and splitting a URL into the components catu names.
//
// URLs are handled as strings on purpose. A general-purpose URL class rewrites what it parses,
// and "the URL as received" matters here.

const PARAMETER = 'CAT';

// RFC 3986 Appendix B, plus the authority split into host and port.
export function split(url) {
  const m = /^(?:([^:/?#]+):)?(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?/.exec(url);
  const authority = (m[2] ?? '').replace(/^.*@/, '');
  const hp = /^(\[[^\]]*\]|[^:]*)(?::(.*))?$/.exec(authority);
  return { scheme: m[1] ?? '', host: hp[1], port: hp[2] ?? '', path: m[3], query: m[4] };
}

// Splits the query on "&", takes each name as everything before the first "=", percent-decodes
// it once and compares it with "CAT". Returns the token values found and the query without them.
export function extractTokens(query) {
  if (query === undefined) return { tokens: [], query: undefined };
  const tokens = [];
  const rest = [];
  for (const field of query.split('&')) {
    const eq = field.indexOf('=');
    const name = eq === -1 ? field : field.slice(0, eq);
    if (decodeOnce(name) === PARAMETER) tokens.push(eq === -1 ? '' : field.slice(eq + 1));
    else rest.push(field);
  }
  return { tokens, query: rest.length ? rest.join('&') : undefined };
}

// Appends the token, leaving the URL alone if it already carries one.
export function attach(url, token) {
  const { query } = split(url);
  if (extractTokens(query).tokens.length) return url;
  return url + (query === undefined ? '?' : '&') + PARAMETER + '=' + token;
}

// RFC 9110 §4.2.3, then RFC 3986 §6.2.2 and §6.2.3.
export function normalize(parts) {
  const scheme = parts.scheme.toLowerCase();
  const defaultPort = { http: '80', https: '443' }[scheme];
  return {
    scheme,
    host: percentNormalize(parts.host).toLowerCase(),
    port: parts.port === defaultPort ? '' : parts.port,
    path: removeDotSegments(percentNormalize(parts.path)) || '/',
    query: parts.query === undefined ? undefined : percentNormalize(parts.query),
  };
}

// The values catu's component labels refer to.
export function components(parts) {
  const slash = parts.path.lastIndexOf('/');
  const filename = parts.path.slice(slash + 1);
  const dot = filename.lastIndexOf('.');
  return new Map([
    [0, parts.scheme],
    [1, parts.host],
    [2, parts.port],
    [3, parts.path],
    [4, parts.query ?? ''],
    [5, parts.path.slice(0, Math.max(slash, 0))],
    [6, filename],
    [7, dot === -1 ? filename : filename.slice(0, dot)],
    [8, dot === -1 ? '' : filename.slice(dot)],
  ]);
}

// scheme://host[:port], with the port only when it is not the scheme's default.
export function origin(url) {
  const n = normalize(split(url));
  return `${n.scheme}://${n.host}${n.port ? ':' + n.port : ''}`;
}

export function decodeOnce(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// Uppercase the hex digits of percent-escapes and decode the ones that stand for unreserved
// characters (letters, digits, "-", ".", "_", "~").
function percentNormalize(s) {
  return s.replace(/%([0-9a-fA-F]{2})/g, (escape, hex) => {
    const char = String.fromCharCode(parseInt(hex, 16));
    return /[A-Za-z0-9\-._~]/.test(char) ? char : escape.toUpperCase();
  });
}

// RFC 3986 §5.2.4.
function removeDotSegments(path) {
  const out = [];
  let input = path;
  while (input.length) {
    if (input.startsWith('../')) input = input.slice(3);
    else if (input.startsWith('./')) input = input.slice(2);
    else if (input.startsWith('/./')) input = input.slice(2);
    else if (input === '/.') input = '/';
    else if (input.startsWith('/../')) {
      input = input.slice(3);
      out.pop();
    } else if (input === '/..') {
      input = '/';
      out.pop();
    } else if (input === '.' || input === '..') input = '';
    else {
      const next = input.indexOf('/', 1);
      const end = next === -1 ? input.length : next;
      out.push(input.slice(0, end));
      input = input.slice(end);
    }
  }
  return out.join('');
}
