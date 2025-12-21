// functions/_middleware.js
// Pages middleware: export async function onRequest(context)
// NOTE: Add two secrets/vars in Pages project settings: PASSWORD (secret) and SIGNING_KEY (secret)

const COOKIE_NAME = 'r_x_auth';
const COOKIE_MAX_AGE = 60 * 60 * 8; // 8 hours
const COOKIE_VERSION = 'v1';

// simple constant-time equality
function safeEquals(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function hmacSignRaw(keyRaw, message) {
  const enc = new TextEncoder();
  const keyData = enc.encode(keyRaw);
  const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message));
  const u8 = new Uint8Array(sig);
  let b64 = btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return b64;
}

async function hmacVerifyRaw(keyRaw, message, sig) {
  const expected = await hmacSignRaw(keyRaw, message);
  return safeEquals(expected, sig);
}

function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  return Object.fromEntries(header.split(';').map(s => s.trim()).filter(Boolean).map(p => {
    const i = p.indexOf('=');
    return i >= 0 ? [p.slice(0,i), p.slice(i+1)] : [p, ''];
  }));
}

function makeSetCookieHeader(value) {
  // HttpOnly, Secure, SameSite=Strict
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Strict;`;
}

function parseAuthCookie(raw) {
  if (!raw) return null;
  try {
    const v = decodeURIComponent(raw);
    const parts = v.split('|');
    if (parts.length !== 4) return null;
    return { ver: parts[0], ts: Number(parts[1]), uid: parts[2], sig: parts[3] };
  } catch (e) {
    return null;
  }
}

function loginFormHtml(message = '') {
  return `<!doctype html>
  <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Protected</title></head>
  <body style="font-family:system-ui, -apple-system, Roboto, Arial;">
    <h3>This site is password protected</h3>
    ${message ? `<div style="color:red">${escapeHtml(message)}</div>` : ''}
    <form method="POST" action="/__auth">
      <label>Shared password</label><br/>
      <input name="password" type="password" required style="padding:8px; width:320px"/><br/><br/>
      <button type="submit">Unlock</button>
    </form>
  </body></html>`;
}

function escapeHtml(s=''){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // Health check passthrough (optional)
  if (url.pathname === '/__health') return new Response('ok');

  // Check existing cookie
  const cookies = parseCookies(request);
  const cookieRaw = cookies[COOKIE_NAME];
  if (cookieRaw) {
    const parsed = parseAuthCookie(cookieRaw);
    if (parsed && parsed.ver === COOKIE_VERSION) {
      const message = `${parsed.ver}|${parsed.ts}|${parsed.uid}`;
      try {
        const ok = await hmacVerifyRaw(env.SIGNING_KEY, message, parsed.sig);
        if (ok) {
          // validate timestamp (within cookie max age)
          const now = Math.floor(Date.now()/1000);
          if ((now - parsed.ts) <= COOKIE_MAX_AGE + 60) {
            // Allow original request to continue to static assets
            return await next();
          }
        }
      } catch (e) {
        // verification error -> fallthrough to login
      }
    }
  }

  // Handle login POST
  if (request.method === 'POST' && url.pathname === '/__auth') {
    const form = await request.formData();
    const provided = String(form.get('password') || '');
    // Compare with secret PASSWORD from Pages project secrets
    const valid = safeEquals(provided, String(env.PASSWORD || ''));
    if (valid) {
      // Create cookie: version|ts|uid|sig
      const ts = Math.floor(Date.now()/1000);
      const uid = Math.random().toString(36).slice(2,10);
      const message = `${COOKIE_VERSION}|${ts}|${uid}`;
      const sig = await hmacSignRaw(env.SIGNING_KEY, message);
      const cookieVal = encodeURIComponent(`${message}|${sig}`);
      const headers = new Headers();
      headers.set('Set-Cookie', makeSetCookieHeader(cookieVal));
      headers.set('Location', '/');
      return new Response(null, { status: 302, headers });
    } else {
      return new Response(loginFormHtml('Invalid password. Try again.'), { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
  }

  // Show login form for everything else
  return new Response(loginFormHtml(), { headers: { 'Content-Type': 'text/html; charset=utf-8' }, status: 200 });
}
