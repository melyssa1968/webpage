/* Unlock VC email entry is lead capture, not verified identity or an account system.
   The demo HTML is served only after email submission succeeds.
   Email addresses go only to the fixed notification recipient through Resend. */
const COOKIE = 'unlock_vc_visit';
const SESSION_SECONDS = 12 * 60 * 60;
const FORM_SECONDS = 30 * 60;
const PRIVATE = { 'Cache-Control': 'private, no-store', 'Vary': 'Cookie', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin' };
const encoder = new TextEncoder();
const now = () => Math.floor(Date.now() / 1000);
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);

function base64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function unbase64(text) { return Uint8Array.from(atob(text.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)); }
async function key(secret) { return crypto.subtle.importKey('raw', encoder.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign','verify']); }
export async function sign(value, secret) {
  const payload = base64(encoder.encode(JSON.stringify(value)));
  return payload + '.' + base64(await crypto.subtle.sign('HMAC', await key(secret), encoder.encode(payload)));
}
export async function verify(token, secret, purpose) {
  try {
    if (!token || token.length > 1500 || !secret) return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payload, signature] = parts;
    if (!await crypto.subtle.verify('HMAC', await key(secret), unbase64(signature), encoder.encode(payload))) return null;
    const value = JSON.parse(new TextDecoder().decode(unbase64(payload)));
    return value.purpose === purpose && Number.isFinite(value.exp) && value.exp > now() ? value : null;
  } catch { return null; }
}
function getCookie(request) {
  return (request.headers.get('Cookie') || '').split(';').map(v => v.trim()).find(v => v.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
}
export function pageFor(pathname) {
  return ['/unlock-vc','/unlock-vc/','/unlock-vc.html','/unlock-vc/index.html','/api/unlock-vc'].includes(pathname) ? 'demo' : null;
}
function destination() { return '/unlock-vc'; }
function response(body, status = 200, headers = {}) { return new Response(body, { status, headers: { ...PRIVATE, ...headers } }); }
function redirect(to, cookie) { return response(null, 303, { Location:to, ...(cookie ? {'Set-Cookie':cookie} : {}) }); }
function configured(env) { return Boolean(env.UNLOCK_VC_GATE_SECRET && env.RESEND_API_KEY && env.UNLOCK_VC_NOTIFICATION_TO && env.UNLOCK_VC_NOTIFICATION_FROM); }

function gateHTML(page, token, error = '', email = '') {
  
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Unlock VC × Bloom Engine</title><style>
  :root{font-family:"Avenir Next",Avenir,"Segoe UI",Arial,sans-serif;color:#171d3a;background:#fcf7fc;color-scheme:light}*{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;padding:clamp(24px,6vw,80px)}main{width:min(100%,580px)}.eyebrow{font-size:14px;letter-spacing:.07em;font-weight:650;color:#626277;margin:0 0 30px}h1{font-size:clamp(32px,4vw,44px);font-weight:600;letter-spacing:-.035em;line-height:1.15;margin:0 0 18px}.intro{font-size:20px;line-height:1.5;margin:0 0 32px}label{display:block;font-size:17px;font-weight:600;margin:0 0 10px}input[type=email]{width:100%;padding:17px 18px;border:1px solid #c6b6cb;border-radius:7px;font:inherit;font-size:18px;color:#171d3a;background:white}input:focus-visible,button:focus-visible{outline:3px solid #285aa4;outline-offset:4px}button{width:100%;margin-top:16px;padding:18px;border:0;border-radius:7px;background:#dd85d8;color:#171d3a;font:inherit;font-size:19px;font-weight:600;cursor:pointer}button:disabled{opacity:.65;cursor:wait}.notice{font-size:14px;line-height:1.55;color:#626277;margin:22px 0 0}.error{font-size:16px;color:#9c3120;line-height:1.5;margin:0 0 18px}.trap{position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden}@media(prefers-reduced-motion:no-preference){main{animation:enter .45s ease-out both}@keyframes enter{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}}</style></head><body><main>
  <p class="eyebrow">UNLOCK VC × BLOOM ENGINE</p><h1>Explore the Unlock VC community experience.</h1>
  <p class="intro">Enter your email to view the demo.</p>
  ${error ? `<p class="error" role="alert">${escape(error)}</p>` : ''}
  <form method="post" action="/unlock-vc/access"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" inputmode="email" maxlength="254" placeholder="you@organization.org" value="${escape(email)}" required>
  <input type="hidden" name="form_token" value="${escape(token)}"><div class="trap" aria-hidden="true"><label for="website">Leave this empty</label><input id="website" name="website" tabindex="-1" autocomplete="off"></div>
  <button type="submit">View demo</button></form><p class="notice">Your email will be shared with the Bloom team to let them know you’ve visited.</p>
  </main><script>document.querySelector('form').addEventListener('submit',function(){const b=this.querySelector('button');b.disabled=true;b.textContent='Opening…';});window.addEventListener('pageshow',function(){const b=document.querySelector('button');b.disabled=false;b.textContent="View demo";});</script></body></html>`;
}
async function gate(page, env, error = '', email = '', status = 200, retryToken = null) {
  const token = retryToken || await sign({ purpose:'form', page, iat:now(), exp:now()+FORM_SECONDS, nonce:crypto.randomUUID() }, env.UNLOCK_VC_GATE_SECRET);
  return response(gateHTML(page, token, error, email), status, { 'Content-Type':'text/html; charset=utf-8', 'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'" });
}
async function readBody(request) {
  if (Number(request.headers.get('Content-Length')) > 4096) throw Error('too_large');
  const reader = request.body?.getReader();
  if (!reader) return '';
  let length = 0, text = '', decoder = new TextDecoder();
  while (true) { const { value, done } = await reader.read(); if (done) break; length += value.byteLength; if (length > 4096) { await reader.cancel(); throw Error('too_large'); } text += decoder.decode(value, { stream:true }); }
  return text + decoder.decode();
}
// Best-effort per-instance throttling; only a short-lived HMAC is retained.
const attempts = new Map();
async function rateAllowed(request, env) {
  const ip = request.headers.get('x-vercel-forwarded-for') || request.headers.get('x-forwarded-for');
  if (!ip) return true;
  const hour = Math.floor(now()/3600);
  const hash = base64(await crypto.subtle.sign('HMAC', await key(env.UNLOCK_VC_GATE_SECRET), encoder.encode(ip.split(',')[0].trim() + ':' + hour)));
  for (const [id, record] of attempts) if (record.hour !== hour) attempts.delete(id);
  const record = attempts.get(hash) || {hour, count:0};
  if (record.count >= 12) return false;
  if (attempts.size >= 10000 && !attempts.has(hash)) return false;
  attempts.set(hash, {hour, count:record.count+1});
  return true;
}

export function createHandler(pages, emailFetch = (...args) => fetch(...args)) {
  return { async fetch(request, env) {
    const url = new URL(request.url);
    let pathname;
    try { pathname = decodeURIComponent(url.pathname); } catch { return response('Invalid address', 400); }
    const page = pageFor(pathname);
    if (pathname === '/unlock-vc/access' || (pathname === '/api/unlock-vc' && request.method === 'POST')) {
      
      if (request.method !== 'POST') return response('Method not allowed', 405, { Allow:'POST' });
      if (request.headers.get('Origin') !== url.origin || request.headers.get('Sec-Fetch-Site') === 'cross-site') return response('Please open the form on this site.', 403);
      if (!configured(env)) return response('Please try again shortly.', 503);
      if (!request.headers.get('Content-Type')?.startsWith('application/x-www-form-urlencoded')) return response('Invalid form', 415);
      let form;
      try { form = new URLSearchParams(await readBody(request)); } catch { return response('Form too large', 413); }
      const token = await verify(form.get('form_token'), env.UNLOCK_VC_GATE_SECRET, 'form');
      if (!token || token.page !== 'demo') return gate('demo', env, 'This form has expired. Please enter your email again.', '', 400);
      const email = (form.get('email') || '').trim().toLowerCase();
      if (form.get('website')) return gate(token.page, env, 'Please try again.', '', 400);
      if (email.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(email)) return gate(token.page, env, 'Enter a valid email address.', email, 400);
      if (await verify(getCookie(request), env.UNLOCK_VC_GATE_SECRET, 'access')) return redirect(destination(token.page));
      if (!await rateAllowed(request, env)) return gate(token.page, env, 'Please wait a little before trying again.', email, 429);
      const entered = new Date(token.iat * 1000).toLocaleString('en-US', { timeZone:'America/New_York', dateStyle:'medium', timeStyle:'short' });
      const label = 'Unlock VC demo';
      const message = {
        from:env.UNLOCK_VC_NOTIFICATION_FROM, to:[env.UNLOCK_VC_NOTIFICATION_TO],
        subject:'Unlock VC demo: a visitor entered their email',
        text:`A visitor entered the Unlock VC experience.\n\nEmail: ${email}\nPage: ${label}\nTime: ${entered} (New York)\nLink: https://racepoint.ai${destination(token.page)}\n\nThis address was supplied by the visitor. Email ownership has not been verified.`,
      };
      try {
        const sent = await emailFetch('https://api.resend.com/emails', {
          method:'POST', headers:{ Authorization:'Bearer '+env.RESEND_API_KEY, 'Content-Type':'application/json', 'Idempotency-Key':'unlock-vc-entry-'+token.nonce },
          body:JSON.stringify(message), signal:AbortSignal.timeout(12000),
        });
        const result = await sent.json();
        if (!sent.ok || !result.id) { console.error('Unlock VC alert rejected', sent.status); return gate(token.page, env, 'We couldn’t open the demo just now. Please try again.', email, 503, form.get('form_token')); }
      } catch { console.error('Unlock VC alert request failed'); return gate(token.page, env, 'We couldn’t open the demo just now. Please try again.', email, 503, form.get('form_token')); }
      const receipt = await sign({ purpose:'access', exp:now()+SESSION_SECONDS, nonce:crypto.randomUUID() }, env.UNLOCK_VC_GATE_SECRET);
      return redirect(destination(token.page), `${COOKIE}=${receipt}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`);
    }
    if (page) {
      if (!['GET','HEAD'].includes(request.method)) return response('Method not allowed', 405, {Allow:'GET, HEAD'});
      
      if (!configured(env)) return response('Please try again shortly.', 503);
      if (await verify(getCookie(request), env.UNLOCK_VC_GATE_SECRET, 'access')) return response(request.method === 'HEAD' ? null : pages[page], 200, {'Content-Type':'text/html; charset=utf-8'});
      const result = await gate(page, env);
      return request.method === 'HEAD' ? new Response(null, result) : result;
    }
    return response('Not found',404);
  } };
}
