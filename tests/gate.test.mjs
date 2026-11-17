import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHandler, sign, verify } from '../lib/unlock-vc-gate.mjs';

const origin = 'https://racepoint.ai';
const env = { UNLOCK_VC_GATE_ENABLED:'true', UNLOCK_VC_GATE_SECRET:'test-only-secret-never-used-in-production', RESEND_API_KEY:'test-key', UNLOCK_VC_NOTIFICATION_TO:'owner@example.org', UNLOCK_VC_NOTIFICATION_FROM:'Studio <demo@example.org>', ASSETS:{fetch:async()=>new Response('public asset')} };
const pages = { demo:'DEMO CONTENT', partnership:'PARTNERSHIP CONTENT' };
function setup(status = 200) {
  const sent = [];
  const worker = createHandler(pages, async (url, init) => { sent.push({url,init}); return Response.json(status === 200 ? {id:'test-mail-id'} : {error:'failed'}, {status}); });
  return { worker, sent };
}
async function formFor(worker, page = 'demo') {
  const response = await worker.fetch(new Request(origin + (page === 'partnership' ? '/unlock-vc' : '/unlock-vc/')), env);
  const html = await response.text();
  return html.match(/name="form_token" value="([^"]+)"/)[1];
}
function post(token, extra = {}, headers = {}) {
  return new Request(origin + '/unlock-vc/access', {method:'POST', headers:{Origin:origin,'Content-Type':'application/x-www-form-urlencoded',...headers}, body:new URLSearchParams({form_token:token,email:'visitor@example.org',website:'',...extra})});
}
test('all demo aliases require entry and private file paths are unavailable', async()=>{
  const {worker,sent} = setup();
  for (const path of ['/unlock-vc','/unlock-vc/','/unlock-vc/index.html','/unlock-vc','/unlock-vc.html','/unlock-vc/']) {
    const res = await worker.fetch(new Request(origin+path),env);
    const html = await res.text();
    assert.equal(res.status,200); assert.match(html,/Enter your email/); assert.doesNotMatch(html,/DEMO CONTENT|PARTNERSHIP CONTENT/); assert.match(res.headers.get('Cache-Control'),/no-store/);
  }
  assert.equal((await worker.fetch(new Request(origin+'/private/unlock-vc.html'),env)).status,404);
  assert.equal(sent.length,0);
});
test('submission sends only to owner and grants a 12-hour Unlock VC visit receipt', async()=>{
  const {worker,sent}=setup();
  const token=await formFor(worker);
  const res=await worker.fetch(post(token,{to:'attacker@example.org',email:' Visitor@Example.org '}),env);
  assert.equal(res.status,303); assert.equal(res.headers.get('Location'),'/unlock-vc');
  const cookie=res.headers.get('Set-Cookie'); assert.match(cookie,/HttpOnly; Secure; SameSite=Lax/); assert.doesNotMatch(cookie,/visitor@/);
  const payload=JSON.parse(sent[0].init.body); assert.deepEqual(payload.to,['owner@example.org']); assert.match(payload.text,/visitor@example.org/); assert.match(payload.text,/not been verified/);
  assert.equal(sent[0].url,'https://api.resend.com/emails');
  for(const path of ['/unlock-vc/','/unlock-vc.html']) {
    const res=await worker.fetch(new Request(origin+path,{headers:{Cookie:cookie.split(';')[0]}}),env);
    assert.match(await res.text(),/CONTENT/);
  }
  const repeat=await worker.fetch(post(token,{}, {Cookie:cookie.split(';')[0]}),env);
  assert.equal(repeat.status,303); assert.equal(sent.length,1);
});
test('cross-origin requests and malformed email never send',async()=>{
  const {worker,sent}=setup(); const token=await formFor(worker);
  assert.equal((await worker.fetch(post(token,{}, {Origin:'https://untrusted.example'}),env)).status,403);
  for(const email of ['no-at','a@b\r\nBcc:x@y.com','<script>@example.org']) assert.equal((await worker.fetch(post(token,{email}),env)).status,400);
  assert.equal(sent.length,0);
});
test('forged and expired receipts cannot unlock the content',async()=>{
  const {worker}=setup();
  const expired=await sign({purpose:'access',exp:1},env.UNLOCK_VC_GATE_SECRET);
  for(const token of [expired,expired.slice(0,-4)+'abcd','access=true']) {
    const res=await worker.fetch(new Request(origin+'/unlock-vc/',{headers:{Cookie:'unlock_vc_visit='+token}}),env);
    assert.match(await res.text(),/Enter your email/);
  }
  assert.equal(await verify(expired,env.UNLOCK_VC_GATE_SECRET,'access'),null);
});
test('invalid form signatures, traps, and oversized requests are rejected',async()=>{
  const {worker,sent}=setup(); const token=await formFor(worker);
  assert.equal((await worker.fetch(post(token+'x'),env)).status,400);
  assert.equal((await worker.fetch(post(token,{website:'bot'}),env)).status,400);
  assert.equal((await worker.fetch(post(token,{email:'a'.repeat(5000)}),env)).status,413);
  assert.equal(sent.length,0);
});
test('provider failures do not grant access or expose keys',async()=>{
  const {worker}=setup(503); const token=await formFor(worker);
  const res=await worker.fetch(post(token),env);
  assert.equal(res.status,503); assert.equal(res.headers.get('Set-Cookie'),null);
  const html = await res.text();
  assert.doesNotMatch(html,/test-key|test-only-secret/);
  assert.equal(html.match(/name="form_token" value="([^"]+)"/)[1],token);
});
test('replaying one form uses the same provider idempotency key and payload',async()=>{
  const {worker,sent}=setup(); const token=await formFor(worker);
  await worker.fetch(post(token),env); await worker.fetch(post(token),env);
  assert.equal(sent[0].init.headers['Idempotency-Key'],sent[1].init.headers['Idempotency-Key']);
  assert.equal(sent[0].init.body,sent[1].init.body);
});
test('throttles repeated attempts without sending more alerts',async()=>{
  const {worker,sent}=setup(); const token=await formFor(worker);
  for(let i=0;i<12;i++) assert.equal((await worker.fetch(post(token,{}, {'x-vercel-forwarded-for':'192.0.2.1'}),env)).status,303);
  assert.equal((await worker.fetch(post(token,{}, {'x-vercel-forwarded-for':'192.0.2.1'}),env)).status,429);
  assert.equal(sent.length,12);
});
test('missing email configuration cannot grant access',async()=>{
  const {worker,sent}=setup();
  const result=await worker.fetch(new Request(origin+'/unlock-vc'),{...env,RESEND_API_KEY:''});
  assert.equal(result.status,503); assert.doesNotMatch(await result.text(),/DEMO CONTENT/);assert.equal(sent.length,0);
});
test('HEAD is empty and API alias is gated',async()=>{
  const {worker}=setup();
  assert.match(await (await worker.fetch(new Request(origin+'/api/unlock-vc'),env)).text(),/Enter your email/);
  const result=await worker.fetch(new Request(origin+'/unlock-vc',{method:'HEAD'}),env);
  assert.equal(await result.text(),'');
});
