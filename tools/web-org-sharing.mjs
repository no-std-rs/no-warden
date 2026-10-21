#!/usr/bin/env node
// Independently authored MIT OR Apache-2.0 actual-browser organization smoke.
// Paired receipts are emitted only after both real runs complete successfully.
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {readFile,writeFile,mkdtemp,rm,mkdir,copyFile} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join,resolve} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import http from 'node:http';
import https from 'node:https';

const quiet=['DEBUG','DEBUG_FILE','PWDEBUG','NODE_DEBUG','NODE_DEBUG_NATIVE'];
if(quiet.some(k=>process.env[k])) {
  const env={...process.env};for(const k of quiet)delete env[k];
  const child=spawnSync(process.execPath,[process.argv[1]],{env,stdio:'inherit'});process.exit(child.status??1);
}
async function main() {
const root=resolve(process.env.BW_WEB_OUTPUT??await mkdtemp('/tmp/no-warden-web-org-sharing-proof-'));
const source=resolve(process.env.BW_WEB_SOURCE_ROOT??fileURLToPath(new URL('../',import.meta.url)));
const pins=JSON.parse(await readFile(join(source,'tools/web-compat/pins.json'),'utf8'));
const mode=process.env.BW_WEB_ORG_MODE??'reference';assert(['reference','paired'].includes(mode));
const routes=new Set([
  '/api/config','/identity/accounts/prelogin/password','/api/devices/knowndevice',
  '/identity/connect/token','/api/sync','/api/accounts/profile','/api/accounts/revision-date',
  '/api/auth-requests/pending','/api/ciphers','/api/ciphers/{id}',
  '/api/ciphers/share','/api/ciphers/{id}/share','/api/ciphers/organization-details',
  '/api/organizations','/api/organizations/{id}','/api/organizations/{id}/collections',
  '/api/organizations/{id}/collections/details','/api/organizations/{id}/groups',
  '/api/organizations/{id}/users/mini-details','/api/collections',
]);
const normalize=p=>p.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ig,'{id}');
const api=p=>/^\/(api|identity|notifications|events|icons)(\/|$)/.test(p);
// Separate reference discovery metadata; background polling counts are observations,
// not protocol assertions or minimums. Semantic operation checks below are strict.
const DISCOVERY_HTTP_COUNTS={
  "fresh GET /api/accounts/profile 200": 2,
  "fresh GET /api/accounts/revision-date 200": 2,
  "fresh GET /api/auth-requests/pending 200": 1,
  "fresh GET /api/config 200": 2,
  "fresh GET /api/devices/knowndevice 200": 1,
  "fresh GET /api/sync 200": 1,
  "fresh POST /identity/accounts/prelogin/password 200": 1,
  "fresh POST /identity/connect/token 200": 1,
  "initial GET /api/accounts/profile 200": 3,
  "initial GET /api/accounts/revision-date 200": 4,
  "initial GET /api/auth-requests/pending 200": 2,
  "initial GET /api/ciphers/organization-details 200": 2,
  "initial GET /api/config 200": 2,
  "initial GET /api/devices/knowndevice 200": 1,
  "initial GET /api/organizations/{id}/collections/details 200": 3,
  "initial GET /api/organizations/{id}/groups 200": 1,
  "initial GET /api/organizations/{id}/users/mini-details 200": 1,
  "initial GET /api/sync 200": 4,
  "initial POST /api/ciphers 200": 1,
  "initial POST /api/organizations 200": 1,
  "initial POST /api/organizations/{id}/collections 200": 1,
  "initial POST /identity/accounts/prelogin/password 200": 1,
  "initial POST /identity/connect/token 200": 4,
  "initial PUT /api/ciphers/share 200": 1
};
const results=[],proxies=[];let stage='configuration',directory,browser;
function endpoint(name,fallback,protocol) {
  const u=new URL(process.env[name]??fallback);assert.equal(u.protocol,protocol);
  assert.equal(u.hostname,'127.0.0.1');assert.equal(u.pathname,'/');assert.equal(u.username+u.password+u.search+u.hash,'');return u;
}
const reference=endpoint('BW_WEB_REFERENCE_BASE','http://127.0.0.1:18181','http:');
const target=endpoint('BW_WEB_TARGET_BASE','http://127.0.0.1:18182','http:');
const referenceOrigin=endpoint('BW_WEB_REFERENCE_ORIGIN','https://127.0.0.1:18184','https:');
const targetOrigin=endpoint('BW_WEB_TARGET_ORIGIN','https://127.0.0.1:18185','https:');
assert.notEqual(referenceOrigin.port,targetOrigin.port);assert.notEqual(reference.origin,target.origin);
async function hash(path) {const h=createHash('sha256');for await(const c of createReadStream(path))h.update(c);return h.digest('hex');}
async function checkpoint() {await writeFile(join(root,'progress.json'),JSON.stringify({stage,results:results.map(r=>({label:r.label,status:r.status})),actualBrowserRunAttempted:true})+'\n',{mode:0o600});console.log(JSON.stringify({stage}));}
async function proxy(origin,backend,tls) {
  const server=https.createServer(tls,(request,response)=>{
    const destination=api(new URL(request.url,origin).pathname)?backend:reference;
    const upstream=http.request({hostname:destination.hostname,port:destination.port,path:request.url,method:request.method,headers:{...request.headers,host:origin.host}},incoming=>{response.writeHead(incoming.statusCode,incoming.headers);incoming.pipe(response);});
    upstream.on('error',()=>{response.writeHead(502);response.end();});request.pipe(upstream);
  });
  server.on('upgrade',(_r,socket)=>socket.destroy());
  await new Promise((yes,no)=>{server.once('error',no);server.listen(Number(origin.port),'127.0.0.1',yes);});proxies.push(server);
}
function reply(page,method,path) {return page.waitForResponse(r=>r.request().method()===method&&normalize(new URL(r.url()).pathname)===path&&r.status()===200,{timeout:30000});}
async function run(label,backend,origin) {
  const email=`web-org-${randomBytes(12).toString('hex')}@example.test`,password=randomBytes(32).toString('base64');
  const values={org:`Organization ${randomBytes(8).toString('hex')}`,collection:`Collection ${randomBytes(8).toString('hex')}`,name:`Note ${randomBytes(8).toString('hex')}`,body:randomBytes(32).toString('base64')};
  const events=new Map(),setup=new Map(),checkpoints=[];let unknown=0,badStatus=0,contextsCreated=0,context;
  const result={label,status:'running',uiCheckpoints:checkpoints};
  results.push(result);
  stage=`${label}: ordinary native account registration`;await checkpoint();
  const {seedAccount}=await import(pathToFileURL(join(source,'tools/seed-account.mjs')).href);
  const originalFetch=globalThis.fetch;
  globalThis.fetch=async(...args)=>{
    const response=await originalFetch(...args);const u=new URL(typeof args[0]==='string'?args[0]:args[0].url);
    if(u.origin===backend.origin){assert(['/api/accounts/register','/identity/accounts/register/send-verification-email','/identity/accounts/register/finish'].includes(u.pathname));const key=(args[1]?.method??'GET')+' '+u.pathname+' '+response.status;setup.set(key,(setup.get(key)??0)+1);}
    return response;
  };
  try {await seedAccount(backend.origin,email,password);} finally {globalThis.fetch=originalFetch;}
  async function freshContext(phase) {
    context=await browser.newContext({ignoreHTTPSErrors:true,locale:'en-US'});contextsCreated++;
    context.on('response',response=>{
      const u=new URL(response.url());if(u.origin!==origin.origin||!api(u.pathname))return;
      const path=normalize(u.pathname);if(!routes.has(path)){unknown++;return;}
      const key=`${phase} ${response.request().method()} ${path} ${response.status()}`;
      events.set(key,(events.get(key)??0)+1);if(response.status()!==200)badStatus++;
    });
    await context.route('**/*',route=>{const u=new URL(route.request().url());return u.origin===origin.origin||['data:','blob:'].includes(u.protocol)?route.continue():route.abort();});
    const page=await context.newPage();page.setDefaultTimeout(20000);return page;
  }
  async function login(page,phase) {
    stage=`${label}: ${phase} ordinary browser login and sync`;await checkpoint();
    await page.goto(origin.origin);await page.getByTestId('login-email-input').fill(email);await page.getByRole('button',{name:'Continue',exact:true}).click();await page.locator('input[type=password]:visible').fill(password);
    await Promise.all([reply(page,'POST','/identity/connect/token'),reply(page,'GET','/api/sync'),reply(page,'GET','/api/accounts/profile'),page.getByRole('button',{name:'Log in',exact:true}).click()]);
    await page.waitForURL(u=>['#/vault','#/setup-extension'].includes(u.hash));
    if(new URL(page.url()).hash==='#/setup-extension') {
      await page.getByRole('button',{name:'Add it later',exact:true}).click();await page.getByRole('dialog').getByRole('link',{name:'Skip to web app',exact:true}).click();await page.waitForURL(u=>u.hash==='#/vault');await page.getByRole('dialog').getByRole('button',{name:'Skip',exact:true}).click();
    }
    for(const operation of ['POST /identity/connect/token 200','GET /api/sync 200','GET /api/accounts/profile 200'])assert((events.get(`${phase} ${operation}`)??0)>0);
    checkpoints.push(`${phase}-ordinary-login-sync`);
  }
  async function assertNote(page,phase) {
    const button=page.getByRole('button',{name:values.name,exact:true});await button.waitFor({state:'visible'});assert.equal(await button.count(),1);await button.click();
    // Actual decrypted DOM equality only; never serialize the body or a DOM dump.
    assert((await page.getByRole('dialog').getByText(values.body,{exact:true}).count())>0);
    checkpoints.push(`${phase}-decrypted-note-equality`);
  }
  try {
    let page=await freshContext('initial');await login(page,'initial');
    stage=`${label}: create personal secure note through UI`;await checkpoint();
    await page.locator('#newItemDropdown').click();await page.getByRole('menuitem',{name:'Note',exact:true}).click();
    const dialog=page.getByRole('dialog');await dialog.locator('input[formcontrolname=name]').fill(values.name);await dialog.locator('textarea[formcontrolname=notes]').fill(values.body);
    await Promise.all([reply(page,'POST','/api/ciphers'),dialog.getByRole('button',{name:'Save',exact:true}).click()]);await dialog.getByRole('button',{name:'Close',exact:true}).click();await dialog.waitFor({state:'hidden'});checkpoints.push('personal-note-created-before-organization');
    stage=`${label}: create organization and collection through UI`;await checkpoint();
    await page.getByRole('link',{name:'New organization',exact:true}).click();await page.locator('[formcontrolname=name]:visible').fill(values.org);await page.locator('input[type=email]:visible').fill(email);
    await Promise.all([reply(page,'POST','/api/organizations'),page.getByRole('button',{name:'Submit',exact:true}).click()]);
    await page.getByRole('button',{name:'New',exact:true}).click();await page.getByRole('menuitem',{name:'Collection',exact:true}).click();await page.locator('[formcontrolname=name]:visible').fill(values.collection);
    await Promise.all([reply(page,'POST','/api/organizations/{id}/collections'),page.getByRole('button',{name:'Save',exact:true}).click()]);checkpoints.push('organization-and-collection-created-by-ui');
    stage=`${label}: assign personal note to organization collection through UI`;await checkpoint();
    await page.getByRole('link',{name:'Password Manager',exact:true}).click();stage=`${label}: wait personal note row after navigation`;await checkpoint();const row=page.getByRole('row').filter({hasText:values.name});await row.waitFor({state:'visible'});assert.equal(await row.count(),1);await row.getByRole('button',{name:'Options',exact:true}).click();await page.getByRole('menuitem',{name:'Assign to collections',exact:true}).click();
    stage=`${label}: select owned collection`;await checkpoint();const picker=page.getByRole('dialog');await picker.getByRole('combobox').nth(1).waitFor({state:'visible'});assert.equal(await picker.getByRole('combobox').count(),2);await picker.getByRole('combobox').nth(1).fill(values.collection);await page.getByRole('option').filter({hasText:values.collection}).click();await page.keyboard.press('Escape');
    stage=`${label}: submit native bulk assignment`;await checkpoint();const assign=picker.locator('button').filter({hasText:'Assign'});assert.equal(await assign.count(),1);assert(await assign.isEnabled());await Promise.all([reply(page,'PUT','/api/ciphers/share'),assign.click()]);await picker.waitFor({state:'hidden'});checkpoints.push('actual-ui-bulk-share-200');
    await assertNote(page,'immediate');await context.close();context=undefined;
    // A new context has no inherited cookies, local/IndexedDB vault cache or
    // storageState. Credentials enter only the ordinary login controls again.
    page=await freshContext('fresh');await login(page,'fresh');stage=`${label}: decrypt moved note from fresh context server sync`;await checkpoint();await assertNote(page,'fresh-context');assert.equal(contextsCreated,2);await context.close();context=undefined;
    const sum=operation=>['initial','fresh'].reduce((n,phase)=>n+(events.get(`${phase} ${operation}`)??0),0);
    for(const operation of ['POST /api/ciphers 200','POST /api/organizations 200','POST /api/organizations/{id}/collections 200','PUT /api/ciphers/share 200'])assert.equal(sum(operation),1);
    assert.equal(sum('PUT /api/ciphers/{id}/share 200'),0);assert.equal(events.get('fresh PUT /api/ciphers/share 200')??0,0);
    for(const path of ['/api/ciphers/organization-details','/api/organizations/{id}/collections/details','/api/organizations/{id}/groups','/api/organizations/{id}/users/mini-details'])assert(sum(`GET ${path} 200`)>0);
    assert.equal(unknown,0);assert.equal(badStatus,0);
    for(const phase of ['initial','fresh']) {
      for(const op of ['GET /api/config 200','POST /identity/accounts/prelogin/password 200','GET /api/devices/knowndevice 200','POST /identity/connect/token 200','GET /api/sync 200','GET /api/accounts/profile 200']) assert((events.get(`${phase} ${op}`)??0)>=1);
    }
    // No extra write can hide behind successful required calls. Password/token
    // exchanges stay separately attributable; polling GET counts may vary.
    const writes=new Set(['POST /api/ciphers','POST /api/organizations','POST /api/organizations/{id}/collections','PUT /api/ciphers/share']);
    for(const [operation,count]of events) {
      const [phase,method,path]=operation.split(' ');
      if(method==='GET'||path.startsWith('/identity/'))continue;
      assert.equal(phase,'initial');assert(writes.has(`${method} ${path}`));assert.equal(count,1);
    }
    Object.assign(result,{status:'passed',strictUiMutationAndLoginPhaseContractAsserted:true,backgroundPollingCountsAreObservations:true,freshContextsCreated:contextsCreated,freshContextHasNoInheritedStorage:true,actualUiBulkMutationCaller:true,exactOneBulkShareResponse:true,singleShareBrowserCallerClaimed:false,immediateAndFreshDecryptedEquality:true,unattributedSuppressedResponses:unknown,browserNon200Responses:badStatus,browserHttpResponses:[...events.values()].reduce((a,b)=>a+b,0),http:[...events].sort().map(([operation,count])=>({operation,count})),nativeRegistrationSetupHttp:[...setup].sort().map(([operation,count])=>({operation,count}))});
  } finally {if(context)await context.close();}
}
try {
  await mkdir(root,{recursive:true,mode:0o700});
  stage='pinned public client artifact verification';await checkpoint();
  const version=await fetch(new URL('/vw-version.json',reference),{signal:AbortSignal.timeout(15000)});assert.equal(version.status,200);assert.equal((await version.json()).version,pins.client.version);
  for(const [path,sha]of Object.entries(pins.client.scripts)){const r=await fetch(new URL(path,reference),{signal:AbortSignal.timeout(15000)});assert.equal(r.status,200);assert.equal(createHash('sha256').update(Buffer.from(await r.arrayBuffer())).digest('hex'),sha);}
  const executable=process.env.BW_WEB_CHROMIUM;assert(executable,'Set BW_WEB_CHROMIUM to the pinned executable');assert.equal(await hash(executable),pins.chromium.executableSha256);
  const modulePath=process.env.BW_WEB_PLAYWRIGHT_MODULE??join(source,'tools/web-compat/node_modules/playwright-core/index.mjs');const pkg=JSON.parse(await readFile(new URL('./package.json',pathToFileURL(modulePath)),'utf8'));assert.equal(pkg.version,pins.playwrightVersion);
  directory=await mkdtemp('/tmp/no-warden-web-org-bulk-private-');
  if(!process.env.FONTCONFIG_FILE) {
    await mkdir(join(directory,'fonts'));await copyFile(process.env.BW_WEB_FONT??'/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',join(directory,'fonts/DejaVuSans.ttf'));await mkdir(join(directory,'fontcache'));await writeFile(join(directory,'fonts.conf'),`<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd"><fontconfig><dir>${directory}/fonts</dir><cachedir>${directory}/fontcache</cachedir></fontconfig>`);process.env.FONTCONFIG_FILE=join(directory,'fonts.conf');
  }
  assert.equal(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem'),'-subj','/CN=localhost','-days','1'],{stdio:'ignore'}).status,0);
  const tls={key:await readFile(join(directory,'key.pem')),cert:await readFile(join(directory,'cert.pem'))};await proxy(referenceOrigin,reference,tls);if(mode==='paired')await proxy(targetOrigin,target,tls);
  const {chromium}=await import(pathToFileURL(modulePath).href);browser=await chromium.launch({executablePath:executable,headless:true});assert.equal(browser.version(),pins.chromium.version);
  const readiness=await browser.newPage();await readiness.goto('data:text/html,<p>input readiness</p><input>');await readiness.locator('input').fill('test-input');assert.equal(await readiness.locator('input').inputValue(),'test-input');assert.match(await readiness.locator('body').innerText(),/input readiness/);await readiness.close();
  await run('vaultwarden',reference,referenceOrigin);if(mode==='paired')await run('no-warden',target,targetOrigin);
  const receipt={schemaVersion:1,status:'passed',mode,pins,actualBrowserExecuted:true,actualBrowserPairedCompatibilityClaimed:mode==='paired',sourceRoot:source,referenceDiscoveryObservedHttpCounts:DISCOVERY_HTTP_COUNTS,results,rawBodiesOrCredentialsPersisted:false,browserStorageBypass:false,playwrightHarTraceScreenshotOrConsoleCapture:false,groupAdministrationClaimed:false,attachmentsClaimed:false,recipientClaimed:false,websocketCompatibilityClaimed:false,fullParity:false};
  await writeFile(join(root,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});console.log(JSON.stringify({status:'passed',mode,phases:results.length}));
} catch {
  await writeFile(join(root,'failure.json'),JSON.stringify({status:'failed',stage,results:results.filter(r=>r.status==='passed'),actualBrowserPairedCompatibilityClaimed:false,fullParity:false})+'\n',{mode:0o600});console.error(JSON.stringify({status:'failed',stage}));process.exitCode=1;
} finally {
  if(browser)await browser.close().catch(()=>{});
  await Promise.all(proxies.map(s=>new Promise(resolve=>{s.closeAllConnections();s.close(resolve);})));if(directory)await rm(directory,{recursive:true,force:true});
}

}
await main().catch(()=>{
  // Configuration rejection occurs before account creation and must remain quiet.
  console.error(JSON.stringify({status:'failed',stage:'configuration'}));
  process.exitCode=1;
});
