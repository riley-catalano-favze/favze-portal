/* ===================== SECURITY ===================== */
/* clickjacking protection */
(function(){
  if(window.top !== window.self){
    try{ window.top.location = window.self.location; }catch(e){ document.body.style.display='none'; }
  }
})();
/* safe URL validators */
function isSafeDataUrl(s){ return typeof s === 'string' && /^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);base64,/i.test(s); }
function isSafeHttpUrl(s){ return typeof s === 'string' && /^https?:\/\//i.test(s); }
/* client-side login rate limiter */
const PORTAL_AUTH_FAIL_KEY = 'favze_portal_auth_fails';
const PORTAL_AUTH_LOCK_KEY = 'favze_portal_auth_lock';
const PORTAL_AUTH_MAX_FAILS = 5;
const PORTAL_AUTH_LOCK_MS   = 5 * 60 * 1000;
function portalAuthRecordFail(email){
  let fails = {};
  try{ fails = JSON.parse(sessionStorage.getItem(PORTAL_AUTH_FAIL_KEY)||'{}'); }catch(e){}
  fails[email] = (fails[email]||0) + 1;
  try{ sessionStorage.setItem(PORTAL_AUTH_FAIL_KEY, JSON.stringify(fails)); }catch(e){}
  if(fails[email] >= PORTAL_AUTH_MAX_FAILS){
    try{ sessionStorage.setItem(PORTAL_AUTH_LOCK_KEY+'_'+email, String(Date.now()+PORTAL_AUTH_LOCK_MS)); }catch(e){}
  }
  return fails[email];
}
function portalAuthClearFails(email){
  try{
    const fails = JSON.parse(sessionStorage.getItem(PORTAL_AUTH_FAIL_KEY)||'{}');
    delete fails[email];
    sessionStorage.setItem(PORTAL_AUTH_FAIL_KEY, JSON.stringify(fails));
    sessionStorage.removeItem(PORTAL_AUTH_LOCK_KEY+'_'+email);
  }catch(e){}
}
function portalAuthIsLocked(email){
  try{
    const until = Number(sessionStorage.getItem(PORTAL_AUTH_LOCK_KEY+'_'+email)||'0');
    if(!until) return false;
    if(Date.now() < until) return Math.ceil((until-Date.now())/1000);
    sessionStorage.removeItem(PORTAL_AUTH_LOCK_KEY+'_'+email);
    return false;
  }catch(e){ return false; }
}
/* idle session timeout (30 minutes) */
const PORTAL_IDLE_MS = 30 * 60 * 1000;
let _portalIdleTimer = null;
function _resetPortalIdle(){
  clearTimeout(_portalIdleTimer);
  _portalIdleTimer = setTimeout(()=>{
    if(typeof portalSignOut==='function' && typeof CLIENT_ID!=='undefined' && CLIENT_ID){
      portalSignOut();
      const errEl = document.getElementById('login-error');
      if(errEl){ errEl.textContent='Signed out after 30 minutes of inactivity.'; errEl.style.display='block'; }
    }
  }, PORTAL_IDLE_MS);
}
['click','keydown','mousemove','touchstart','scroll'].forEach(evt=>{
  document.addEventListener(evt, _resetPortalIdle, { passive: true });
});

/* ===================== NAV ===================== */
const titles = {
  dashboard:['Dashboard','Here is where things stand today.'],
  calendar:['Content Calendar','Review, approve, and comment on upcoming content.'],
  projects:['Projects & Tasks','Full visibility into everything in motion.'],
  reports:['Reports & Analytics','Performance, straight from the source.'],
  team:['Your Team','Everyone working on your account.'],
  billing:['Billing & Invoicing','History, retainer details, and add-ons.'],
  services:['Request a Service','Something not on your plan yet? Start here.'],
  meetings:['Book a Meeting','Grab time on your account team\'s calendar.'],
  tickets:['Support Tickets','Ask a question or flag an issue, and track it through to resolved.'],
  features:['Feature Requests','Got an idea to make this portal better? Post it and vote on others.'],
  howto:['How to Use This Portal','A quick walkthrough of everything in here.'],
  settings:['Settings','Profile and notification preferences.'],
  glossary:['Marketing Glossary','Plain-English definitions for the terms we use.']
};
const PAGE_VIEW = window.FAVZE_PAGE || 'dashboard';
// Elements that live on a different page do not exist here. Sections of the code that update
// several areas at once (counts, lists) can therefore ask for an element this page does not
// contain; hand back a detached placeholder so those updates are harmless no-ops.
const _realGetById = document.getElementById.bind(document);
document.getElementById = function(id){ return _realGetById(id) || document.createElement('div'); };
const PORTAL_AFTER_KEY = 'favze-portal-after';
function runPortalAfter(a){
  if(!a) return;
  if(a.t==='ticket') openTicketModal(a.id);
  else if(a.t==='modal') openModal(a.v);
}
function goTo(view, after){
  if(view !== PAGE_VIEW){
    try{ if(after) sessionStorage.setItem(PORTAL_AFTER_KEY, JSON.stringify(after)); else sessionStorage.removeItem(PORTAL_AFTER_KEY); }catch(e){}
    window.location.href = 'portal-' + view + '.html';
    return;
  }
  runPortalAfter(after);
  applyViewChrome(view);
}
function applyViewChrome(view){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  const viewEl = _realGetById('view-'+view); if(viewEl) viewEl.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const navEl = document.querySelector('.nav-item[data-view="'+view+'"]'); if(navEl) navEl.classList.add('active');
  document.getElementById('topbar-title').textContent = titles[view][0];
  document.getElementById('topbar-sub').textContent = titles[view][1];
  window.scrollTo(0,0);
}
applyViewChrome(PAGE_VIEW);

/* ===================== MODALS ===================== */
function openModal(name){ document.getElementById('overlay-'+name).classList.add('open'); }
function closeModal(name){ document.getElementById('overlay-'+name).classList.remove('open'); }
document.querySelectorAll('.overlay').forEach(o=>{
  if(o.id==='loginScreen' || o.id==='pendingScreen') return; // never dismissable by clicking outside
  o.addEventListener('click', e=>{ if(e.target===o) o.classList.remove('open'); });
});
/* ===================== SUPABASE (shared database with the Favze CRM) =====================
   This portal and the internal CRM now read and write the same three Supabase tables, so a
   piece of content submitted for approval in the CRM shows up here for the client to review,
   and the client's Approve/Reject/comment flows back to the CRM. Publishable key is the
   low-privilege, RLS-gated key Supabase designed for browser code — never put a secret key here.
   Real login now controls access: CLIENT_ID is set to the logged-in user's own auth id after
   sign-in, and the database's Row Level Security rules only let a user see rows where
   client_id matches their own id (or the agency's), so one client can no longer see another
   client's data just by having the same publishable key. */
const SUPABASE_URL = 'https://ozbhlqgytfyjdgkoyhkt.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_35rPBJVeCiEETVdBP0dLlw_OmpU77Vd';
let CLIENT_ID = null;
let supabaseClient = null;
function getSupabaseClient(){
  if(supabaseClient) return supabaseClient;
  if(typeof window.supabase==='undefined'){ console.error('Supabase JS library did not load'); return null; }
  supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);
  return supabaseClient;
}
/* Notification preference helpers */
function getNotifPrefs(){
  if(window.FAVZE_NOTIF_PREFS) return window.FAVZE_NOTIF_PREFS;
  var defaults = { content: true, ticket: true, invoice: true, report: false };
  try{
    var key = 'favze_notif_prefs_' + (window._favzeUid || 'default');
    var raw = localStorage.getItem(key);
    var prefs = raw ? Object.assign({}, defaults, JSON.parse(raw)) : Object.assign({}, defaults);
    window.FAVZE_NOTIF_PREFS = prefs;
    return prefs;
  }catch(e){ return defaults; }
}
/* Map action names to preference keys */
function notifPrefForAction(action){
  if(!action) return null;
  var a = action.toLowerCase();
  if(a === 'comment' || a === 'approved' || a === 'rejected' || a === 'photo-download') return 'content';
  if(a === 'new-ticket' || a === 'ticket-reply') return 'ticket';
  if(a === 'invoice-reminder') return 'invoice';
  if(a === 'report-ready') return 'report';
  return null;
}
async function notifyAgency({ action, contentTitle, note, ticketSubject, ticketCategory }){
  try{
    var prefKey = notifPrefForAction(action);
    if(prefKey !== null){
      var prefs = getNotifPrefs();
      if(!prefs[prefKey]) return; // user disabled this notification type
    }
    const sb = getSupabaseClient();
    if(!sb) return;
    const { data: { session } } = await sb.auth.getSession().catch(()=>({ data:{ session:null } }));
    if(!session) return;
    const clientName = session.user?.user_metadata?.full_name || session.user?.email || '';
    await fetch(`${SUPABASE_URL}/functions/v1/portal-notify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + session.access_token,
      },
      body: JSON.stringify({ action, contentTitle, clientName, note: note || '', ticketSubject, ticketCategory }),
    });
  }catch(e){ console.error('notifyAgency failed', e); }
}
async function downloadContentPhoto(url, contentId, contentTitle, photoNum){
  // Fire the notification first -- the download itself may be async
  notifyAgency({ action: 'photo-download', contentTitle: contentTitle, note: `Photo ${photoNum}` });
  try{
    const res = await fetch(url, { mode: 'cors' });
    if(!res.ok) throw new Error('fetch failed');
    const blob = await res.blob();
    const ext = (blob.type.split('/')[1] || 'jpg').replace('jpeg','jpg');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `favze-photo-${photoNum}.${ext}`;
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }catch(e){
    // CORS block or network error: open full-res in new tab so client can long-press save
    console.warn('Direct download blocked, opening in new tab', e);
    showPortalToast('Opening photo in new tab -- long-press or right-click to save.');
    window.open(url, '_blank', 'noopener,noreferrer');
  }
}
function showLoginError(msg){
  const el = document.getElementById('login-error');
  el.textContent = msg;
  el.style.display = 'block';
}
let loginMode = 'signin';
function setLoginMode(mode){
  loginMode = mode;
  document.getElementById('login-error').style.display = 'none';
  document.getElementById('login-success').style.display = 'none';
  const signinTab = document.getElementById('login-tab-signin');
  const signupTab = document.getElementById('login-tab-signup');
  const fpBtn = document.getElementById('forgot-pw-btn');
  if(mode==='signin'){
    signinTab.style.background = '#fff'; signinTab.style.boxShadow = '0 1px 2px rgba(0,0,0,.08)'; signinTab.style.color = 'var(--navy-deep)';
    signupTab.style.background = 'transparent'; signupTab.style.boxShadow = 'none'; signupTab.style.color = 'var(--slate)';
    document.getElementById('login-subtext').textContent = 'Sign in with the email and password your account manager gave you.';
    document.getElementById('login-btn').textContent = 'Sign In';
    document.getElementById('login-footnote').innerHTML = "Don't have login details yet? <a href=\"mailto:riley@favze.com\" style=\"color:var(--navy);\">Reach out to your account manager.</a>";
    if(fpBtn) fpBtn.style.display = '';
  } else {
    signupTab.style.background = '#fff'; signupTab.style.boxShadow = '0 1px 2px rgba(0,0,0,.08)'; signupTab.style.color = 'var(--navy-deep)';
    signinTab.style.background = 'transparent'; signinTab.style.boxShadow = 'none'; signinTab.style.color = 'var(--slate)';
    document.getElementById('login-subtext').textContent = 'Create your account with a work email and a password.';
    document.getElementById('login-btn').textContent = 'Sign Up';
    document.getElementById('login-footnote').textContent = 'Already have an account? Switch to Sign In above.';
    if(fpBtn) fpBtn.style.display = 'none';
  }
}
function handleLoginSubmit(){
  if(loginMode==='signin') portalSignIn();
  else portalSignUp();
}
async function portalSignIn(){
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const btn = document.getElementById('login-btn');
  document.getElementById('login-error').style.display = 'none';
  document.getElementById('login-success').style.display = 'none';
  if(!email || !password){ showLoginError('Enter both your email and password.'); return; }
  const locked = portalAuthIsLocked(email);
  if(locked){ showLoginError(`Too many failed attempts. Try again in ${locked} seconds.`); return; }
  const client = getSupabaseClient();
  if(!client){ showLoginError('Could not reach the login service. Check your connection and try again.'); return; }
  btn.textContent = 'Signing in…'; btn.disabled = true;
  try{
    const { data, error } = await client.auth.signInWithPassword({ email, password });
    if(error){
      const fails = portalAuthRecordFail(email);
      const remaining = PORTAL_AUTH_MAX_FAILS - fails;
      if(remaining <= 0){
        showLoginError('Too many failed attempts. Sign-in is locked for 5 minutes.');
      } else {
        showLoginError(`That email and password combination was not recognized.${remaining <= 2 ? ` ${remaining} attempt${remaining===1?'':'s'} remaining before lockout.` : ''}`);
      }
      return;
    }
    portalAuthClearFails(email);
    await onSignedIn(data.session);
  }catch(err){
    console.error(err);
    showLoginError('Could not reach the login service. Check your connection and try again.');
  }finally{
    btn.textContent = 'Sign In'; btn.disabled = false;
  }
}
async function portalSignUp(){
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const btn = document.getElementById('login-btn');
  document.getElementById('login-error').style.display = 'none';
  document.getElementById('login-success').style.display = 'none';
  if(!email || !password){ showLoginError('Enter both an email and a password.'); return; }
  if(password.length < 12){ showLoginError('Use a password with at least 12 characters.'); return; }
  const client = getSupabaseClient();
  if(!client){ showLoginError('Could not reach the login service. Check your connection and try again.'); return; }
  btn.textContent = 'Creating account…'; btn.disabled = true;
  try{
    const { data, error } = await client.auth.signUp({ email, password });
    if(error){ showLoginError(error.message || 'Could not create that account.'); return; }
    if(data.session){
      // Email confirmation is off for this project, the new account is signed in immediately.
      await onSignedIn(data.session);
    } else {
      // Email confirmation is required, they'll need to click the link before signing in.
      const successEl = document.getElementById('login-success');
      successEl.textContent = 'Account created. Check your email to confirm it, then sign in.';
      successEl.style.display = 'block';
      setLoginMode('signin');
    }
  }catch(err){
    console.error(err);
    showLoginError('Could not reach the login service. Check your connection and try again.');
  }finally{
    btn.textContent = 'Sign Up'; btn.disabled = false;
  }
}
async function portalSignOut(){
  const client = getSupabaseClient();
  if(client) await client.auth.signOut();
  CLIENT_ID = null;
  document.getElementById('portalShell').style.display = 'none';
  document.getElementById('pendingScreen').classList.remove('open');
  document.getElementById('loginScreen').classList.add('open');
  document.getElementById('login-email').value = '';
  document.getElementById('login-password').value = '';
}
let currentSessionEmail = 'Client Contact';
async function ensureAccountRequest(role){
  const client = getSupabaseClient();
  if(!client) return null;
  try{
    const { data: existing, error: selErr } = await client.from('account_requests').select('*').eq('user_id', CLIENT_ID).maybeSingle();
    if(selErr){ console.error(selErr); return null; }
    if(existing) return existing;
    const { data: inserted, error: insErr } = await client.from('account_requests').insert({ user_id: CLIENT_ID, email: currentSessionEmail, role }).select().maybeSingle();
    if(insErr){ console.error(insErr); return null; }
    return inserted;
  }catch(err){ console.error(err); return null; }
}
async function onSignedIn(session){
  CLIENT_ID = session.user.id;
  window._favzeUid = session.user.id;
  currentSessionEmail = session.user.email || 'Client Contact';
  document.getElementById('acct-email').textContent = currentSessionEmail;
  document.getElementById('acct-avatar').textContent = currentSessionEmail.slice(0,2).toUpperCase();
  document.getElementById('loginScreen').classList.remove('open');
  const request = await ensureAccountRequest('client');
  if(!request || !request.approved){
    document.getElementById('pendingScreen').classList.add('open');
    document.getElementById('portalShell').style.display = 'none';
    return;
  }
  document.getElementById('pendingScreen').classList.remove('open');
  document.getElementById('portalShell').style.display = '';
  await initPortal();
  if(typeof window.onPortalReady === 'function'){ try{ window.onPortalReady(); }catch(e){} }
}
/* ===================== PASSWORD RESET =====================
   Supabase sends reset links with a ?code= query param (PKCE flow).
   We detect that before showing the login screen, display a loading
   placeholder, then swap in the reset form once PASSWORD_RECOVERY fires. */
function portalShowLoginError(msg){
  const el = document.getElementById('login-error');
  if(el){ el.textContent = msg; el.style.display = 'block'; }
}
async function portalSendPasswordReset(){
  const email = (document.getElementById('login-email')||{}).value?.trim();
  const btn = document.getElementById('forgot-pw-btn');
  const successEl = document.getElementById('login-success');
  const errEl = document.getElementById('login-error');
  if(!email){ portalShowLoginError('Enter your email address above, then click Forgot password?.'); return; }
  const client = getSupabaseClient();
  if(!client){ portalShowLoginError('Could not reach the login service. Check your connection.'); return; }
  if(btn) btn.disabled = true;
  try{
    const { error } = await client.auth.resetPasswordForEmail(email, { redirectTo: window.location.href.split('?')[0].split('#')[0] });
    if(errEl) errEl.style.display = 'none';
    if(successEl){ successEl.textContent = error ? (error.message||'Could not send reset email.') : 'Reset link sent. Check your inbox.'; successEl.style.display = 'block'; }
  }catch(e){ portalShowLoginError('Could not send reset email. Try again.'); }
  finally{ if(btn) btn.disabled = false; }
}
async function portalSubmitPasswordReset(){
  const btn = document.getElementById('portal-reset-btn');
  const msgEl = document.getElementById('portal-reset-msg');
  const pw = (document.getElementById('portal-reset-pw')||{}).value||'';
  if(pw.length < 12){ if(msgEl) msgEl.textContent = 'Use at least 12 characters.'; return; }
  const client = getSupabaseClient();
  if(!client) return;
  if(btn) btn.disabled = true;
  try{
    const { error } = await client.auth.updateUser({ password: pw });
    if(error){ if(msgEl) msgEl.textContent = error.message || 'Could not update password.'; return; }
    const ls = document.getElementById('login-success');
    if(ls){ ls.textContent = 'Password updated. Sign in with your new password.'; ls.style.display = 'block'; }
    document.getElementById('loginScreen').classList.add('open');
    document.getElementById('portal-reset-wrap').style.display = 'none';
  }catch(e){ if(msgEl) msgEl.textContent = 'Could not update password. Try again.'; }
  finally{ if(btn) btn.disabled = false; }
}
const _portalIsRecoveryLink = (function handlePortalPasswordReset(){
  const search = window.location.search;
  const hash = window.location.hash;
  const sp = new URLSearchParams(search);
  const hp = new URLSearchParams(hash.replace(/^#/, ''));
  const codeVal = sp.get('code');
  const isRecovery = hp.get('type') === 'recovery' || sp.get('type') === 'recovery' || (typeof codeVal === 'string' && codeVal.length > 10);
  if(!isRecovery) return false;
  const client = getSupabaseClient();
  if(!client) return false;
  // Show a loading placeholder synchronously so the login form never flashes
  const ls = document.getElementById('loginScreen');
  if(ls) ls.classList.add('open');
  // Find the card (.modal inside loginScreen) so the reset form appears inside it
  const card = ls ? ls.querySelector('.modal') : null;
  const wrap = card || ls;
  if(wrap){
    const resetWrap = document.createElement('div');
    resetWrap.id = 'portal-reset-wrap';
    resetWrap.style.cssText = 'padding:24px;text-align:center;';
    resetWrap.innerHTML = '<p style="font-size:14px;color:#04305f;">Loading reset form…</p>';
    wrap.appendChild(resetWrap);
  }
  client.auth.onAuthStateChange((event) => {
    if(event === 'PASSWORD_RECOVERY'){
      const rw = document.getElementById('portal-reset-wrap');
      if(rw){
        rw.innerHTML = `
          <p style="font-size:15px;font-weight:700;color:#04305f;margin:0 0 6px;">Set a new password</p>
          <p style="font-size:13px;color:#5b6b80;margin-bottom:16px;">Choose a strong password with at least 12 characters.</p>
          <div style="text-align:left;margin-bottom:12px;">
            <label style="font-size:11.5px;font-weight:700;color:#04305f;">New Password</label>
            <input id="portal-reset-pw" type="password" autocomplete="new-password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" onkeydown="if(event.key==='Enter')portalSubmitPasswordReset()" style="width:100%;margin-top:4px;padding:10px 12px;border:1px solid #d5dce6;border-radius:9px;font-size:14px;box-sizing:border-box;">
          </div>
          <div id="portal-reset-msg" style="font-size:12.5px;margin-bottom:12px;min-height:16px;color:#b42318;"></div>
          <button id="portal-reset-btn" type="button" onclick="portalSubmitPasswordReset()" style="width:100%;padding:12px;border:none;border-radius:9px;background:#04305f;color:#fff;font-weight:700;font-size:14px;cursor:pointer;">Set Password</button>`;
      }
    }
  });
  return true;
})();
async function checkExistingSession(){
  if(_portalIsRecoveryLink) return; // let the reset handler take over
  const client = getSupabaseClient();
  if(!client){ return; }
  const { data } = await client.auth.getSession();
  if(data && data.session){ await onSignedIn(data.session); }
}
checkExistingSession();
const STORAGE_KEY_TO_TABLE = {
  'favze-portal-content-items': 'content_items',
  'favze-portal-tickets': 'support_tickets',
  'favze-portal-features': 'feature_requests',
};
/* ===================== PERSISTENCE HELPERS =====================
   storageGet/storageSet keep their original names and shapes (a whole array in, a whole array
   out) so every call site below is unchanged. Underneath, they now sync that array to a shared
   Supabase table (each item stored as one row, keyed by its own id, under CLIENT_ID) instead of
   the old window.storage-only approach. window.storage/localStorage is kept as a same-device
   fallback if Supabase is unreachable (offline, or misconfigured), so the portal still works. */
async function storageGet(key, fallback){
  const table = STORAGE_KEY_TO_TABLE[key];
  if(table && CLIENT_ID){
    try{
      const client = getSupabaseClient();
      if(client){
        const { data, error } = await client.from(table).select('data').eq('client_id', CLIENT_ID).order('created_at', {ascending:true});
        if(!error && data) return data.map(row=>row.data);
      }
    }catch(e){ console.error('Supabase load failed, falling back to local storage', e); }
  }
  try{
    if(!window.storage) return fallback;
    const res = await window.storage.get(key, false);
    return (res && res.value) ? JSON.parse(res.value) : fallback;
  }catch(e){ return fallback; }
}
async function storageSet(key, value){
  const table = STORAGE_KEY_TO_TABLE[key];
  if(table && CLIENT_ID){
    try{
      const client = getSupabaseClient();
      if(client){
        if(value.length === 0){
          // All items removed -- delete every row for this client so other devices
          // don't see stale data on next load.
          const { error } = await client.from(table).delete().eq('client_id', CLIENT_ID);
          if(error) console.error('Supabase delete-all failed', error);
        } else {
          const rows = value.map(item=>({ id: String(item.id), client_id: CLIENT_ID, data: item, updated_at: new Date().toISOString() }));
          const { error } = await client.from(table).upsert(rows);
          if(error) console.error('Supabase save failed', error);
          // Remove any rows whose ids are no longer in the current value array
          // (handles single-item deletions without clearing everything).
          const currentIds = rows.map(r=>r.id);
          await client.from(table).delete().eq('client_id', CLIENT_ID).not('id', 'in', `(${currentIds.join(',')})`);
        }
      }
    }catch(e){ console.error('Supabase save failed, falling back to local storage', e); }
  }
  try{
    if(!window.storage) return;
    await window.storage.set(key, JSON.stringify(value), false);
  }catch(e){ /* local fallback unavailable, fail silently */ }
}



/* ===================== PINNED ANNOUNCEMENTS ===================== */
const pins = [
  {label:'Welcome', text:'This is your Favze Portal. Announcements from your account team will show up here.'}
];
let pinIdx = 0;
if(pins.length<=1){
  const pinnedNav = document.getElementById('pinned-nav');
  if(pinnedNav) pinnedNav.style.display='none';
}
function cyclePin(dir){
  pinIdx = (pinIdx + dir + pins.length) % pins.length;
  document.getElementById('pin-label').textContent = pins[pinIdx].label;
  document.getElementById('pin-text').textContent = pins[pinIdx].text;
}

/* ===================== CONTENT CALENDAR ===================== */
const defaultContentItems = [];
let contentItems = [];
let currentContentId = null;

function escHtml(s){ const d=document.createElement('div'); d.textContent = s==null?'':String(s); return d.innerHTML; }
function escJs(s){ return escHtml(s).replace(/'/g,'&#x27;'); }
let _portalToastTimer = null;
function showPortalToast(msg, isError){
  let el = document.getElementById('portal-toast');
  if(!el){
    el = document.createElement('div');
    el.id = 'portal-toast';
    el.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:10px 20px;border-radius:8px;font-size:14px;font-weight:600;color:#fff;z-index:9999;pointer-events:none;transition:opacity .3s;';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.background = isError ? '#b42318' : '#04305f';
  el.style.opacity = '1';
  clearTimeout(_portalToastTimer);
  _portalToastTimer = setTimeout(()=>{ el.style.opacity='0'; }, 3000);
}
function fmtNow(){
  return new Date().toLocaleString('en-US', {month:'short', day:'numeric', hour:'numeric', minute:'2-digit'});
}
function fmtDate(iso){
  if(!iso) return '';
  const [y,m,d] = iso.split('-');
  return new Date(Number(y), Number(m)-1, Number(d)).toLocaleDateString('en-US', {month:'short', day:'numeric', year:'numeric'});
}
function statusBadgeClass(status){
  return status==='approved' ? 'badge-approved' : status==='pending' ? 'badge-pending' : 'badge-rejected';
}
function statusBadgeText(status){
  return status==='approved' ? 'Approved' : status==='pending' ? 'Pending Review' : 'Needs Revision';
}
function fmtItemDate(iso){
  if(!iso) return '';
  return new Date(iso+'T00:00:00').toLocaleDateString('en-US', {month:'long', day:'numeric', year:'numeric'});
}

// Real calendar math, not a hardcoded month. Content items carry a full ISO date (set by
// whichever app created them — the CRM's Content Calendar uses real dates), so this works
// correctly no matter what month or year a synced item actually falls on.
let calMonthOffset = 0;
function calMonthMeta(offset){
  const d = new Date(); d.setDate(1); d.setMonth(d.getMonth()+offset);
  return { year: d.getFullYear(), month: d.getMonth() };
}
function buildMonthCells(year, month){
  const first = new Date(year, month, 1);
  const startDay = first.getDay(); // 0=Sun, matches the Sun-first dow header below
  const daysInMonth = new Date(year, month+1, 0).getDate();
  const cells = [];
  for(let i=0;i<startDay;i++) cells.push(null);
  for(let d=1; d<=daysInMonth; d++) cells.push(new Date(year, month, d));
  return cells;
}
function isoDate(d){ return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
function changeCalMonth(dir){
  calMonthOffset += dir;
  buildCalendar();
}
function buildCalendar(){
  const { year, month } = calMonthMeta(calMonthOffset);
  document.getElementById('cal-month-label').textContent = new Date(year, month, 1).toLocaleDateString('en-US', {month:'long', year:'numeric'});
  const grid = document.getElementById('cal-grid');
  grid.innerHTML = '';
  const dows = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  dows.forEach(d=>{
    const el = document.createElement('div');
    el.className='cal-dow'; el.textContent=d;
    grid.appendChild(el);
  });
  const cells = buildMonthCells(year, month);
  cells.forEach(dateObj=>{
    const c = document.createElement('div'); c.className='cal-cell';
    if(!dateObj){ c.className += ' faded'; grid.appendChild(c); return; }
    const num = document.createElement('div'); num.className='cal-daynum'; num.textContent=dateObj.getDate();
    c.appendChild(num);
    const iso = isoDate(dateObj);
    contentItems.filter(ci=>ci.date===iso).forEach(ci=>{
      const chip = document.createElement('div');
      chip.className='cal-chip chip-'+ci.status;
      chip.onclick=()=>openContentModal(ci.id);
      chip.innerHTML='<span class="dot"></span>'+escHtml(ci.title);
      c.appendChild(chip);
    });
    grid.appendChild(c);
  });
  buildCalList();
  updateCalendarCounts();
}
function buildCalList(){
  const wrap = document.getElementById('cal-list-rows');
  wrap.innerHTML = '';
  if(contentItems.length===0){
    wrap.innerHTML = '<div style="padding:20px 16px; font-size:13px; color:var(--slate-soft);">No content scheduled yet. Items your account team submits for review will show up here.</div>';
    return;
  }
  const sorted = [...contentItems].sort((a,b)=>(a.date||'').localeCompare(b.date||''));
  sorted.forEach(ci=>{
    const dateObj = ci.date ? new Date(ci.date+'T00:00:00') : null;
    const row = document.createElement('div');
    row.className='list-row';
    row.style.cursor='pointer';
    row.onclick=()=>openContentModal(ci.id);
    row.innerHTML = `
      <div class="list-thumb">${dateObj ? dateObj.getDate() : '?'}</div>
      <div class="list-main">
        <div class="list-title">${escHtml(ci.title)}</div>
        <div class="list-sub">${fmtItemDate(ci.date)}</div>
      </div>
      <span class="badge ${statusBadgeClass(ci.status)}">${statusBadgeText(ci.status)}</span>
    `;
    wrap.appendChild(row);
  });
}
function updateCalendarCounts(){
  const approved = contentItems.filter(c=>c.status==='approved').length;
  const pending = contentItems.filter(c=>c.status==='pending').length;
  const rejected = contentItems.filter(c=>c.status==='rejected').length;
  document.getElementById('cal-approved-count').textContent = approved;
  document.getElementById('cal-pending-count').textContent = pending;
  document.getElementById('cal-rejected-count').textContent = rejected;
  const navBadge = document.getElementById('nav-pending-badge');
  navBadge.textContent = pending;
  navBadge.style.display = pending>0 ? 'inline-flex' : 'none';
}
function renderContentThread(ci){
  const wrap = document.getElementById('cd-thread');
  wrap.innerHTML = '';
  if(ci.comments.length===0){
    wrap.innerHTML = '<div style="font-size:12.5px; color:var(--slate-soft); margin-bottom:10px;">No comments yet, be the first to leave one.</div>';
    return;
  }
  ci.comments.forEach(cm=>{
    const initials = cm.author.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    const row = document.createElement('div');
    row.className='comment';
    row.innerHTML = `
      <div class="avatar" style="${cm.role==='client' ? 'background:var(--slate-soft);' : ''}">${escHtml(initials)}</div>
      <div class="comment-body">
        <span class="comment-name">${escHtml(cm.author)}</span><span class="comment-time">${escHtml(cm.time)}</span>
        <div class="comment-text">${escHtml(cm.text)}</div>
      </div>
    `;
    wrap.appendChild(row);
  });
}
function openContentModal(id){
  currentContentId = id;
  const ci = contentItems.find(c=>c.id===id);
  if(!ci) return;
  document.getElementById('cd-type').textContent = ci.type;
  document.getElementById('cd-title').textContent = ci.title;
  document.getElementById('cd-desc').textContent = ci.desc || '';
  const capEl = document.getElementById('cd-caption');
  if(capEl){
    if(ci.caption){ capEl.textContent = '“' + ci.caption + '”'; capEl.style.display = ''; }
    else { capEl.textContent = ''; capEl.style.display = 'none'; }
  }
  const pageStatusEl = document.getElementById('cd-page-status');
  if(pageStatusEl){
    if(ci.typeValue === 'website-page' && (ci.copywritingStatus || ci.designStatus || ci.pageUrl)){
      pageStatusEl.style.display = '';
      document.getElementById('cd-copy-status').textContent = ci.copywritingStatus || 'Not Started';
      document.getElementById('cd-design-status').textContent = ci.designStatus || 'Not Started';
      const urlWrap = document.getElementById('cd-page-url-wrap');
      const urlEl = document.getElementById('cd-page-url');
      if(ci.pageUrl){ urlWrap.style.display = ''; urlEl.textContent = ci.pageUrl; urlEl.href = ci.pageUrl.startsWith('http') ? ci.pageUrl : '#'; }
      else { urlWrap.style.display = 'none'; }
    } else {
      pageStatusEl.style.display = 'none';
    }
  }
  const media = document.getElementById('cd-media');
  if(ci.imageUrls && ci.imageUrls.length){
    const safeUrls = ci.imageUrls.filter(u=>isSafeHttpUrl(u)||isSafeDataUrl(u));
    media.innerHTML = `<div class="review-carousel">${safeUrls.map((u,idx)=>`
      <div class="carousel-photo-wrap">
        <img src="${escHtml(u)}" onclick="window.open('${escJs(u)}','_blank','noopener,noreferrer')" alt="Content photo">
        <button class="btn-photo-dl" onclick="downloadContentPhoto('${escJs(u)}','${escJs(ci.id)}','${escJs(ci.title)}',${idx+1})" title="Download photo">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download
        </button>
      </div>`).join('')}</div>`;
  } else {
    media.innerHTML = `<div class="review-media-empty">No photos attached to this item yet.</div>`;
  }
  const badge = document.getElementById('cd-badge');
  badge.className = 'badge '+statusBadgeClass(ci.status);
  badge.textContent = statusBadgeText(ci.status);
  renderContentThread(ci);
  document.getElementById('cd-reply').value = '';
  openModal('content');
}
async function postContentComment(){
  const ci = contentItems.find(c=>c.id===currentContentId);
  if(!ci) return;
  const text = document.getElementById('cd-reply').value.trim();
  if(!text) return;
  ci.comments.push({author:currentSessionEmail, role:'client', time:fmtNow(), text});
  await storageSet('favze-portal-content-items', contentItems);
  renderContentThread(ci);
  document.getElementById('cd-reply').value = '';
  notifyAgency({ action: 'comment', contentTitle: ci.title, note: text });
}
async function setContentStatus(status){
  const ci = contentItems.find(c=>c.id===currentContentId);
  if(!ci) return;
  ci.status = status;
  await storageSet('favze-portal-content-items', contentItems);
  const badge = document.getElementById('cd-badge');
  badge.className = 'badge '+statusBadgeClass(status);
  badge.textContent = statusBadgeText(status);
  buildCalendar();
  renderDeliverables();
  notifyAgency({ action: status, contentTitle: ci.title });
  setTimeout(()=>closeModal('content'), 500);
}
function setCalView(btn, mode){
  document.querySelectorAll('.cal-tabs button').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('cal-month').style.display = mode==='month' ? 'block':'none';
  document.getElementById('cal-list').style.display = mode==='list' ? 'block':'none';
}

/* ===================== PROJECT DELIVERABLES =====================
   This panel is not a separate dataset, it reads straight from
   contentItems, the same array the Content Calendar uses. Approving
   or rejecting a piece here updates the calendar too, and vice versa,
   since both write to the same 'favze-portal-content-items' key. */
function renderDeliverables(){
  const wrap = document.getElementById('deliverablesList');
  wrap.innerHTML = '';
  const needsAction = contentItems.filter(c=>c.status!=='approved');
  document.getElementById('deliverables-count').textContent = contentItems.filter(c=>c.status==='pending').length+' pending';
  if(needsAction.length===0){
    wrap.innerHTML = '<div style="font-size:12.5px; color:var(--slate-soft); padding:10px 0;">Nothing waiting on you right now.</div>';
    return;
  }
  needsAction.forEach(ci=>{
    const row = document.createElement('div');
    row.className='list-row';
    row.style.cursor='pointer';
    let actionHtml;
    if(ci.status==='pending'){
      actionHtml = `
        <button class="btn btn-bad btn-sm" onclick="event.stopPropagation(); setContentStatusById('${ci.id}','rejected')">Needs Revision</button>
        <button class="btn btn-good btn-sm" onclick="event.stopPropagation(); setContentStatusById('${ci.id}','approved')">Approve</button>`;
    } else {
      actionHtml = `<span class="badge ${statusBadgeClass(ci.status)}">${statusBadgeText(ci.status)}</span>`;
    }
    row.onclick=()=>openContentModal(ci.id);
    row.innerHTML = `
      <div class="list-thumb">${escHtml(ci.title).slice(0,2).toUpperCase()}</div>
      <div class="list-main">
        <div class="list-title">${escHtml(ci.title)}</div>
        <div class="list-sub">${escHtml(ci.project)} &middot; ${fmtItemDate(ci.date)}</div>
      </div>
      <div style="display:flex; gap:8px; align-items:center;">${actionHtml}</div>
    `;
    wrap.appendChild(row);
  });
}
async function setContentStatusById(id, status){
  const ci = contentItems.find(c=>c.id===id);
  if(!ci) return;
  ci.status = status;
  await storageSet('favze-portal-content-items', contentItems);
  buildCalendar();
  renderDeliverables();
  notifyAgency({ action: status, contentTitle: ci.title });
}

/* ===================== SUPPORT TICKETS ===================== */
const defaultTickets = [];
let ticketsData = [];
let currentTicketId = null;
let ticketCounter = 1;

function priorityLabel(p){
  return {low:'Low priority', normal:'Normal priority', high:'High priority', urgent:'Urgent priority'}[p] || 'Normal priority';
}
function ticketBadgeClass(status){
  return status==='resolved' ? 'badge-resolved' : status==='in-progress' ? 'badge-inprogress' : 'badge-open';
}
function ticketBadgeText(status){
  return status==='resolved' ? 'Resolved' : status==='in-progress' ? 'In Progress' : 'Open';
}
function renderTickets(){
  const wrap = document.getElementById('ticketList');
  const empty = document.getElementById('ticketListEmpty');
  wrap.innerHTML = '';
  if(ticketsData.length===0){ empty.style.display='block'; return; }
  empty.style.display='none';
  const sorted = [...ticketsData].reverse();
  sorted.forEach(t=>{
    const row = document.createElement('div');
    row.className='list-row';
    row.style.cursor='pointer';
    row.onclick=()=>openTicketModal(t.id);
    row.innerHTML = `
      <div class="list-thumb"><span class="pri-chip pri-${t.priority}" style="margin:0;"></span></div>
      <div class="list-main">
        <div class="list-title">${escHtml(t.subject)}</div>
        <div class="list-sub">${escHtml(t.category)} &middot; opened ${escHtml(t.createdAt)}</div>
      </div>
      <span class="badge ${ticketBadgeClass(t.status)}">${ticketBadgeText(t.status)}</span>
    `;
    wrap.appendChild(row);
  });
  updateTicketsBadge();
}
function updateTicketsBadge(){
  const openCount = ticketsData.filter(t=>t.status!=='resolved').length;
  const navBadge = document.getElementById('nav-tickets-badge');
  navBadge.textContent = openCount;
  navBadge.style.display = openCount>0 ? 'inline-flex' : 'none';
}
function renderTicketThread(t){
  const wrap = document.getElementById('tk-thread');
  wrap.innerHTML = '';
  t.thread.forEach(cm=>{
    const initials = cm.author.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    const row = document.createElement('div');
    row.className='comment';
    row.innerHTML = `
      <div class="avatar" style="${cm.role==='client' ? 'background:var(--slate-soft);' : ''}">${escHtml(initials)}</div>
      <div class="comment-body">
        <span class="comment-name">${escHtml(cm.author)}</span><span class="comment-time">${escHtml(cm.time)}</span>
        <div class="comment-text">${escHtml(cm.text)}</div>
      </div>
    `;
    wrap.appendChild(row);
  });
}
function openTicketModal(id){
  currentTicketId = id;
  const t = ticketsData.find(x=>x.id===id);
  if(!t) return;
  document.getElementById('tk-category').textContent = t.category;
  document.getElementById('tk-subject').textContent = t.subject;
  document.getElementById('tk-details').textContent = t.details;
  const badge = document.getElementById('tk-badge');
  badge.className = 'badge '+ticketBadgeClass(t.status);
  badge.textContent = ticketBadgeText(t.status);
  document.getElementById('tk-pri-dot').className = 'pri-chip pri-'+t.priority;
  document.getElementById('tk-pri-text').textContent = priorityLabel(t.priority);
  document.getElementById('tk-resolve-btn').style.display = t.status==='resolved' ? 'none' : 'inline-flex';
  document.getElementById('tk-reopen-btn').style.display = t.status==='resolved' ? 'inline-flex' : 'none';
  renderTicketThread(t);
  document.getElementById('tk-reply').value = '';
  openModal('ticket');
}
async function submitTicket(){
  const subject = document.getElementById('ticketSubject').value.trim();
  const category = document.getElementById('ticketCategory').value;
  const priority = document.getElementById('ticketPriority').value;
  const details = document.getElementById('ticketDetails').value.trim();
  if(!subject || !details){
    showPortalToast('Add a subject and a few details so your account team knows what they are looking at.', true);
    return;
  }
  const id = 't'+Date.now();
  const now = fmtNow();
  const ticket = {id, subject, category, priority, status:'open', createdAt:now, details,
    thread:[{author:currentSessionEmail, role:'client', time:now, text:details}]};
  ticketsData.push(ticket);
  await storageSet('favze-portal-tickets', ticketsData);
  renderTickets();
  notifyAgency({ action: 'new-ticket', ticketSubject: subject, ticketCategory: category, note: details });
  document.getElementById('ticketSubject').value='';
  document.getElementById('ticketDetails').value='';
  closeModal('newTicket');
  goTo('tickets', {t:'ticket', id});
}
async function postTicketReply(){
  const t = ticketsData.find(x=>x.id===currentTicketId);
  if(!t) return;
  const text = document.getElementById('tk-reply').value.trim();
  if(!text) return;
  t.thread.push({author:currentSessionEmail, role:'client', time:fmtNow(), text});
  if(t.status==='resolved') t.status='open';
  await storageSet('favze-portal-tickets', ticketsData);
  renderTicketThread(t);
  notifyAgency({ action: 'ticket-reply', ticketSubject: t.subject, ticketCategory: t.category, note: text });
  document.getElementById('tk-reply').value='';
  const badge = document.getElementById('tk-badge');
  badge.className = 'badge '+ticketBadgeClass(t.status);
  badge.textContent = ticketBadgeText(t.status);
  document.getElementById('tk-resolve-btn').style.display = t.status==='resolved' ? 'none' : 'inline-flex';
  document.getElementById('tk-reopen-btn').style.display = t.status==='resolved' ? 'inline-flex' : 'none';
  renderTickets();
}
async function setTicketStatus(status){
  const t = ticketsData.find(x=>x.id===currentTicketId);
  if(!t) return;
  t.status = status;
  await storageSet('favze-portal-tickets', ticketsData);
  const badge = document.getElementById('tk-badge');
  badge.className = 'badge '+ticketBadgeClass(status);
  badge.textContent = ticketBadgeText(status);
  document.getElementById('tk-resolve-btn').style.display = status==='resolved' ? 'none' : 'inline-flex';
  document.getElementById('tk-reopen-btn').style.display = status==='resolved' ? 'inline-flex' : 'none';
  renderTickets();
}

/* ===================== SERVICE REQUESTS ===================== */
let currentServiceName = null;
function openServiceRequest(serviceName){
  currentServiceName = serviceName;
  document.getElementById('sr-name').textContent = serviceName;
  document.getElementById('sr-notes').value = '';
  openModal('serviceRequest');
}
async function submitServiceRequest(){
  const notes = document.getElementById('sr-notes').value.trim();
  const now = fmtNow();
  const id = 't'+Date.now();
  const details = notes ? `Interested in adding ${currentServiceName}. ${notes}` : `Interested in adding ${currentServiceName}.`;
  const ticket = {id, subject:'Service Request: '+currentServiceName, category:'Service Request', priority:'normal', status:'open', createdAt:now, details,
    thread:[{author:currentSessionEmail, role:'client', time:now, text:details}]};
  ticketsData.push(ticket);
  await storageSet('favze-portal-tickets', ticketsData);
  renderTickets();
  notifyAgency({ action: 'new-ticket', ticketSubject: ticket.subject, ticketCategory: 'Service Request', note: details });
  closeModal('serviceRequest');
  goTo('tickets', {t:'ticket', id});
}

/* ===================== FEATURE REQUESTS ===================== */
const defaultFeatures = [];
let featuresData = [];
let featureSort = 'votes';

function featureBadgeClass(status){
  return status==='shipped' ? 'badge-shipped' : status==='planned' ? 'badge-planned' : status==='in-progress' ? 'badge-progress' : 'badge-pending';
}
function featureBadgeText(status){
  return status==='shipped' ? 'Shipped' : status==='planned' ? 'Planned' : status==='in-progress' ? 'In Progress' : 'Under Review';
}
function renderFeatures(){
  const wrap = document.getElementById('featureList');
  const empty = document.getElementById('featureListEmpty');
  wrap.innerHTML = '';
  if(featuresData.length===0){ empty.style.display='block'; return; }
  empty.style.display='none';
  const sorted = featureSort==='votes'
    ? [...featuresData].sort((a,b)=>b.votes - a.votes)
    : [...featuresData].reverse(); // newest submitted first, relies on push() appending in chronological order
  sorted.forEach(f=>{
    const row = document.createElement('div');
    row.className='feature-row';
    row.innerHTML = `
      <div class="vote-block ${f.votedByMe?'voted':''}" onclick="toggleVote('${f.id}')">
        <div class="vote-arrow">&#9650;</div>
        <div class="vote-count">${f.votes}</div>
      </div>
      <div class="feature-main">
        <div class="feature-title">${escHtml(f.title)}</div>
        <div class="feature-desc">${escHtml(f.desc)}</div>
        <div class="feature-meta">
          <span class="badge ${featureBadgeClass(f.status)}">${featureBadgeText(f.status)}</span>
          <span>${escHtml(f.category)}</span>
          <span>&middot; posted by ${escHtml(f.author)}, ${escHtml(f.date)}</span>
        </div>
      </div>
    `;
    wrap.appendChild(row);
  });
}
// Votes are tracked per-browser via a random id stashed in localStorage so "did I vote"
// survives a reload even though the vote count lives in the shared Supabase table.
function getMyVoterId(){
  let id = localStorage.getItem('favze_portal_voter_id');
  if(!id){ id = 'v_'+Math.random().toString(36).slice(2,10); localStorage.setItem('favze_portal_voter_id', id); }
  return id;
}
async function toggleVote(id){
  const f = featuresData.find(x=>x.id===id);
  if(!f) return;
  const myId = getMyVoterId();
  f.voterIds = f.voterIds || [];
  if(f.votedByMe){ f.votes--; f.votedByMe=false; f.voterIds = f.voterIds.filter(v=>v!==myId); }
  else { f.votes++; f.votedByMe=true; f.voterIds.push(myId); }
  await storageSet('favze-portal-features', featuresData);
  renderFeatures();
}
function setFeatureSort(btn, mode){
  document.querySelectorAll('#view-features .cal-tabs button').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  featureSort = mode;
  renderFeatures();
}
async function submitFeature(){
  const title = document.getElementById('featureTitle').value.trim();
  const category = document.getElementById('featureCategory').value;
  const desc = document.getElementById('featureDetails').value.trim();
  if(!title || !desc){
    showPortalToast('Add a title and a short description so other users know what this is.', true);
    return;
  }
  const id = 'f'+Date.now();
  const myId = getMyVoterId();
  const feature = {id, title, category, desc, status:'under-review', votes:1, votedByMe:true, voterIds:[myId],
    author:currentSessionEmail, date:fmtNow()};
  featuresData.push(feature);
  await storageSet('favze-portal-features', featuresData);
  renderFeatures();
  document.getElementById('featureTitle').value='';
  document.getElementById('featureDetails').value='';
  closeModal('newFeature');
  goTo('features');
}

/* ===================== INIT ===================== */
async function initPortal(){
  const rawContentItems = await storageGet('favze-portal-content-items', defaultContentItems);
  // Only show items that are marked visible to client AND include this client's portal UID
  // in assignedClients. Legacy items (no assignedClients) are shown if visibleToClient is true.
  contentItems = rawContentItems.filter(ci=>{
    if(!ci.visibleToClient) return false;
    if(!ci.assignedClients || ci.assignedClients.length === 0) return true;
    return CLIENT_ID && ci.assignedClients.includes(CLIENT_ID);
  });
  ticketsData = await storageGet('favze-portal-tickets', defaultTickets);
  featuresData = await storageGet('favze-portal-features', defaultFeatures);
  const myId = getMyVoterId();
  featuresData.forEach(f=>{ f.voterIds = f.voterIds || []; f.votedByMe = f.voterIds.includes(myId); });
  buildCalendar();
  renderTickets();
  renderDeliverables();
  renderFeatures();
  loadExtraDeliverablesBilling();
  loadPortalProjects();
  loadBillingData();
  loadReferralData();
  loadPortalBrandAssets();
  checkSatisfactionPulse();
  try{ const a = JSON.parse(sessionStorage.getItem(PORTAL_AFTER_KEY)||'null'); sessionStorage.removeItem(PORTAL_AFTER_KEY); runPortalAfter(a); }catch(e){}
}

/* ===================== STRIPE PAYMENTS ===================== */
async function loadBillingData(){
  const client = getSupabaseClient();
  if(!client || !CLIENT_ID) return;
  try{
    const { data, error } = await client.from('crm_data').select('stripe_payment_link, referral_reward').eq('client_id', CLIENT_ID).maybeSingle();
    if(error || !data) return;
    // Stripe payment link
    const link = (data.stripe_payment_link || '').trim();
    const payWrap = document.getElementById('stripe-pay-wrap');
    if(payWrap){
      if(link){
        payWrap.innerHTML = `
          <a href="${escHtml(link)}" target="_blank" rel="noopener noreferrer" class="btn btn-primary" style="display:inline-flex;align-items:center;gap:8px;text-decoration:none;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
            Pay Invoice
          </a>
          <p style="font-size:12px;color:var(--slate);margin-top:8px;">Opens Stripe Checkout in a new tab. Your card details are never stored here.</p>`;
      } else {
        payWrap.innerHTML = `<p style="font-size:13px;color:var(--slate-soft);">No invoice ready yet. Your account manager will send a payment link when billing is active.</p>`;
      }
    }
    // Referral reward type
    const reward = (data.referral_reward || '').trim();
    const rewardEl = document.getElementById('referral-reward-type');
    if(rewardEl && reward) rewardEl.textContent = reward;
  }catch(e){ console.error('loadBillingData failed', e); }

  // Load individual invoices from invoices table
  loadInvoicesList();
}

async function loadInvoicesList(){
  const wrap = document.getElementById('invoices-list-wrap');
  if(!wrap || !CLIENT_ID) return;
  const client = getSupabaseClient();
  if(!client) return;
  try{
    const { data, error } = await client.from('invoices').select('*').eq('client_id', CLIENT_ID).order('created_at',{ascending:false});
    if(error) throw error;
    const rows = data || [];
    if(!rows.length){ wrap.innerHTML = '<div style="font-size:13px;color:var(--slate-soft);padding:4px 0;">No invoices yet.</div>'; return; }
    const statusColor = s => s==='paid'?'#276749':s==='overdue'?'#9b2c2c':s==='cancelled'?'#718096':'#92400e';
    const statusBg   = s => s==='paid'?'#c6f6d5':s==='overdue'?'#fed7d7':s==='cancelled'?'#edf2f7':'#fef3c7';
    wrap.innerHTML = rows.map(inv=>`
      <div style="border:1px solid var(--line,#e2e8f0);border-radius:10px;padding:14px 18px;margin-bottom:10px;background:#fff;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;">
          <div>
            ${inv.invoice_number?`<div style="font-size:11.5px;color:var(--slate);margin-bottom:2px;">${escHtml(inv.invoice_number)}</div>`:''}
            <div style="font-weight:700;font-size:15px;">${escHtml(inv.description||'Invoice')}</div>
            <div style="font-size:13px;color:var(--slate);margin-top:3px;">${inv.due_date?'Due '+fmtPortalDate(inv.due_date):''}</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:18px;font-weight:800;">${inv.amount!=null?'$'+Number(inv.amount).toFixed(2):''}</div>
            <span style="background:${statusBg(inv.status)};color:${statusColor(inv.status)};border-radius:4px;padding:2px 8px;font-size:11.5px;font-weight:700;">${inv.status}</span>
          </div>
        </div>
        ${inv.payment_link && inv.status!=='paid' && inv.status!=='cancelled' ? `
        <div style="margin-top:12px;">
          <a href="${escHtml(inv.payment_link)}" target="_blank" rel="noopener noreferrer"
            style="display:inline-block;background:#04305f;color:#fff;padding:9px 20px;border-radius:7px;text-decoration:none;font-weight:700;font-size:14px;">
            Pay Now
          </a>
          <span style="font-size:11.5px;color:var(--slate);margin-left:10px;">Secure checkout via Stripe</span>
        </div>` : ''}
      </div>`).join('');
  }catch(e){ console.error('loadInvoicesList failed', e); }
}

function fmtPortalDate(iso){
  if(!iso) return '';
  const d = new Date(iso+'T00:00:00');
  return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
}

/* ===================== BRAND ASSETS (CLIENT UPLOAD) ===================== */
const ASSET_TYPE_EMOJI = {
  'image/png':'🖼️','image/jpeg':'🖼️','image/jpg':'🖼️','image/svg+xml':'🖼️',
  'image/webp':'🖼️','image/gif':'🖼️','application/pdf':'📄',
  'font/ttf':'🔤','font/otf':'🔤','font/woff':'🔤','font/woff2':'🔤',
  'application/x-font-ttf':'🔤','application/x-font-otf':'🔤',
  'application/font-woff':'🔤','application/font-woff2':'🔤',
  'application/zip':'📦','application/x-zip-compressed':'📦'
};
function assetEmoji(mime){ return ASSET_TYPE_EMOJI[mime] || '📎'; }
function formatFileSize(bytes){
  if(!bytes) return '';
  if(bytes < 1024) return bytes + ' B';
  if(bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/1048576).toFixed(1) + ' MB';
}

async function loadPortalBrandAssets(){
  const grid = document.getElementById('assets-grid');
  if(!grid || !CLIENT_ID) return;
  const client = getSupabaseClient();
  if(!client) return;
  try{
    const { data, error } = await client.from('brand_assets').select('*').eq('client_id', CLIENT_ID).order('uploaded_at',{ascending:false});
    if(error) throw error;
    const rows = data || [];
    if(!rows.length){
      grid.innerHTML = '<div style="font-size:13px;color:var(--slate-soft);padding:4px 0;">No files uploaded yet. Add your logos, fonts, and brand photos above.</div>';
      return;
    }
    grid.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;">` +
      rows.map(a=>`
        <div style="border:1px solid var(--line,#e2e8f0);border-radius:10px;padding:14px;background:#fff;display:flex;flex-direction:column;gap:8px;">
          <div style="font-size:28px;">${assetEmoji(a.file_type)}</div>
          <div style="font-weight:600;font-size:13.5px;word-break:break-all;line-height:1.4;">${escHtml(a.file_name)}</div>
          <div style="font-size:12px;color:var(--slate);">${formatFileSize(a.file_size_bytes)} &middot; ${fmtPortalDate((a.uploaded_at||'').slice(0,10))}</div>
          <div style="display:flex;gap:8px;margin-top:4px;">
            <button class="btn btn-sm" onclick="downloadPortalAsset('${escHtml(a.file_path)}','${escHtml(a.file_name)}')" style="font-size:12px;padding:5px 12px;">Download</button>
            <button class="btn btn-sm" onclick="deletePortalAsset('${escHtml(a.id)}','${escHtml(a.file_path)}')" style="font-size:12px;padding:5px 12px;color:#dc2626;border-color:#dc2626;">Delete</button>
          </div>
        </div>`).join('') +
      `</div>`;
  }catch(e){ console.error('loadPortalBrandAssets failed', e); grid.innerHTML = '<div style="font-size:13px;color:var(--slate-soft);">Could not load files.</div>'; }
}

async function handleAssetUpload(input){
  const file = input.files && input.files[0];
  if(!file) return;
  if(file.size > 20 * 1024 * 1024){ alert('File exceeds the 20MB limit. Please choose a smaller file.'); input.value = ''; return; }
  const client = getSupabaseClient();
  if(!client || !CLIENT_ID) return;
  const progressWrap = document.getElementById('upload-progress');
  const statusEl = document.getElementById('upload-status');
  const bar = document.getElementById('upload-bar');
  if(progressWrap){ progressWrap.style.display = 'block'; }
  if(statusEl){ statusEl.textContent = 'Uploading ' + file.name + '...'; }
  if(bar){ bar.style.width = '30%'; }
  try{
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const path = `${CLIENT_ID}/${Date.now()}_${safeName}`;
    const { error: upErr } = await client.storage.from('brand-assets').upload(path, file, { contentType: file.type, upsert: false });
    if(upErr) throw upErr;
    if(bar){ bar.style.width = '70%'; }
    const { error: dbErr } = await client.from('brand_assets').insert({
      client_id: CLIENT_ID,
      file_name: file.name,
      file_path: path,
      file_type: file.type,
      file_size_bytes: file.size
    });
    if(dbErr) throw dbErr;
    if(bar){ bar.style.width = '100%'; }
    if(statusEl){ statusEl.textContent = 'Upload complete!'; }
    setTimeout(()=>{ if(progressWrap){ progressWrap.style.display = 'none'; bar.style.width = '0%'; } }, 1800);
    input.value = '';
    loadPortalBrandAssets();
  }catch(e){
    console.error('handleAssetUpload failed', e);
    if(statusEl){ statusEl.textContent = 'Upload failed. Please try again.'; }
    if(bar){ bar.style.width = '0%'; }
    input.value = '';
  }
}

async function downloadPortalAsset(filePath, fileName){
  const client = getSupabaseClient();
  if(!client) return;
  try{
    const { data, error } = await client.storage.from('brand-assets').download(filePath);
    if(error) throw error;
    const url = URL.createObjectURL(data);
    const a = document.createElement('a');
    a.href = url; a.download = fileName;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    setTimeout(()=> URL.revokeObjectURL(url), 5000);
  }catch(e){ console.error('downloadPortalAsset failed', e); alert('Could not download the file. Please try again.'); }
}

async function deletePortalAsset(assetId, filePath){
  if(!confirm('Delete this file? This cannot be undone.')) return;
  const client = getSupabaseClient();
  if(!client) return;
  try{
    await client.storage.from('brand-assets').remove([filePath]);
    await client.from('brand_assets').delete().eq('id', assetId);
    loadPortalBrandAssets();
  }catch(e){ console.error('deletePortalAsset failed', e); alert('Could not delete the file. Please try again.'); }
}

/* ===================== REFERRAL TRACKER ===================== */
async function loadReferralData(){
  const wrap = document.getElementById('referral-wrap');
  if(!wrap || !CLIENT_ID) return;
  const refLink = `${location.origin}${location.pathname.replace(/\/[^/]*$/, '/')}index.html?ref=${CLIENT_ID}`;
  const client = getSupabaseClient();
  let referrals = [];
  try{
    const { data, error } = await client.from('referrals').select('*').eq('referrer_client_id', CLIENT_ID).order('created_at', {ascending:false});
    if(!error) referrals = data || [];
  }catch(e){ console.error('loadReferralData failed', e); }
  const counts = { pending: 0, signed: 0, converted: 0 };
  referrals.forEach(r => { counts[r.status] = (counts[r.status] || 0) + 1; });
  wrap.innerHTML = `
    <div style="margin-bottom:16px;">
      <div style="font-size:13px;font-weight:600;color:var(--navy-deep);margin-bottom:6px;">Your referral link</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <input id="referral-link-input" type="text" value="${escHtml(refLink)}" readonly
          style="flex:1;min-width:200px;font-size:12px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--paper);color:var(--slate);">
        <button class="btn btn-navy btn-sm" onclick="copyReferralLink()" style="white-space:nowrap;">Copy Link</button>
      </div>
      <div id="referral-reward-type" style="font-size:12px;color:var(--slate);margin-top:6px;"></div>
    </div>
    <div class="grid g-3" style="margin-bottom:16px;">
      <div style="text-align:center;padding:14px;background:var(--paper);border-radius:10px;">
        <div style="font-size:28px;font-weight:900;font-family:'Barlow Condensed',sans-serif;color:var(--navy-deep);">${counts.pending + counts.signed + counts.converted}</div>
        <div style="font-size:12px;color:var(--slate);">Total Referred</div>
      </div>
      <div style="text-align:center;padding:14px;background:var(--good-bg);border-radius:10px;">
        <div style="font-size:28px;font-weight:900;font-family:'Barlow Condensed',sans-serif;color:var(--good);">${counts.signed + counts.converted}</div>
        <div style="font-size:12px;color:var(--slate);">Became Clients</div>
      </div>
      <div style="text-align:center;padding:14px;background:var(--pend-bg);border-radius:10px;">
        <div style="font-size:28px;font-weight:900;font-family:'Barlow Condensed',sans-serif;color:var(--pend);">${counts.pending}</div>
        <div style="font-size:12px;color:var(--slate);">Pending</div>
      </div>
    </div>
    ${referrals.length ? `
    <div style="font-size:13px;font-weight:600;color:var(--navy-deep);margin-bottom:8px;">Referral History</div>
    <div style="display:flex;flex-direction:column;gap:6px;">
      ${referrals.map(r=>`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--paper);border-radius:8px;font-size:13px;">
          <span style="color:var(--ink);">${escHtml(r.referred_email || 'Referred contact')}</span>
          <span class="badge ${r.status==='converted'?'badge-shipped':r.status==='signed'?'badge-planned':'badge-pending'}">${r.status==='converted'?'Converted':r.status==='signed'?'Signed':'Pending'}</span>
        </div>`).join('')}
    </div>` : `<p style="font-size:13px;color:var(--slate-soft);">No referrals yet. Share your link to get started.</p>`}
    <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--line);">
      <div style="font-size:13px;font-weight:600;color:var(--navy-deep);margin-bottom:8px;">Log a referral</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <input id="referral-email-input" type="email" placeholder="Referred business email"
          style="flex:1;min-width:180px;font-size:13px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;">
        <button class="btn btn-navy btn-sm" onclick="submitReferral()" style="white-space:nowrap;">Submit</button>
      </div>
    </div>`;
  // Load reward type now that DOM is set
  loadBillingData();
}

function copyReferralLink(){
  const inp = document.getElementById('referral-link-input');
  if(!inp) return;
  navigator.clipboard.writeText(inp.value).then(()=>showPortalToast('Referral link copied!')).catch(()=>{
    inp.select(); document.execCommand('copy'); showPortalToast('Referral link copied!');
  });
}

async function submitReferral(){
  const inp = document.getElementById('referral-email-input');
  if(!inp) return;
  const email = inp.value.trim();
  if(!email || !email.includes('@')){ showPortalToast('Enter a valid email address.', true); return; }
  const client = getSupabaseClient();
  if(!client || !CLIENT_ID){ showPortalToast('Sign in to submit a referral.', true); return; }
  try{
    const { error } = await client.from('referrals').insert({ referrer_client_id: CLIENT_ID, referred_email: email, status: 'pending' });
    if(error) throw error;
    inp.value = '';
    showPortalToast('Referral submitted! We\'ll follow up with them.');
    loadReferralData();
  }catch(e){ console.error(e); showPortalToast('Could not save referral. Try again.', true); }
}

/* ===================== SATISFACTION PULSE ===================== */
const PULSE_KEY = 'favze-pulse-last';
function checkSatisfactionPulse(){
  // Show pulse once per month per browser
  try{
    const last = localStorage.getItem(PULSE_KEY);
    if(last){
      const daysSince = (Date.now() - Number(last)) / 86400000;
      if(daysSince < 28) return;
    }
  }catch(e){}
  // Delay 90s after login so client gets a chance to look around first
  setTimeout(openPulseModal, 90000);
}
function openPulseModal(){
  const overlay = document.getElementById('overlay-pulse');
  if(!overlay) return;
  overlay.classList.add('open');
  renderPulseStars(0);
}
function closePulseModal(didRate){
  const overlay = document.getElementById('overlay-pulse');
  if(overlay) overlay.classList.remove('open');
  if(didRate){
    try{ localStorage.setItem(PULSE_KEY, String(Date.now())); }catch(e){}
  }
}
let pulseRating = 0;
function renderPulseStars(selected){
  pulseRating = selected;
  const wrap = document.getElementById('pulse-stars');
  if(!wrap) return;
  wrap.innerHTML = [1,2,3,4,5].map(n=>`
    <button onclick="renderPulseStars(${n})" aria-label="${n} star${n>1?'s':''}"
      style="background:none;border:none;cursor:pointer;padding:4px;font-size:36px;color:${n<=selected?'#f5a623':'var(--line)'};transition:color .1s;">
      &#9733;
    </button>`).join('');
}
async function submitPulse(){
  if(!pulseRating){ showPortalToast('Pick a rating first.', true); return; }
  const comment = (document.getElementById('pulse-comment')||{}).value || '';
  const client = getSupabaseClient();
  if(client && CLIENT_ID){
    try{
      await client.from('satisfaction_ratings').insert({ client_id: CLIENT_ID, rating: pulseRating, comment });
    }catch(e){ console.error('pulse insert failed', e); }
  }
  // Also notify agency
  notifyAgency({ action: 'satisfaction', note: `Rating: ${pulseRating}/5. ${comment}` });
  closePulseModal(true);
  showPortalToast('Thanks for the feedback!');
}
let portalProjects = [];
async function loadPortalProjects(){
  const wrap = document.getElementById('projectsListWrap');
  if(!wrap) return;
  wrap.innerHTML = '<p style="color:var(--slate); font-size:14px; padding:20px 0;">Loading projects...</p>';
  const client = getSupabaseClient();
  if(!client || !CLIENT_ID){ wrap.innerHTML = '<p style="color:var(--slate); font-size:14px; padding:20px 0;">Sign in to view your projects.</p>'; return; }
  try{
    const { data, error } = await client.from('client_projects').select('data').eq('client_id', CLIENT_ID);
    if(error) throw error;
    portalProjects = (data || []).map(r=>r.data).filter(p=>p.visibleToClient);
    renderProjects();
  }catch(err){
    console.error(err);
    if(wrap) wrap.innerHTML = '<p style="color:var(--slate); font-size:14px; padding:20px 0;">Could not load projects right now.</p>';
  }
}
function renderProjects(){
  const wrap = document.getElementById('projectsListWrap');
  if(!wrap) return;
  if(!portalProjects.length){
    wrap.innerHTML = '<p style="color:var(--slate); font-size:14px; padding:20px 0;">No projects shared with you yet.</p>';
    return;
  }
  wrap.innerHTML = portalProjects.map(p=>{
    const tasks = p.projectTasks || [];
    const done = tasks.filter(t=>t.status==='Done').length;
    const total = tasks.length;
    const pct = total ? Math.round((done/total)*100) : 0;
    const statusColors = {Planning:'#6b7280', 'In Progress':'#0d9488', Review:'#f59e0b', Complete:'#10b981'};
    const statusColor = statusColors[p.status] || '#6b7280';
    return `
    <div class="project-card" id="proj_${p.id}" style="background:var(--surface); border:1.5px solid var(--line); border-radius:12px; padding:20px 24px; margin-bottom:16px;">
      <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:16px; cursor:pointer;" onclick="toggleProjectTasks('${p.id}')">
        <div style="flex:1;">
          <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
            <span style="font-size:16px; font-weight:700; color:var(--navy-deep);">${escHtml(p.name)}</span>
            <span style="font-size:11px; font-weight:600; padding:3px 10px; border-radius:20px; background:${statusColor}22; color:${statusColor};">${p.status}</span>
          </div>
          ${p.description ? `<p style="font-size:13px; color:var(--slate); margin:0 0 10px;">${escHtml(p.description)}</p>` : ''}
          <div style="display:flex; gap:16px; font-size:12px; color:var(--slate);">
            ${p.startDate ? `<span>Started ${fmtDate(p.startDate)}</span>` : ''}
            ${p.dueDate ? `<span>Due ${fmtDate(p.dueDate)}</span>` : ''}
          </div>
        </div>
        <div style="text-align:right; min-width:80px;">
          <div style="font-size:22px; font-weight:800; color:var(--navy-deep);">${pct}%</div>
          <div style="font-size:11px; color:var(--slate);">${done} of ${total} tasks</div>
        </div>
      </div>
      ${total ? `
      <div style="margin-top:12px; background:var(--line); border-radius:4px; height:6px; overflow:hidden;">
        <div style="width:${pct}%; height:100%; background:var(--teal); border-radius:4px; transition:width .4s;"></div>
      </div>` : ''}
      <div id="projTasks_${p.id}" style="display:none; margin-top:16px;">
        ${tasks.length ? tasks.map(t=>{
          const taskStatusColors = {'Not Started':'#6b7280', 'In Progress':'#0d9488', Done:'#10b981', Blocked:'#ef4444'};
          const tColor = taskStatusColors[t.status] || '#6b7280';
          return `
          <div style="display:flex; align-items:center; gap:12px; padding:10px 0; border-bottom:1px solid var(--line);">
            <div style="flex:1;">
              <div style="font-size:14px; font-weight:600; color:var(--navy-deep); ${t.status==='Done'?'text-decoration:line-through; opacity:.6;':''}">${escHtml(t.title)}</div>
              ${t.dueDate ? `<div style="font-size:11px; color:var(--slate);">Due ${fmtDate(t.dueDate)}</div>` : ''}
            </div>
            <span style="font-size:11px; font-weight:600; padding:3px 10px; border-radius:20px; background:${tColor}22; color:${tColor};">${t.status}</span>
            <div style="display:flex; gap:6px;">
              ${t.status!=='Done' ? `<button class="btn-ghost" style="font-size:12px; padding:4px 10px; color:#10b981; border-color:#10b981;" onclick="setTaskStatus('${p.id}','${t.id}','Done')">Done</button>` : ''}
              ${t.status!=='Blocked' ? `<button class="btn-ghost" style="font-size:12px; padding:4px 10px; color:#ef4444; border-color:#ef4444;" onclick="setTaskStatus('${p.id}','${t.id}','Blocked')">Blocked</button>` : ''}
            </div>
          </div>`;
        }).join('') : '<p style="font-size:13px; color:var(--slate); padding:8px 0;">No tasks added yet.</p>'}
      </div>
      ${tasks.length ? `<div style="margin-top:12px; text-align:center;"><button class="btn-ghost" style="font-size:12px;" onclick="toggleProjectTasks('${p.id}')">Show tasks</button></div>` : ''}
    </div>`;
  }).join('');
}
function toggleProjectTasks(projectId){
  const el = document.getElementById('projTasks_'+projectId);
  if(!el) return;
  const card = el.closest('.project-card');
  const btn = card ? card.querySelector('button[onclick^="toggleProjectTasks"]') : null;
  if(el.style.display==='none'){
    el.style.display='block';
    if(btn) btn.textContent='Hide tasks';
  } else {
    el.style.display='none';
    if(btn) btn.textContent='Show tasks';
  }
}
async function setTaskStatus(projectId, taskId, newStatus){
  const project = portalProjects.find(p=>p.id===projectId);
  if(!project) return;
  const task = (project.projectTasks||[]).find(t=>t.id===taskId);
  if(!task) return;
  task.status = newStatus;
  renderProjects();
  // re-open the task panel that was visible before re-render
  const panel = document.getElementById('projTasks_'+projectId);
  if(panel){
    panel.style.display = 'block';
    const btn = panel.closest('.project-card') && panel.closest('.project-card').querySelector('button[onclick^="toggleProjectTasks"]');
    if(btn) btn.textContent = 'Hide tasks';
  }
  // persist back to Supabase
  const client = getSupabaseClient();
  if(!client || !CLIENT_ID) return;
  try{
    await client.from('client_projects').update({ data: project, updated_at: new Date().toISOString() }).eq('id', projectId).eq('client_id', CLIENT_ID);
  }catch(err){ console.error('setTaskStatus sync failed', err); }
}
// Itemized, transparent -- each extra deliverable shows on its own with its own price. No
// bundled percentage markup gets added anywhere; total is just the sum of what's listed.
async function loadExtraDeliverablesBilling(){
  const el = document.getElementById('extraDeliverablesBilling');
  if(!el) return;
  const client = getSupabaseClient();
  if(!client){ el.innerHTML = 'Could not load.'; return; }
  try{
    const { data, error } = await client.from('extra_deliverables').select('data').eq('client_id', CLIENT_ID).order('created_at', {ascending:true});
    if(error) throw error;
    const rows = data || [];
    if(!rows.length){
      el.innerHTML = 'Nothing extra logged yet this cycle.';
      return;
    }
    const total = rows.reduce((sum,r)=> sum + (Number(r.data.value)||0), 0);
    el.innerHTML = rows.map(r=>`
      <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--line);">
        <div style="color:var(--ink);">${escHtml(r.data.title)}${r.data.note?` - <span style="color:var(--slate-soft);">${escHtml(r.data.note)}</span>`:''}</div>
        <b>$${Number(r.data.value||0).toLocaleString()}</b>
      </div>`).join('') + `<div style="display:flex; justify-content:space-between; padding-top:10px; font-weight:700; color:var(--ink);"><span>Total extra this cycle</span><span>$${total.toLocaleString()}</span></div>`;
  }catch(err){
    console.error(err);
    el.innerHTML = 'Could not load your extras right now.';
  }
}
// initPortal() now runs from onSignedIn() once a real session exists, not automatically here.


/* ===================== MEETINGS ===================== */
function pickSlot(el){
  document.querySelectorAll('.slot').forEach(s=>{ if(!s.classList.contains('taken')) s.classList.remove('selected'); });
  el.classList.add('selected');
}
function confirmMeeting(){
  const selected = document.querySelector('.slot.selected');
  if(!selected){
    showPortalToast('Pick a time slot first.', true);
    return;
  }
  showPortalToast('Meeting request sent for '+selected.textContent.trim()+'. Your account team will confirm shortly.');
}

/* ===================== GLOSSARY ===================== */
const glossary = [
  {term:'ROAS', def:'Return on Ad Spend. Revenue earned for every dollar spent on advertising. A 4x ROAS means $4 back for every $1 spent.'},
  {term:'CTR', def:'Click-Through Rate. The percentage of people who see an ad or listing and click on it.'},
  {term:'LTV', def:'Lifetime Value. The total revenue a business can expect from a single customer over the life of the relationship.'},
  {term:'GBP', def:'Google Business Profile. The free listing that controls how a business shows up in Google Search and Maps.'},
  {term:'Local Pack', def:'The set of three business listings shown at the top of Google Search results for a local search.'},
  {term:'CPC', def:'Cost Per Click. The amount paid each time someone clicks a paid ad.'},
  {term:'SEO', def:'Search Engine Optimization. Improving a website so it ranks higher in unpaid search results.'},
  {term:'AEO', def:'Answer Engine Optimization. Structuring content so AI tools and answer engines can find and cite it directly.'},
  {term:'Conversion Rate', def:'The percentage of visitors who complete a desired action, like booking an appointment or filling out a form.'},
  {term:'Impressions', def:'The number of times content or an ad was shown on screen, regardless of whether it was clicked.'},
  {term:'Bounce Rate', def:'The percentage of visitors who leave a website after viewing only one page.'},
  {term:'Retainer', def:'A recurring monthly fee that secures ongoing marketing work, rather than paying per project.'}
];
function renderGloss(list){
  const wrap = document.getElementById('glossList');
  if(!wrap) return;
  wrap.innerHTML = '';
  list.forEach(g=>{
    const el = document.createElement('div');
    el.className='gloss-item';
    el.innerHTML = `<div class="gloss-term">${g.term}</div><div class="gloss-def">${g.def}</div>`;
    wrap.appendChild(el);
  });
}
function filterGloss(){
  const q = document.getElementById('glossSearch').value.toLowerCase();
  renderGloss(glossary.filter(g=>g.term.toLowerCase().includes(q) || g.def.toLowerCase().includes(q)));
}
renderGloss(glossary);

/* ===================== MOBILE NAV ===================== */
(function injectMobileNav(){
  // Build the top bar and slide-out drawer from the existing sidebar's nav links
  const sidebar = document.querySelector('.sidebar');
  if(!sidebar) return;

  // Top bar
  const topbar = document.createElement('div');
  topbar.className = 'mob-topbar';
  topbar.innerHTML = `
    <div class="mob-logo">Favze</div>
    <button class="mob-hamburger" id="mob-ham" aria-label="Open menu">
      <span></span><span></span><span></span>
    </button>`;

  // Overlay
  const overlay = document.createElement('div');
  overlay.className = 'mob-drawer-overlay';
  overlay.id = 'mob-overlay';

  // Drawer -- clone the sidebar's nav links
  const drawer = document.createElement('nav');
  drawer.className = 'mob-drawer';
  drawer.id = 'mob-drawer';
  drawer.innerHTML = `<button class="mob-drawer-close" id="mob-close" aria-label="Close menu">&#x2715;</button>` + sidebar.innerHTML;

  document.body.prepend(overlay);
  document.body.prepend(drawer);
  const main = document.querySelector('.shell') || document.querySelector('main');
  if(main) main.before(topbar);
  else document.body.prepend(topbar);

  function openDrawer(){
    drawer.classList.add('open');
    overlay.classList.add('open');
    document.getElementById('mob-ham').classList.add('open');
    document.body.style.overflow = 'hidden';
  }
  function closeDrawer(){
    drawer.classList.remove('open');
    overlay.classList.remove('open');
    document.getElementById('mob-ham').classList.remove('open');
    document.body.style.overflow = '';
  }
  document.getElementById('mob-ham').addEventListener('click', openDrawer);
  document.getElementById('mob-close').addEventListener('click', closeDrawer);
  overlay.addEventListener('click', closeDrawer);
  drawer.querySelectorAll('a').forEach(a => a.addEventListener('click', closeDrawer));
})();
