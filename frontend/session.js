const resetToken=new URLSearchParams(location.hash.slice(1)).get('token')||'';
if(location.pathname==='/reset-password')history.replaceState(null,'',location.pathname);
/* No audit state or app frame exists before a valid server session. */
const el=id=>document.getElementById(id);
let sessionGeneration=0, signedIn=false, checking=false, setupRequired=false;
function clearWorkspace(message='Sign in to continue.'){
  sessionGeneration++;signedIn=false;el('recovery-panel').hidden=true;el('reset-form').reset();
  el('workspace-host').replaceChildren(); // Destroy the child document and its in-memory audit state.
  el('authenticated-shell').hidden=true;el('login-screen').hidden=false;
  el('login-form').hidden=false;el('password').value='';el('login-status').textContent=message;
}
async function sessionRequest(path,options={}){
  const response=await fetch('/api/auth/'+path,{...options,cache:'no-store',credentials:'same-origin',signal:AbortSignal.timeout(15000)});
  const data=await response.json();
  if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'Unable to sign in. Check your credentials.');
  return data;
}
function deviceMode(){
  const mode=el('device-mode').value;
  el('device-stage').dataset.device=mode;
  const description=el('device-description');description.hidden=mode==='desktop';
  description.textContent=mode==='android'?'Android layout preview · 390px viewport':'iPhone layout preview · 393px viewport';
  try{localStorage.setItem('accesslease.device',mode);}catch{}
}
function openWorkspace(){
  signedIn=true;el('login-screen').hidden=true;el('authenticated-shell').hidden=false;el('password').value='';
  if(!el('workspace-host').firstChild){const frame=document.createElement('iframe');frame.id='workspace-frame';frame.title='AccessLease authenticated dashboard';frame.src='/workspace'+(location.hash||'#overview');el('workspace-host').append(frame);}
  deviceMode();
}
async function checkSession(){
  if(checking)return;checking=true;const generation=sessionGeneration;
  try{const status=await sessionRequest('status');if(generation!==sessionGeneration)return;
    setupRequired=status.setup_required;el('forgot-password').hidden=setupRequired;
    if(location.pathname==='/reset-password'){el('login-screen').hidden=false;el('authenticated-shell').hidden=true;el('login-title').textContent='Recover your account';recoveryView(true);await loadResetChallenge();return;}
    if(status.authenticated){openWorkspace();return;}
    if(signedIn)clearWorkspace('Your session ended. Please sign in again.');
    el('login-form').hidden=false;el('retry-session').hidden=true;
    el('login-title').textContent=setupRequired?'Create your local administrator':'Sign in to your workspace';
    el('sign-in').textContent=setupRequired?'Create administrator':'Sign in securely';
    el('password').autocomplete=setupRequired?'new-password':'current-password';
    el('password-help').textContent=setupRequired?'First-time setup: choose a password with 10–128 characters.':'Use your existing local administrator credentials.';
    el('login-status').textContent='';
  }catch{if(generation!==sessionGeneration)return;clearWorkspace('Unable to verify your session. Keep the backend running and retry.');el('login-form').hidden=true;el('retry-session').hidden=false;}
  finally{checking=false;}
}
el('login-form').addEventListener('submit',async e=>{
  e.preventDefault();const button=el('sign-in');button.disabled=true;el('login-status').textContent='Verifying credentials…';
  try{await sessionRequest(setupRequired?'setup':'login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:el('username').value.trim(),password:el('password').value})});await checkSession();}
  catch(error){el('login-status').textContent=error.message;el('password').value='';el('password').focus();}
  finally{button.disabled=false;}
});
el('show-password').addEventListener('click',()=>{const show=el('password').type==='password';el('password').type=show?'text':'password';el('show-password').textContent=show?'Hide':'Show';el('show-password').setAttribute('aria-label',show?'Hide password':'Show password');el('show-password').setAttribute('aria-pressed',String(show));});
el('sign-out').addEventListener('click',async()=>{
  clearWorkspace('Signing out…');el('login-form').hidden=true;
  try{await sessionRequest('logout',{method:'POST'});el('login-status').textContent='Signed out.';el('login-form').hidden=false;}
  catch{el('login-status').textContent='Workspace hidden, but server sign-out could not be confirmed. Retry sign-out.';el('retry-session').hidden=false;el('retry-session').textContent='Retry sign-out';el('retry-session').dataset.logout='true';}
});
el('retry-session').addEventListener('click',()=>{if(el('retry-session').dataset.logout){delete el('retry-session').dataset.logout;el('retry-session').hidden=true;el('sign-out').click();}else checkSession();});
el('device-mode').addEventListener('change',deviceMode);
window.addEventListener('message',e=>{if(e.origin!==location.origin||e.source!==el('workspace-frame')?.contentWindow)return;if(e.data?.type==='accesslease:locked')clearWorkspace('Your session ended. Please sign in again.');});
window.addEventListener('pageshow',e=>{if(e.persisted){clearWorkspace('Checking your session…');el('login-form').hidden=true;checkSession();}});
window.addEventListener('pagehide',()=>{clearWorkspace('Checking your session…');});
try{const saved=localStorage.getItem('accesslease.device');if(['desktop','android','ios'].includes(saved))el('device-mode').value=saved;}catch{}
setInterval(()=>{if(signedIn&&!document.hidden)checkSession();},10000);
checkSession();

function recoveryView(show){el('recovery-panel').hidden=!show;el('login-form').hidden=show;el('forgot-password').hidden=show||setupRequired;el('login-status').textContent='';el('reset-status').textContent='';el('reset-form').reset();if(show){el('reset-username').value=el('username').value.trim();el('reset-username').focus();}else el('password').focus();}

el('back-to-login').addEventListener('click',()=>location.assign('/'));
el('confirm-password').addEventListener('input',()=>el('confirm-password').setCustomValidity(''));
el('new-password').addEventListener('input',()=>el('confirm-password').setCustomValidity(''));
el('reset-form').addEventListener('submit',async e=>{e.preventDefault();if(el('new-password').value!==el('confirm-password').value){el('confirm-password').setCustomValidity('Passwords do not match');el('confirm-password').reportValidity();return;}const button=el('reset-submit');button.disabled=true;el('reset-status').textContent='Resetting password…';try{const username=el('reset-username').value.trim();const result=await sessionRequest('reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password:el('new-password').value,recovery_code:resetToken,captcha_answer:el('captcha-answer').value.trim()})});el('password').value='';el('username').value=username;history.replaceState(null,'','/');el('login-title').textContent='Sign in to your workspace';recoveryView(false);el('login-status').textContent=result.message;}catch(error){el('reset-status').textContent=error.message;}finally{button.disabled=false;}});

async function loadResetChallenge(){
  el('reset-submit').disabled=true;
  if(!resetToken){el('reset-status').textContent='Run Reset-Password.cmd in your project folder to open a private reset link.';return;}
  try{const challenge=await sessionRequest('reset-challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:resetToken})});el('reset-username').value=challenge.username;el('reset-username').readOnly=true;el('captcha-question').textContent=challenge.question;el('reset-submit').disabled=false;el('new-password').focus();}
  catch(error){el('reset-status').textContent=error.message;}
}
