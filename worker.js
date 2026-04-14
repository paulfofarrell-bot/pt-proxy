async function hashPassword(password) {
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 2592000 })); // 30 days
  const data = header + '.' + body;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return data + '.' + sigB64;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const data = parts[0] + '.' + parts[1];
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sig = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch(e) {
    return null;
  }
}

function getToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/pt_session=([^;]+)/);
  return match ? match[1] : null;
}

function redirectToLogin(request, message) {
  const base = new URL(request.url).origin;
  const url = message ? `${base}/login?error=${encodeURIComponent(message)}` : `${base}/login`;
  return Response.redirect(url, 302);
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...extraHeaders }
  });
}

function sessionCookie(token) {
  return `pt_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login — The Partnership Tree</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,600;1,600&family=Lato:wght@300;400;700;900&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Lato',sans-serif;background:#0f2318;min-height:100vh;display:flex;align-items:center;justify-content:center;}
.card{background:#fff;border-radius:16px;padding:48px;width:100%;max-width:420px;box-shadow:0 24px 80px rgba(0,0,0,0.4);}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;}
.logo-text{font-family:'Playfair Display',serif;font-size:18px;color:#1a3a2a;font-weight:600;}
.logo-sub{font-size:10px;color:#6b7c6b;letter-spacing:.06em;text-transform:uppercase;margin-top:1px;}
h1{font-family:'Playfair Display',serif;font-size:26px;color:#1a3a2a;margin-bottom:8px;}
p{font-size:14px;color:#6b7c6b;margin-bottom:28px;line-height:1.6;}
label{font-size:11px;font-weight:700;color:#1a3a2a;letter-spacing:.06em;text-transform:uppercase;display:block;margin-bottom:6px;}
input{width:100%;padding:12px 14px;border:1.5px solid #dde8de;border-radius:8px;font-size:14px;font-family:inherit;color:#1a3a2a;outline:none;margin-bottom:16px;transition:border-color .2s;}
input:focus{border-color:#c9a84c;}
.btn{width:100%;padding:14px;background:#1a3a2a;border:none;border-radius:8px;font-weight:800;font-size:15px;color:#fff;cursor:pointer;font-family:inherit;letter-spacing:.04em;margin-top:4px;}
.btn:hover{background:#0f2318;}
.error{background:#ffeaea;color:#c0392b;padding:12px;border-radius:8px;font-size:13px;font-weight:700;margin-bottom:20px;display:none;}
.footer{margin-top:24px;text-align:center;font-size:12px;color:#6b7c6b;}
.footer a{color:#1a3a2a;font-weight:700;text-decoration:none;}
</style>
</head>
<body>
<nav style="position:fixed;top:0;left:0;right:0;background:#1a3a2a;height:56px;display:flex;align-items:center;padding:0 28px;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,0.08);z-index:100;">
  <a href="https://app.thepartnershiptree.com" style="display:flex;align-items:center;gap:10px;text-decoration:none;">
    <svg width="28" height="28" viewBox="0 0 36 36" fill="none"><circle cx="18" cy="18" r="18" fill="#2d5a3d"/><path d="M18 8 C18 8 10 14 10 20 C10 24.4 13.6 28 18 28 C22.4 28 26 24.4 26 20 C26 14 18 8 18 8Z" fill="#c9a84c" opacity="0.9"/></svg>
    <div><div style="font-family:'Playfair Display',serif;font-size:16px;color:#f5f0e8;font-weight:600;">The Partnership Tree</div><div style="font-size:9px;color:rgba(245,240,232,0.45);letter-spacing:.06em;text-transform:uppercase;">A Life Science Partner Network</div></div>
  </a>
  <span style="font-size:11px;font-weight:700;color:rgba(245,240,232,0.5);border:1px solid rgba(245,240,232,0.2);border-radius:6px;padding:5px 12px;letter-spacing:.04em;">Login</span>
</nav>
<div class="card" style="margin-top:72px;">
  <div class="logo">
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
      <circle cx="18" cy="18" r="18" fill="#1a3a2a"/>
      <path d="M18 8 C18 8 10 14 10 20 C10 24.4 13.6 28 18 28 C22.4 28 26 24.4 26 20 C26 14 18 8 18 8Z" fill="#c9a84c" opacity="0.9"/>
      <path d="M18 12 C18 12 13 16 13 20 C13 22.8 15.2 25 18 25 C20.8 25 23 22.8 23 20 C23 16 18 12 18 12Z" fill="#fff" opacity="0.15"/>
    </svg>
    <div><div class="logo-text">The Partnership Tree</div><div class="logo-sub">A Life Science Partner Network</div></div>
  </div>
  <h1>Welcome back</h1>
  <p>Sign in to access the partner search platform.</p>
  <div class="error" id="err"></div>
  <div id="loggedout" style="background:#f0f8f0;color:#1a6b2a;padding:11px 14px;border-radius:8px;font-size:13px;font-weight:700;margin-bottom:20px;display:none;">✓ You have been logged out successfully.</div>
  <form method="POST" action="/login">
    <label>Email address</label>
    <input type="email" name="email" placeholder="your@company.com" required autofocus/>
    <label>Password</label>
    <input type="password" name="password" placeholder="Your password" required/>
    <button type="submit" class="btn">Sign In →</button>
  </form>
  <div class="footer">Need access? <a href="https://thepartnershiptree.com">Request a demo</a></div>
</div>
<script>
const p=new URLSearchParams(location.search);
const e=p.get('error');
if(e){const el=document.getElementById('err');el.textContent=e;el.style.display='block';}
if(p.get('loggedout')==='1'){document.getElementById('loggedout').style.display='block';}
</script>
</body>
</html>`;

const SET_PASSWORD_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Set Your Password — The Partnership Tree</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,600;1,600&family=Lato:wght@300;400;700;900&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Lato',sans-serif;background:#0f2318;min-height:100vh;display:flex;align-items:center;justify-content:center;}
.card{background:#fff;border-radius:16px;padding:48px;width:100%;max-width:420px;box-shadow:0 24px 80px rgba(0,0,0,0.4);}
.logo-text{font-family:'Playfair Display',serif;font-size:18px;color:#1a3a2a;font-weight:600;}
h1{font-family:'Playfair Display',serif;font-size:26px;color:#1a3a2a;margin-bottom:8px;}
label{font-size:11px;font-weight:700;color:#1a3a2a;letter-spacing:.06em;text-transform:uppercase;display:block;margin-bottom:6px;}
input{width:100%;padding:12px 14px;border:1.5px solid #dde8de;border-radius:8px;font-size:14px;font-family:inherit;color:#1a3a2a;outline:none;margin-bottom:16px;}
input:focus{border-color:#c9a84c;}
.btn{width:100%;padding:14px;background:#1a3a2a;border:none;border-radius:8px;font-weight:800;font-size:15px;color:#fff;cursor:pointer;font-family:inherit;}
.error{background:#ffeaea;color:#c0392b;padding:12px;border-radius:8px;font-size:13px;font-weight:700;margin-bottom:20px;display:none;}
.notice{background:#f0f8f0;color:#1a6b2a;padding:14px;border-radius:8px;font-size:13px;margin-bottom:24px;line-height:1.6;}
</style>
</head>
<body>
<div class="card">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:28px;">
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none"><circle cx="18" cy="18" r="18" fill="#1a3a2a"/><path d="M18 8 C18 8 10 14 10 20 C10 24.4 13.6 28 18 28 C22.4 28 26 24.4 26 20 C26 14 18 8 18 8Z" fill="#c9a84c" opacity="0.9"/></svg>
    <div><div class="logo-text">The Partnership Tree</div></div>
  </div>
  <h1>Set your password</h1>
  <div class="notice">Welcome! This is your first login. Please set a personal password to secure your account.</div>
  <div class="error" id="err"></div>
  <form method="POST" action="/set-password">
    <label>New password</label>
    <input type="password" name="password" id="pw" placeholder="Minimum 8 characters" required/>
    <label>Confirm password</label>
    <input type="password" name="confirm" id="pw2" placeholder="Repeat your password" required/>
    <button type="submit" class="btn">Set Password & Continue →</button>
  </form>
</div>
<script>
document.querySelector('form').addEventListener('submit',function(e){
  var p=document.getElementById('pw').value,p2=document.getElementById('pw2').value,err=document.getElementById('err');
  if(p.length<8){e.preventDefault();err.textContent='Password must be at least 8 characters.';err.style.display='block';return;}
  if(p!==p2){e.preventDefault();err.textContent='Passwords do not match.';err.style.display='block';}
});
</script>
</body>
</html>`;

const ADMIN_PAGE = (users, companies, tab, msg) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — The Partnership Tree</title>
<link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Lato',sans-serif;background:#f5f5f0;min-height:100vh;padding:28px 24px;}
.container{max-width:1100px;margin:0 auto;}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;}
h1{font-size:22px;color:#1a3a2a;font-weight:900;}
.sub{font-size:12px;color:#6b7c6b;margin-top:2px;}
.logout{font-size:13px;color:#c0392b;font-weight:700;text-decoration:none;}
.tabs{display:flex;gap:0;margin-bottom:20px;border-bottom:2px solid #dde8de;}
.tab{padding:9px 22px;font-size:13px;font-weight:700;color:#6b7c6b;cursor:pointer;border-bottom:3px solid transparent;margin-bottom:-2px;text-decoration:none;background:none;border-top:none;border-left:none;border-right:none;font-family:inherit;display:inline-block;}
.tab.active{color:#1a3a2a;border-bottom-color:#c9a84c;}
.card{background:#fff;border-radius:12px;padding:22px;border:1.5px solid #dde8de;margin-bottom:18px;}
h2{font-size:14px;color:#1a3a2a;margin-bottom:16px;font-weight:700;}
label{font-size:11px;font-weight:700;color:#1a3a2a;letter-spacing:.06em;text-transform:uppercase;display:block;margin-bottom:4px;}
input[type=text],input[type=email],input[type=url],input[type=password],select,textarea{width:100%;padding:8px 11px;border:1.5px solid #dde8de;border-radius:7px;font-size:13px;font-family:inherit;color:#1a3a2a;outline:none;margin-bottom:10px;background:#fff;}
input[type=text]:focus,input[type=email]:focus,input[type=url]:focus,select:focus,textarea:focus{border-color:#c9a84c;}
textarea{resize:vertical;min-height:60px;}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.btn{padding:8px 16px;background:#1a3a2a;border:none;border-radius:7px;font-weight:700;font-size:12px;color:#fff;cursor:pointer;font-family:inherit;}
.btn:hover{opacity:.88;}
.btn-red{background:#c0392b;}
.btn-amber{background:#c9a84c;color:#1a3a2a;}
.btn-sm{padding:3px 9px;font-size:11px;}
.msg{padding:10px 14px;border-radius:7px;font-size:13px;font-weight:700;margin-bottom:14px;}
.msg-ok{background:#e8f5e9;color:#1a6b2a;}
.msg-err{background:#ffeaea;color:#c0392b;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{text-align:left;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#6b7c6b;padding:6px 10px;border-bottom:2px solid #dde8de;white-space:nowrap;}
td{padding:7px 10px;border-bottom:1px solid #f0f0ea;color:#1a3a2a;vertical-align:middle;}
tr:hover td{background:#fafafa;}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;}
.badge-green{background:#e8f5e9;color:#1a6b2a;}
.badge-red{background:#ffeaea;color:#c0392b;}
.badge-amber{background:#fff8e1;color:#8a6000;}
.trunc{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.pager{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:#6b7c6b;}
.pager a{color:#1a3a2a;font-weight:700;text-decoration:none;padding:3px 8px;border:1px solid #dde8de;border-radius:5px;}
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div><h1>🌿 Admin Console</h1><div class="sub">The Partnership Tree — Administration</div></div>
    <a href="/logout" class="logout">Log out</a>
  </div>

  ${msg ? `<div class="msg ${msg.ok ? 'msg-ok' : 'msg-err'}">${msg.text}</div>` : ''}

  <div class="tabs">
    <a href="/admin?tab=users" class="tab ${tab==='users'?'active':''}">👥 Users (${users.length})</a>
    <a href="/admin?tab=companies" class="tab ${tab==='companies'?'active':''}">🏢 Companies (${companies.total})</a>
    <a href="/admin?tab=add-company" class="tab ${tab==='add-company'?'active':''}">➕ Add Company</a>
    <a href="/admin?tab=applications" class="tab ${tab==='applications'?'active':''}">📋 Applications${companies.pendingApps>0?' <span style="background:#c0392b;color:#fff;font-size:10px;padding:1px 6px;border-radius:10px;margin-left:4px;">'+companies.pendingApps+'</span>':''}</a>
    <a href="/admin?tab=extract-locations" class="tab ${tab==='extract-locations'?'active':''}">📍 Extract Locations</a>
    <a href="/admin?tab=import-drug-delivery" class="tab ${tab==='import-drug-delivery'?'active':''}">💊 Import Drug Delivery</a>
  </div>

  ${tab === 'users' ? `
  <div class="card">
    <h2>Create New User</h2>
    <form method="POST" action="/admin/create-user">
      <div class="grid2">
        <div><label>Full Name *</label><input type="text" name="name" placeholder="Jane Smith" required/></div>
        <div><label>Company *</label><input type="text" name="company" placeholder="Pharma Co Ltd" required/></div>
      </div>
      <div class="grid2">
        <div><label>Email *</label><input type="email" name="email" placeholder="jane@pharma.com" required/></div>
        <div><label>Role</label><input type="text" name="role" placeholder="Head of Business Development"/></div>
      </div>
      <label>Temporary Password *</label>
      <input type="text" name="temp_password" placeholder="e.g. Welcome2025!" required/>
      <button type="submit" class="btn">Create User →</button>
    </form>
  </div>
  <div class="card">
    <h2>Current Users</h2>
    <table>
      <tr><th>Name</th><th>Company</th><th>Email</th><th>Role</th><th>Status</th><th>Password</th><th>Temp Password</th><th>Created</th><th></th></tr>
      ${users.map(u => `<tr>
        <td>${u.name}</td><td>${u.company}</td><td>${u.email}</td><td>${u.role||'—'}</td>
        <td><span class="badge ${u.active?'badge-green':'badge-red'}">${u.active?'Active':'Inactive'}</span></td>
        <td><span class="badge ${u.first_login?'badge-amber':'badge-green'}">${u.first_login?'Pending':'Set'}</span></td>
        <td>${u.first_login ? '<code style="background:#fff8e1;color:#8a6000;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700;">'+u.password_hash+'</code>' : '<span style="font-size:11px;color:#6b7c6b;">—</span>'}</td>
        <td>${u.created_at?u.created_at.substring(0,10):'—'}</td>
        <td><form method="POST" action="/admin/toggle-user" style="display:inline;">
          <input type="hidden" name="id" value="${u.id}"/>
          <input type="hidden" name="active" value="${u.active?0:1}"/>
          <button type="submit" class="btn btn-sm ${u.active?'btn-red':''}">${u.active?'Deactivate':'Activate'}</button>
        </form></td>
      </tr>`).join('')}
    </table>
  </div>
  ` : ''}

  ${tab === 'companies' ? `
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <h2 style="margin:0;">Company Catalogue &nbsp;<span style="font-weight:400;color:#6b7c6b;">${companies.active} active · ${companies.inactive} inactive</span></h2>
    </div>
    <form method="GET" action="/admin" style="display:flex;gap:10px;margin-bottom:14px;align-items:center;">
      <input type="hidden" name="tab" value="companies"/>
      <input type="text" name="q" value="${companies.q||''}" placeholder="Search by company name..." style="margin-bottom:0;flex:1;"/>
      <select name="filter" style="margin-bottom:0;width:130px;">
        <option value="all" ${companies.filter==='all'?'selected':''}>All status</option>
        <option value="active" ${companies.filter==='active'?'selected':''}>Active only</option>
        <option value="inactive" ${companies.filter==='inactive'?'selected':''}>Inactive only</option>
      </select>
      <button type="submit" class="btn">Search</button>
      ${companies.q ? `<a href="/admin?tab=companies" style="font-size:12px;color:#c0392b;font-weight:700;text-decoration:none;">✕ Clear</a>` : ''}
    </form>
    <table>
      <tr><th>ID</th><th>Company Name</th><th>Partnership Types</th><th>Website</th><th>Status</th><th>Actions</th></tr>
      ${companies.rows.map(c => {
        const types = [c.licence_in?'Lic IN':'',c.licence_out?'Lic OUT':'',c.distribution?'Distrib':'',c.research?'Research':''].filter(Boolean).join(' · ')||'—';
        return `<tr>
          <td style="color:#aaa;font-size:11px;">${c.id}</td>
          <td><strong>${c.company_name}</strong>${c.partnership_title?'<div style="font-size:10px;color:#6b7c6b;margin-top:1px;">'+c.partnership_title.substring(0,55)+'…</div>':''}</td>
          <td><span style="font-size:11px;color:#4a6a5a;">${types}</span></td>
          <td class="trunc">${c.website?'<a href="'+c.website+'" target="_blank" style="color:#c9a84c;font-size:11px;text-decoration:none;">🌐 '+c.website.replace(/https?:\/\//,'').substring(0,28)+'</a>':'—'}</td>
          <td><span class="badge ${c.status==='active'?'badge-green':'badge-red'}">${c.status}</span></td>
          <td style="display:flex;gap:5px;">
            <a href="/admin?tab=edit-company&id=${c.id}" class="btn btn-sm btn-amber">Edit</a>
            <form method="POST" action="/admin/toggle-company" style="display:inline;">
              <input type="hidden" name="id" value="${c.id}"/>
              <input type="hidden" name="status" value="${c.status==='active'?'inactive':'active'}"/>
              <input type="hidden" name="q" value="${companies.q||''}"/>
              <input type="hidden" name="filter" value="${companies.filter||'all'}"/>
              <button type="submit" class="btn btn-sm ${c.status==='active'?'btn-red':''}">${c.status==='active'?'Deactivate':'Activate'}</button>
            </form>
          </td>
        </tr>`;
      }).join('')}
    </table>
    <div class="pager">
      <span>Page ${companies.page} of ${companies.pages} &nbsp;·&nbsp; ${companies.filtered} result${companies.filtered!==1?'s':''}</span>
      ${companies.page>1?`<a href="/admin?tab=companies&q=${companies.q||''}&filter=${companies.filter}&page=${companies.page-1}">← Prev</a>`:''}
      ${companies.page<companies.pages?`<a href="/admin?tab=companies&q=${companies.q||''}&filter=${companies.filter}&page=${companies.page+1}">Next →</a>`:''}
    </div>
  </div>
  ` : ''}

  ${tab === 'applications' ? `
  <div class="card">
    <h2>Access Applications <span style="font-weight:400;color:#6b7c6b;font-size:13px;">${companies.applications.length} total</span></h2>
    ${companies.applications.length === 0 ? '<p style="font-size:13px;color:#6b7c6b;">No applications received yet.</p>' :
    '<table><tr><th>Name</th><th>Company</th><th>Email</th><th>Role</th><th>Interest</th><th>Date</th><th>Status</th><th></th></tr>' +
    companies.applications.map(a => {
      const badgeClass = a.status==='pending'?'badge-amber':a.status==='approved'?'badge-green':'badge-red';
      const actions = a.status==='pending'
        ? '<form method="POST" action="/admin/approve-application" style="display:inline;"><input type="hidden" name="id" value="'+a.id+'"/><input type="hidden" name="name" value="'+a.name+'"/><input type="hidden" name="company" value="'+a.company+'"/><input type="hidden" name="email" value="'+a.email+'"/><input type="hidden" name="role" value="'+(a.role||'')+'"/><button type="submit" class="btn btn-sm" style="background:#1a6b2a;">Approve →</button></form>'
          + '<form method="POST" action="/admin/reject-application" style="display:inline;"><input type="hidden" name="id" value="'+a.id+'"/><button type="submit" class="btn btn-sm btn-red" onclick="return confirm(\'Reject this application?\')">Reject</button></form>'
        : a.status==='approved'
          ? '<span style="font-size:11px;color:#1a6b2a;font-weight:700;">✓ User created</span>'
          : '<span style="font-size:11px;color:#c0392b;">✗ Rejected</span>';
      return '<tr>'
        + '<td><strong>'+a.name+'</strong></td>'
        + '<td>'+a.company+'</td>'
        + '<td><a href="mailto:'+a.email+'" style="color:var(--forest);font-weight:700;">'+a.email+'</a></td>'
        + '<td style="font-size:11px;color:#6b7c6b;">'+(a.role||'—')+'</td>'
        + '<td style="font-size:11px;color:#6b7c6b;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'+(a.interest||'').substring(0,60)+(a.interest&&a.interest.length>60?'…':'')+'</td>'
        + '<td style="font-size:11px;white-space:nowrap;">'+(a.created_at?a.created_at.substring(0,10):'—')+'</td>'
        + '<td><span class="badge '+badgeClass+'">'+a.status+'</span></td>'
        + '<td style="display:flex;gap:5px;flex-wrap:wrap;">'+actions+'</td>'
        + '</tr>';
    }).join('') + '</table>'
    }
  </div>
  ` : ''}

  ${tab === 'extract-locations' ? `
  <div class="card">
    <h2>📍 Extract Locations from Company Descriptions</h2>
    <p style="font-size:13px;color:#6b7c6b;line-height:1.7;margin-bottom:20px;">Uses Claude AI to read each company's description and extract their primary city/country, writing it to the <code>location</code> column. Processes in batches of 20.</p>
    <div style="background:#f0f8f0;border-radius:8px;padding:14px;margin-bottom:20px;font-size:13px;color:#1a6b2a;">
      <strong>First run this SQL in your D1 console if you haven't already:</strong><br>
      <code style="background:#fff;padding:6px 10px;border-radius:5px;display:inline-block;margin-top:8px;font-size:12px;color:#1a3a2a;user-select:all;">ALTER TABLE companies ADD COLUMN location TEXT DEFAULT '';</code>
    </div>
    <div id="loc-status" style="margin-bottom:16px;font-size:13px;color:#6b7c6b;">Ready. Click Start to begin.</div>
    <div style="background:#f5f5f0;border-radius:8px;padding:12px;margin-bottom:16px;font-size:11px;font-family:monospace;color:#1a3a2a;max-height:200px;overflow-y:auto;min-height:60px;" id="loc-log"></div>
    <div style="display:flex;gap:10px;align-items:center;">
      <button id="loc-btn" class="btn" onclick="startLocationExtraction()">Start Extraction →</button>
      <span id="loc-progress" style="font-size:12px;color:#6b7c6b;"></span>
    </div>
  </div>
  <script>
  async function startLocationExtraction() {
    const btn = document.getElementById('loc-btn');
    const status = document.getElementById('loc-status');
    const log = document.getElementById('loc-log');
    const progress = document.getElementById('loc-progress');
    btn.disabled = true; btn.textContent = 'Running...';
    log.innerHTML = '';
    try {
      const resp = await fetch('/admin/get-companies-no-location');
      const data = await resp.json();
      const companies = data.companies || [];
      status.textContent = 'Found ' + companies.length + ' companies without a location.';
      if (!companies.length) { status.textContent = '✓ All companies already have locations!'; btn.textContent = 'Done'; return; }

      // Process in batches of 5 (fetching real pages — be gentle on the server)
      const batchSize = 5;
      let totalUpdated = 0;
      for (let i = 0; i < companies.length; i += batchSize) {
        const batch = companies.slice(i, i + batchSize);
        const batchNum = Math.floor(i/batchSize)+1;
        const totalBatches = Math.ceil(companies.length/batchSize);
        progress.textContent = 'Batch ' + batchNum + ' of ' + totalBatches + ' (' + i + '/' + companies.length + ' companies)...';
        const r = await fetch('/admin/extract-locations', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ companies: batch })
        });
        const result = await r.json();
        totalUpdated += result.updated || 0;
        (result.results || []).forEach(function(res) {
          const co = batch.find(function(c){ return c.id === res.id; });
          const name = co ? co.company_name : res.id;
          log.innerHTML += (res.location ? '✓ ' : '— ') + name + (res.location ? ': ' + res.location : ' (no location found)') + '<br>';
        });
        log.scrollTop = log.scrollHeight;
        // Pause between batches to avoid rate limiting
        await new Promise(res => setTimeout(res, 1000));
      }

      status.textContent = '✓ Complete! Updated ' + totalUpdated + ' of ' + companies.length + ' companies.';
      progress.textContent = '';
      btn.textContent = 'Run Again'; btn.disabled = false;
    } catch(e) {
      status.textContent = 'Error: ' + e.message;
      btn.textContent = 'Retry'; btn.disabled = false;
    }
  }
  </script>
  ` : ''}

  ${tab === 'import-drug-delivery' ? `
  <div class="card">
    <h2>💊 Import Drug Delivery Companies</h2>
    <p style="font-size:13px;color:#6b7c6b;line-height:1.7;margin-bottom:16px;">Scrapes the Pharma Services Directory for companies with sector = Drug Delivery (371 companies across 8 pages) and imports those not already in D1. Each company's profile page is fetched to extract name, location, website and description.</p>
    <div style="background:#f0f8f0;border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#1a6b2a;">
      <strong>Already in D1:</strong> <span id="dd-existing">checking...</span> &nbsp;|&nbsp;
      <strong>To import:</strong> <span id="dd-new">—</span>
    </div>
    <div id="dd-status" style="margin-bottom:12px;font-size:13px;color:#6b7c6b;">Click Start to begin. This will take several minutes.</div>
    <div style="background:#f5f5f0;border-radius:8px;padding:12px;margin-bottom:14px;font-size:11px;font-family:monospace;color:#1a3a2a;max-height:220px;overflow-y:auto;min-height:60px;" id="dd-log"></div>
    <div style="display:flex;gap:10px;align-items:center;">
      <button id="dd-btn" class="btn" onclick="startDrugDeliveryImport()">Start Import →</button>
      <span id="dd-progress" style="font-size:12px;color:#6b7c6b;"></span>
    </div>
  </div>
  <script>
  // Check existing count on load
  fetch('/admin/dd-status').then(r=>r.json()).then(d=>{
    document.getElementById('dd-existing').textContent = d.existing + ' already in D1';
    document.getElementById('dd-new').textContent = d.toImport + ' new companies found';
  }).catch(()=>{ document.getElementById('dd-existing').textContent = 'error checking'; });

  async function startDrugDeliveryImport() {
    const btn = document.getElementById('dd-btn');
    const status = document.getElementById('dd-status');
    const log = document.getElementById('dd-log');
    const progress = document.getElementById('dd-progress');
    btn.disabled = true; btn.textContent = 'Running...';
    log.innerHTML = '';

    try {
      // Process 8 pages
      const offsets = [0, 50, 100, 150, 200, 250, 300, 350];
      let totalImported = 0;
      let totalSkipped = 0;

      for (let i = 0; i < offsets.length; i++) {
        const offset = offsets[i];
        progress.textContent = 'Page ' + (i+1) + ' of ' + offsets.length + ' (offset ' + offset + ')...';
        const r = await fetch('/admin/dd-import-page', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ offset })
        });
        const result = await r.json();
        totalImported += result.imported || 0;
        totalSkipped += result.skipped || 0;
        if (result.companies) {
          result.companies.forEach(c => {
            log.innerHTML += (c.imported ? '✓ ' : '— ') + c.name + (c.imported ? ' imported' : ' already exists') + '<br>';
          });
        }
        log.scrollTop = log.scrollHeight;
        // Pause between pages
        await new Promise(res => setTimeout(res, 1500));
      }

      status.textContent = '✓ Complete! Imported ' + totalImported + ' new companies. Skipped ' + totalSkipped + ' already in D1.';
      progress.textContent = '';
      btn.textContent = 'Run Again'; btn.disabled = false;
    } catch(e) {
      status.textContent = 'Error: ' + e.message;
      btn.textContent = 'Retry'; btn.disabled = false;
    }
  }
  </script>
  ` : ''}

  ${(tab==='add-company'||tab==='edit-company') ? `
  <div class="card">
    <h2>${tab==='edit-company'?`Edit: ${companies.editing?.company_name||'Company'}`:'Add New Company'}</h2>
    <form method="POST" action="/admin/${tab==='edit-company'?'update-company':'create-company'}">
      ${tab==='edit-company'?`<input type="hidden" name="id" value="${companies.editing?.id}"/>`:''}
      <div class="grid2">
        <div><label>Company Name *</label><input type="text" name="company_name" value="${companies.editing?.company_name||''}" required/></div>
        <div><label>Website</label><input type="url" name="website" value="${companies.editing?.website||''}" placeholder="https://"/></div>
      </div>
      <div class="grid2">
        <div><label>Directory URL (pharmaservicesdirectory.com)</label><input type="url" name="directory_url" value="${companies.editing?.directory_url||''}" placeholder="https://pharmaservicesdirectory.com/profile/..."/></div>
        <div><label>External Link</label><input type="url" name="external_link" value="${companies.editing?.external_link||''}" placeholder="https://"/></div>
      </div>
      <div><label>Company Description <span style="font-weight:400;color:#9b9b9b;">(full profile — used by AI for matching queries)</span></label><textarea name="description" rows="4">${companies.editing?.description||''}</textarea></div>
      <div><label>Partnership Title / Tagline</label><input type="text" name="partnership_title" value="${companies.editing?.partnership_title||''}" placeholder="e.g. Oral thin film CDMO seeking licensing partners"/></div>
      <div><label>Partnership Summary <span style="font-weight:400;color:#9b9b9b;">(short — shown in search result cards)</span></label><textarea name="summary" rows="2">${companies.editing?.summary||''}</textarea></div>
      <div><label>Contact Email</label><input type="email" name="contact_email" value="${companies.editing?.contact_email||''}" placeholder="partnerships@company.com"/></div>
      <div><label>Location <span style="font-weight:400;color:#9b9b9b;">(city, country — shown on result cards)</span></label><input type="text" name="location" value="${companies.editing?.location||''}" placeholder="e.g. Basel, Switzerland"/></div>
      <div style="margin-bottom:12px;">
        <label style="margin-bottom:8px;">Partnership Types Sought</label>
        <div style="display:flex;gap:24px;flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:7px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;cursor:pointer;"><input type="checkbox" name="licence_in" value="1" ${companies.editing?.licence_in?'checked':''} style="width:auto;margin:0;padding:0;border:none;"/> Licence IN</label>
          <label style="display:flex;align-items:center;gap:7px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;cursor:pointer;"><input type="checkbox" name="licence_out" value="1" ${companies.editing?.licence_out?'checked':''} style="width:auto;margin:0;padding:0;border:none;"/> Licence OUT</label>
          <label style="display:flex;align-items:center;gap:7px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;cursor:pointer;"><input type="checkbox" name="distribution" value="1" ${companies.editing?.distribution?'checked':''} style="width:auto;margin:0;padding:0;border:none;"/> Distribution</label>
          <label style="display:flex;align-items:center;gap:7px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;cursor:pointer;"><input type="checkbox" name="research" value="1" ${companies.editing?.research?'checked':''} style="width:auto;margin:0;padding:0;border:none;"/> Research Collaboration</label>
          <label style="display:flex;align-items:center;gap:7px;font-size:13px;text-transform:none;letter-spacing:0;font-weight:600;cursor:pointer;"><input type="checkbox" name="co_development" value="1" ${companies.editing?.co_development?'checked':''} style="width:auto;margin:0;padding:0;border:none;"/> Co-Development</label>
        </div>
      </div>
      <div style="margin-bottom:16px;"><label>Status</label>
        <select name="status" style="width:150px;margin-bottom:0;">
          <option value="active" ${(companies.editing?.status||'active')==='active'?'selected':''}>Active</option>
          <option value="inactive" ${companies.editing?.status==='inactive'?'selected':''}>Inactive</option>
        </select>
      </div>
      <div style="display:flex;align-items:center;gap:10px;">
        <button type="submit" class="btn">${tab==='edit-company'?'Save Changes →':'Add Company →'}</button>
        <a href="/admin?tab=companies" style="padding:8px 16px;border:1.5px solid #dde8de;border-radius:7px;font-size:12px;font-weight:700;color:#6b7c6b;text-decoration:none;">Cancel</a>
        ${tab==='edit-company'?`
        <form method="POST" action="/admin/delete-company" style="margin-left:auto;display:inline;">
          <input type="hidden" name="id" value="${companies.editing?.id}"/>
          <button type="submit" class="btn btn-red" onclick="return confirm('Permanently delete this company record? This cannot be undone.')">Delete Permanently</button>
        </form>`:''}
      </div>
    </form>
  </div>

  ${tab==='edit-company' && companies.editing ? `
  <div class="card">
    <h2>Partnership Opportunities <span style="font-weight:400;color:#6b7c6b;font-size:13px;">for ${companies.editing.company_name}</span></h2>
    <p style="font-size:13px;color:#6b7c6b;margin-bottom:16px;line-height:1.6;">Add specific partnership opportunities — each with its own title, type and description. These appear on the company's Partnerships tab.</p>

    ${companies.partnerships && companies.partnerships.length > 0 ? `
    <table style="margin-bottom:20px;">
      <tr><th>Title</th><th>Type</th><th>Status</th><th></th></tr>
      ${companies.partnerships.map(p => `<tr>
        <td><strong>${p.title}</strong>${p.description?'<div style="font-size:11px;color:#6b7c6b;margin-top:2px;">'+p.description.substring(0,80)+'…</div>':''}</td>
        <td><span class="badge badge-green" style="text-transform:capitalize;">${p.type.replace(/_/g,' ')}</span></td>
        <td><span class="badge ${p.status==='active'?'badge-green':'badge-red'}">${p.status}</span></td>
        <td style="display:flex;gap:5px;">
          <a href="/admin?tab=edit-partnership&pid=${p.id}&id=${companies.editing.id}" class="btn btn-sm btn-amber">Edit</a>
          <form method="POST" action="/admin/delete-partnership" style="display:inline;">
            <input type="hidden" name="pid" value="${p.id}"/>
            <input type="hidden" name="company_id" value="${companies.editing.id}"/>
            <button type="submit" class="btn btn-sm btn-red" onclick="return confirm('Delete this partnership opportunity?')">Delete</button>
          </form>
        </td>
      </tr>`).join('')}
    </table>` : '<p style="font-size:13px;color:#6b7c6b;margin-bottom:16px;">No partnership opportunities added yet.</p>'}

    <form method="POST" action="/admin/add-partnership" style="background:#f5f5f0;padding:16px;border-radius:8px;">
      <input type="hidden" name="company_id" value="${companies.editing.id}"/>
      <div style="font-size:12px;font-weight:700;color:#1a3a2a;margin-bottom:12px;letter-spacing:.04em;text-transform:uppercase;">${companies.editingPartnership ? 'Edit Opportunity' : 'Add New Opportunity'}</div>
      ${companies.editingPartnership ? `
      <form method="POST" action="/admin/update-partnership" style="background:#f5f5f0;padding:16px;border-radius:8px;">
        <input type="hidden" name="pid" value="${companies.editingPartnership.id}"/>
        <input type="hidden" name="company_id" value="${companies.editing.id}"/>
        <div class="grid2">
          <div><label>Title *</label><input type="text" name="title" value="${companies.editingPartnership.title||''}" required/></div>
          <div><label>Type</label>
            <select name="type" style="margin-bottom:0;">
              ${['licence_out','licence_in','co_development','distribution','research','manufacturing','other'].map(t => `<option value="${t}" ${companies.editingPartnership.type===t?'selected':''}>${t.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}</option>`).join('')}
            </select>
          </div>
        </div>
        <div><label>Description</label><textarea name="description" rows="3">${companies.editingPartnership.description||''}</textarea></div>
        <div style="margin-bottom:12px;"><label>Status</label>
          <select name="status" style="width:130px;margin-bottom:0;">
            <option value="active" ${companies.editingPartnership.status==='active'?'selected':''}>Active</option>
            <option value="inactive" ${companies.editingPartnership.status==='inactive'?'selected':''}>Inactive</option>
          </select>
        </div>
        <div style="display:flex;gap:8px;">
          <button type="submit" class="btn">Save Changes →</button>
          <a href="/admin?tab=edit-company&id=${companies.editing.id}" style="padding:8px 16px;border:1.5px solid #dde8de;border-radius:7px;font-size:12px;font-weight:700;color:#6b7c6b;text-decoration:none;">Cancel</a>
        </div>
      </form>` : `
      <div class="grid2">
        <div><label>Title *</label><input type="text" name="title" placeholder="e.g. Oral Thin Film Platform" required/></div>
        <div><label>Type</label>
          <select name="type" style="margin-bottom:0;">
            <option value="licence_out">Licence OUT</option>
            <option value="licence_in">Licence IN</option>
            <option value="co_development">Co-Development</option>
            <option value="distribution">Distribution</option>
            <option value="research">Research Collaboration</option>
            <option value="manufacturing">Contract Manufacturing</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>
      <div><label>Description</label><textarea name="description" rows="3" placeholder="Describe this specific partnership opportunity..."></textarea></div>
      <button type="submit" class="btn">Add Opportunity →</button>`}
    </form>
  </div>
  ` : ''}
  ` : ''}

</div>
</body>
</html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const JWT_SECRET = env.JWT_SECRET || 'pt-secret-change-this';

    if (method === 'OPTIONS') {
      return new Response(null, { headers: { 'Access-Control-Allow-Origin': 'https://app.thepartnershiptree.com', 'Access-Control-Allow-Methods': 'POST, GET, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Credentials': 'true' } });
    }

    if (url.hostname === 'www.app.thepartnershiptree.com') {
      return Response.redirect(url.href.replace('www.app.thepartnershiptree.com', 'app.thepartnershiptree.com'), 301);
    }

    if (path === '/sitemap.xml') return new Response(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://app.thepartnershiptree.com/</loc></url></urlset>`, { headers: { 'Content-Type': 'application/xml' } });
    if (path === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain' } });

    // ── Auth check endpoint (used by Pages worker) ──
    if (path === '/__auth') {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return new Response('Unauthorised', { status: 401 });
      return new Response('OK', { status: 200 });
    }

    // ── Login ──
    if (path === '/login' && method === 'GET') return htmlResponse(LOGIN_PAGE);

    if (path === '/login' && method === 'POST') {
      const form = await request.formData();
      const email = (form.get('email') || '').toLowerCase().trim();
      const password = form.get('password') || '';
      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND active = 1').bind(email).first();
      if (!user) return redirectToLogin(request, 'Invalid email or password.');
      const hashed = await hashPassword(password);
      if (user.password_hash !== hashed && user.password_hash !== password) return redirectToLogin(request, 'Invalid email or password.');
      const token = await createToken({ userId: user.id, email: user.email, name: user.name }, JWT_SECRET);
      return new Response(null, { status: 302, headers: { 'Set-Cookie': sessionCookie(token), 'Location': user.first_login ? '/set-password' : '/' } });
    }

    if (path === '/logout') {
      return new Response(null, {
        status: 302,
        headers: {
          'Set-Cookie': 'pt_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
          'Location': '/login'
        }
      });
    }

    // ── Set password ──
    if (path === '/set-password' && method === 'GET') {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return redirectToLogin(request, 'Please log in first.');
      return htmlResponse(SET_PASSWORD_PAGE);
    }

    if (path === '/set-password' && method === 'POST') {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return redirectToLogin(request, 'Please log in first.');
      const form = await request.formData();
      const password = form.get('password') || '';
      const confirm = form.get('confirm') || '';
      if (password.length < 8 || password !== confirm) return htmlResponse(SET_PASSWORD_PAGE);
      await env.DB.prepare('UPDATE users SET password_hash = ?, first_login = 0 WHERE id = ?').bind(await hashPassword(password), payload.userId).run();
      return new Response(null, { status: 302, headers: { 'Location': '/' } });
    }

    // ── Claude proxy ──
    if (path === '/claude' && method === 'POST') {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return new Response(JSON.stringify({ error: 'Unauthorised' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      const body = await request.json();
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify(body)
      });
      return new Response(await resp.text(), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    }

    // ── Fetch partnership opportunities for a company ──
    if (path === '/partnerships' && method === 'GET') {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return new Response(JSON.stringify({ error: 'Unauthorised' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      const companyId = parseInt(url.searchParams.get('company_id') || '0');
      if (!companyId) return new Response(JSON.stringify({ opportunities: [] }), { headers: { 'Content-Type': 'application/json' } });
      const { results } = await env.DB.prepare(
        "SELECT id, title, type, description FROM company_partnerships WHERE company_id = ? AND status = 'active' ORDER BY created_at DESC"
      ).bind(companyId).all();
      return new Response(JSON.stringify({ opportunities: results || [] }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // ── AI Search ──
    if (path === '/search' && method === 'POST') {
      const body = await request.json();

      // Fetch companies and their specific partnership opportunities together
      const { results: companies } = await env.DB.prepare(
        'SELECT id, company_name, partnership_title, summary, description, location, licence_in, licence_out, distribution, research FROM companies WHERE status = ? ORDER BY company_name ASC'
      ).bind('active').all();

      // Fetch all active partnership opportunities
      const { results: allOpps } = await env.DB.prepare(
        "SELECT company_id, title, type, description FROM company_partnerships WHERE status = 'active'"
      ).all();

      // Build a map of company_id → opportunities
      const oppMap = {};
      for (const op of (allOpps || [])) {
        if (!oppMap[op.company_id]) oppMap[op.company_id] = [];
        oppMap[op.company_id].push(`${op.title} (${op.type.replace(/_/g,' ')})`);
      }

      // Build compact company list — combine all available text for richest AI matching
      let companyList = '';
      for (const c of companies) {
        const types = [c.licence_in?'LI':'', c.licence_out?'LO':'', c.distribution?'D':'', c.research?'R':''].filter(Boolean).join('/') || 'P';
        const parts = [c.description, c.partnership_title, c.summary].filter(Boolean);
        if (oppMap[c.id]) parts.push('Opportunities: ' + oppMap[c.id].join('; '));
        const desc = parts.join(' | ').substring(0, 350);
        companyList += `${c.id}|${c.company_name}|[${types}]|${desc}\n`;
      }

      const systemPrompt = `You are an AI Partnership Consultant for The Partnership Tree. Match user queries to life sciences companies seeking partnerships.

COMPANIES (${companies.length} total, format: id|name|[types]|description, types: LI=licence-in LO=licence-out D=distribution R=research):
${companyList}

RULES:
1. STRICT primary capability matching only — exclude tangential matches
2. Order by relevance, strongest match first
3. Broad queries: up to 20 results. Specific queries: 2-8 genuine matches only

RESPOND with ONLY this JSON:
{"ids":[id1,id2],"summary":"1 short sentence on what was found.","match_reasons":{"id1":"Why this matches.","id2":"Why this matches."}}

Keep summary under 20 words. If no matches: {"ids":[],"summary":"brief note","match_reasons":{}}`;

      const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': env.ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 2048, system: systemPrompt, messages: body.messages })
      });
      const data = await aiResp.json();

      // Fetch full company data only for matched IDs
      try {
        const text = (data.content && data.content[0]) ? data.content[0].text : '';
        const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
        const ids = parsed.ids || [];

        // Fetch full details only for matched companies
        let matchedCompanies = [];
        if (ids.length > 0) {
          const placeholders = ids.map(() => '?').join(',');
          const { results: fullCompanies } = await env.DB.prepare(
            `SELECT id, company_name, website, directory_url, partnership_title, summary, description, location, licence_in, licence_out, distribution, research, contact_email, external_link FROM companies WHERE id IN (${placeholders})`
          ).bind(...ids).all();
          matchedCompanies = ids.map(id => {
            const c = fullCompanies.find(c => c.id === id);
            if (c && parsed.match_reasons?.[id]) c.match_reason = parsed.match_reasons[id];
            return c || null;
          }).filter(Boolean);
        }

        return new Response(JSON.stringify({ ...parsed, d1Companies: matchedCompanies }), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      } catch(e) {
        return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
      }
    }

    // ── Extract locations (admin batch job) ──
    if (path === '/admin/extract-locations' && method === 'POST') {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return new Response(JSON.stringify({ error: 'Unauthorised' }), { status: 401 });

      const body = await request.json();
      const { companies } = body; // array of {id, directory_url}

      let updated = 0;
      const results = [];

      for (const company of companies) {
        // Build the profile URL from the partnerships URL
        const profileUrl = company.directory_url
          ? company.directory_url.replace('/company_partnerships/', '/company_profile/')
          : null;

        if (!profileUrl) {
          results.push({ id: company.id, location: '', status: 'no_url' });
          continue;
        }

        try {
          const resp = await fetch(profileUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PartnershipTree/1.0)' }
          });
          const html = await resp.text();

          // Extract country — try multiple patterns from the directory HTML
          let country = '';

          // Pattern 1: <div class="strong">Country:&nbsp;</div>\n   Switzerland
          const countryMatch1 = html.match(/Country:&nbsp;<\/div>\s+([A-Za-z][A-Za-z\s\-]+?)(?:\s*<|\s*\n\s*\n)/);
          if (countryMatch1) country = countryMatch1[1].trim();

          // Pattern 2: <p>Country Name</p> directly under company name (short, title-cased)
          if (!country) {
            const countryMatch2 = html.match(/<h2>[^<]+<\/h2>\s*<p>([A-Z][A-Za-z\s\-]{2,40})<\/p>/);
            if (countryMatch2) country = countryMatch2[1].trim();
          }

          // Extract city from address — all on one line with extra spaces
          let city = '';
          const addrLineMatch = html.match(/Address:&nbsp;<\/div>\s*\n\s*([^\n<]+)/);
          if (addrLineMatch) {
            const addr = addrLineMatch[1].replace(/\s+/g, ' ').trim();
            const parts = addr.split(',').map(p => p.trim()).filter(Boolean);
            // parts[0] = street, parts[1] = town, parts[2] = postcode
            if (parts.length >= 2) city = parts[1].trim();
          }

          // Build location string — prefer City, Country; fall back to Country only
          const location = city && country ? city + ', ' + country
            : country || city || '';

          if (location) {
            await env.DB.prepare('UPDATE companies SET location = ? WHERE id = ?')
              .bind(location, company.id).run();
            updated++;
          }
          results.push({ id: company.id, location, status: 'ok' });

        } catch(e) {
          results.push({ id: company.id, location: '', status: 'error: ' + e.message });
        }

        // Small delay to avoid hammering the directory server
        await new Promise(res => setTimeout(res, 200));
      }

      return new Response(JSON.stringify({ ok: true, updated, results }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // ── Public application submission ──
    if (path === '/apply' && method === 'POST') {
      const body = await request.json();
      const { name, company, email, role, interest } = body;
      if (!name || !company || !email || !interest) {
        return new Response(JSON.stringify({ error: 'Missing required fields.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      // Check for duplicate application
      const existing = await env.DB.prepare("SELECT id FROM applications WHERE email = ? AND status = 'pending'").bind(email.toLowerCase().trim()).first();
      if (existing) {
        return new Response(JSON.stringify({ error: 'An application from this email is already pending review.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      await env.DB.prepare('INSERT INTO applications (name, company, email, role, interest, status) VALUES (?,?,?,?,?,?)')
        .bind(name.trim(), company.trim(), email.toLowerCase().trim(), role||'', interest.trim(), 'pending').run();
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // ── Admin ──
    if (path.startsWith('/admin')) {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return redirectToLogin(request, 'Please log in to access admin.');

      const tab = url.searchParams.get('tab') || 'users';
      const q = (url.searchParams.get('q') || '').replace(/'/g, "''");
      const filter = url.searchParams.get('filter') || 'all';
      const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
      const perPage = 50;

      const buildPage = async (overrideTab, msg, editId) => {
        const { results: users } = await env.DB.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
        const stats = await env.DB.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active FROM companies").first();
        let where = filter==='active' ? "status='active'" : filter==='inactive' ? "status='inactive'" : "1=1";
        if (q) where += ` AND company_name LIKE '%${q}%'`;
        const cnt = await env.DB.prepare(`SELECT COUNT(*) as n FROM companies WHERE ${where}`).first();
        const filtered = cnt?.n || 0;
        const pages = Math.max(1, Math.ceil(filtered / perPage));
        const { results: rows } = await env.DB.prepare(
          `SELECT id, company_name, website, partnership_title, location, licence_in, licence_out, distribution, research, status FROM companies WHERE ${where} ORDER BY company_name ASC LIMIT ${perPage} OFFSET ${(page-1)*perPage}`
        ).all();
        let editing = null;
        let partnerships = [];
        if (editId) {
          editing = await env.DB.prepare('SELECT * FROM companies WHERE id = ?').bind(editId).first();
          const { results: ps } = await env.DB.prepare('SELECT * FROM company_partnerships WHERE company_id = ? ORDER BY created_at DESC').bind(editId).all();
          partnerships = ps || [];
        }
        // Fetch applications (table may not exist yet)
        let applications = [];
        let pendingApps = 0;
        try {
          const { results: apps } = await env.DB.prepare('SELECT * FROM applications ORDER BY created_at DESC').all();
          applications = apps || [];
          pendingApps = applications.filter(a => a.status === 'pending').length;
        } catch(e) {
          // applications table doesn't exist yet
        }
        return htmlResponse(ADMIN_PAGE(users, { total: stats?.total||0, active: stats?.active||0, inactive: (stats?.total||0)-(stats?.active||0), rows, q, filter, page, pages, filtered, editing, partnerships, applications, pendingApps }, overrideTab||tab, msg));
      };

      // ── GET: drug delivery diagnostic ──
      if (path === '/admin/dd-debug' && method === 'GET') {
        const baseUrl = 'https://www.pharmaservicesdirectory.com';
        const listUrl = `${baseUrl}/companies/index/list/created/desc/all/all/49/all/all/all/all/all/0`;
        const resp = await fetch(listUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PartnershipTree/1.0)' } });
        const html = await resp.text();
        // Try multiple link patterns
        const pat1 = [...html.matchAll(/href="(\/profile\/company_profile\/(\d+)\/([^"]+))"/g)].length;
        const pat2 = [...html.matchAll(/href="(\/profile\/company_partnerships\/(\d+)\/([^"]+))"/g)].length;
        const pat3 = [...html.matchAll(/href="([^"]*company[^"]*)">/g)].length;
        // Show first 2000 chars of HTML
        const snippet = html.substring(0, 2000);
        return new Response(JSON.stringify({ pat1, pat2, pat3, snippet, status: resp.status }), { headers: { 'Content-Type': 'application/json' } });
      }

      // ── GET: drug delivery status ──
      if (path === '/admin/dd-status' && method === 'GET') {
        const { results: existing } = await env.DB.prepare(
          "SELECT directory_url FROM companies WHERE directory_url LIKE '%pharmaservicesdirectory.com%'"
        ).all();
        const existingUrls = new Set((existing || []).map(c => c.directory_url));
        try {
          const resp = await fetch('https://www.pharmaservicesdirectory.com/companies/index/list/created/desc/all/all/49/all/all/all/all/all/0', {
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PartnershipTree/1.0)' }
          });
          const html = await resp.text();
          const matches = [...html.matchAll(/href="(\/profile\/company_profile\/(\d+)\/[^"]+)"/g)];
          const toImport = matches.filter(m => {
            const url = 'https://www.pharmaservicesdirectory.com' + m[1];
            const partnerUrl = url.replace('company_profile', 'company_partnerships');
            return !existingUrls.has(url) && !existingUrls.has(partnerUrl);
          }).length;
          return new Response(JSON.stringify({ existing: existingUrls.size, toImport }), { headers: { 'Content-Type': 'application/json' } });
        } catch(e) {
          return new Response(JSON.stringify({ existing: existingUrls.size, toImport: '?' }), { headers: { 'Content-Type': 'application/json' } });
        }
      }

      // ── POST: import one page of drug delivery companies ──
      if (path === '/admin/dd-import-page' && method === 'POST') {
        const body = await request.json();
        const offset = body.offset || 0;
        const baseUrl = 'https://www.pharmaservicesdirectory.com';
        const listUrl = `${baseUrl}/companies/index/list/created/desc/all/all/49/all/all/all/all/all/${offset}`;

        const listResp = await fetch(listUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PartnershipTree/1.0)' } });
        const listHtml = await listResp.text();

        // Extract unique company profile URLs from the listing page
        const profileLinks = [...listHtml.matchAll(/href="(\/profile\/company_profile\/(\d+)\/([^"]+))"/g)];
        const uniqueLinks = [];
        const seen = new Set();
        for (const m of profileLinks) {
          if (!seen.has(m[2])) { seen.add(m[2]); uniqueLinks.push({ path: m[1], id: m[2], slug: m[3] }); }
        }

        // Get existing D1 directory URLs
        const { results: existingRows } = await env.DB.prepare(
          "SELECT directory_url FROM companies WHERE directory_url LIKE '%pharmaservicesdirectory.com%'"
        ).all();
        const existingUrls = new Set((existingRows || []).map(c => c.directory_url));

        const results = [];
        let imported = 0, skipped = 0;

        for (const link of uniqueLinks) {
          const profileUrl = baseUrl + link.path;
          const partnerUrl = profileUrl.replace('company_profile', 'company_partnerships');

          if (existingUrls.has(profileUrl) || existingUrls.has(partnerUrl)) {
            results.push({ name: link.slug.replace(/-/g,' '), imported: false });
            skipped++; continue;
          }

          try {
            await new Promise(res => setTimeout(res, 300));
            const profResp = await fetch(profileUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PartnershipTree/1.0)' } });
            const html = await profResp.text();

            // Extract name
            const nameMatch = html.match(/<h2>([^<]+)<\/h2>/);
            const company_name = nameMatch ? nameMatch[1].trim() : link.slug.replace(/-/g,' ');

            // Extract country
            let country = '';
            const cm1 = html.match(/Country:&nbsp;<\/div>\s+([A-Za-z][A-Za-z\s\-]+?)(?:\s*<)/);
            if (cm1) country = cm1[1].trim();
            if (!country) { const cm2 = html.match(/<h2>[^<]+<\/h2>\s*<p>([A-Z][A-Za-z\s\-]{2,40})<\/p>/); if (cm2) country = cm2[1].trim(); }

            // Extract city
            let city = '';
            const am = html.match(/Address:&nbsp;<\/div>\s*\n\s*([^\n<]+)/);
            if (am) { const parts = am[1].replace(/\s+/g,' ').trim().split(',').map(p=>p.trim()); if (parts.length>=2) city = parts[1]; }
            const location = city && country ? city+', '+country : country||city||'';

            // Extract description from activities
            let description = '';
            const dm = html.match(/Company Activities[\s\S]{0,300}<p><span>([^<]{20,})<\/span><\/p>/);
            if (dm) description = dm[1].trim();

            await env.DB.prepare(
              'INSERT INTO companies (company_name, directory_url, location, description, summary, status) VALUES (?,?,?,?,?,?)'
            ).bind(company_name, profileUrl, location, description, description.substring(0,200), 'active').run();

            results.push({ name: company_name, imported: true });
            imported++;
          } catch(e) {
            results.push({ name: link.slug.replace(/-/g,' '), imported: false });
          }
        }

        return new Response(JSON.stringify({ imported, skipped, companies: results }), { headers: { 'Content-Type': 'application/json' } });
      }

      // GET: companies without location (for extraction tool)
      if (path === '/admin/get-companies-no-location' && method === 'GET') {
        const { results } = await env.DB.prepare(
          "SELECT id, company_name, directory_url FROM companies WHERE status='active' AND (location IS NULL OR location='') AND directory_url != '' ORDER BY id ASC"
        ).all();
        return new Response(JSON.stringify({ companies: results || [] }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (method === 'GET') {
        const editId = (tab==='edit-company' || tab==='edit-partnership') ? parseInt(url.searchParams.get('id')||'0') : null;
        if (tab === 'edit-partnership') {
          const pid = parseInt(url.searchParams.get('pid')||'0');
          const p = await env.DB.prepare('SELECT * FROM company_partnerships WHERE id = ?').bind(pid).first();
          const co = await env.DB.prepare('SELECT * FROM companies WHERE id = ?').bind(editId).first();
          const { results: ps } = await env.DB.prepare('SELECT * FROM company_partnerships WHERE company_id = ? ORDER BY created_at DESC').bind(editId).all();
          const { results: users } = await env.DB.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
          const stats = await env.DB.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active FROM companies").first();
          return htmlResponse(ADMIN_PAGE(users, { total: stats?.total||0, active: stats?.active||0, inactive: (stats?.total||0)-(stats?.active||0), rows: [], q, filter, page, pages: 1, filtered: 0, editing: co, partnerships: ps||[], editingPartnership: p }, 'edit-company', null));
        }
        return buildPage(tab, null, editId);
      }

      // ── POST: approve application → create user ──
      if (path === '/admin/approve-application') {
        const f = await request.formData();
        const id = f.get('id');
        const name = f.get('name') || '';
        const company = f.get('company') || '';
        const email = f.get('email') || '';
        const role = f.get('role') || '';
        const tempPass = 'PT' + Math.random().toString(36).substring(2,8).toUpperCase();
        try {
          await env.DB.prepare('INSERT INTO users (email, password_hash, name, company, role, first_login, active) VALUES (?,?,?,?,?,1,1)')
            .bind(email, tempPass, name, company, role).run();
          await env.DB.prepare("UPDATE applications SET status='approved' WHERE id=?").bind(id).run();
          const approvalMsg = {
            ok: true,
            text: `✓ Application approved — user account created.<br><strong>Email:</strong> ${email} &nbsp;|&nbsp; <strong>Temporary password:</strong> <code style="background:#fff;padding:2px 8px;border-radius:4px;font-weight:700;">${tempPass}</code><br><span style="font-size:12px;">Send these credentials to the applicant. They will be prompted to set a new password on first login.</span>`
          };
          return buildPage('applications', approvalMsg, null);
        } catch(e) {
          return buildPage('applications', { ok: false, text: 'Error: could not create user. Email may already exist.' }, null);
        }
      }

      // ── POST: reject application ──
      if (path === '/admin/reject-application') {
        const f = await request.formData();
        await env.DB.prepare("UPDATE applications SET status='rejected' WHERE id=?").bind(f.get('id')).run();
        return new Response(null, { status: 302, headers: { 'Location': '/admin?tab=applications' } });
      }

      // ── POST: add partnership opportunity ──
      if (path === '/admin/add-partnership') {
        const f = await request.formData();
        const company_id = parseInt(f.get('company_id')||'0');
        await env.DB.prepare('INSERT INTO company_partnerships (company_id, title, type, description, status) VALUES (?,?,?,?,?)')
          .bind(company_id, f.get('title')||'', f.get('type')||'licence_out', f.get('description')||'', 'active').run();
        return new Response(null, { status: 302, headers: { 'Location': `/admin?tab=edit-company&id=${company_id}` } });
      }

      // ── POST: update partnership opportunity ──
      if (path === '/admin/update-partnership') {
        const f = await request.formData();
        const pid = f.get('pid');
        const company_id = f.get('company_id');
        await env.DB.prepare('UPDATE company_partnerships SET title=?, type=?, description=?, status=? WHERE id=?')
          .bind(f.get('title')||'', f.get('type')||'licence_out', f.get('description')||'', f.get('status')||'active', pid).run();
        return new Response(null, { status: 302, headers: { 'Location': `/admin?tab=edit-company&id=${company_id}` } });
      }

      // ── POST: delete partnership opportunity ──
      if (path === '/admin/delete-partnership') {
        const f = await request.formData();
        await env.DB.prepare('DELETE FROM company_partnerships WHERE id=?').bind(f.get('pid')).run();
        return new Response(null, { status: 302, headers: { 'Location': `/admin?tab=edit-company&id=${f.get('company_id')}` } });
      }

      // POST handlers
      if (path === '/admin/create-user') {
        const f = await request.formData();
        try { await env.DB.prepare('INSERT INTO users (email,password_hash,name,company,role,first_login,active) VALUES (?,?,?,?,?,1,1)').bind((f.get('email')||'').toLowerCase().trim(), f.get('temp_password')||'', f.get('name')||'', f.get('company')||'', f.get('role')||'').run(); } catch(e) {}
        return new Response(null, { status: 302, headers: { 'Location': '/admin?tab=users' } });
      }

      if (path === '/admin/toggle-user') {
        const f = await request.formData();
        await env.DB.prepare('UPDATE users SET active=? WHERE id=?').bind(f.get('active'), f.get('id')).run();
        return new Response(null, { status: 302, headers: { 'Location': '/admin?tab=users' } });
      }

      if (path === '/admin/create-company') {
        const f = await request.formData();
        try {
          await env.DB.prepare('INSERT INTO companies (company_name,website,directory_url,external_link,partnership_title,summary,description,contact_email,location,licence_in,licence_out,distribution,research,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(f.get('company_name')||'', f.get('website')||'', f.get('directory_url')||'', f.get('external_link')||'', f.get('partnership_title')||'', f.get('summary')||'', f.get('description')||'', f.get('contact_email')||'', f.get('location')||'', f.get('licence_in')?1:0, f.get('licence_out')?1:0, f.get('distribution')?1:0, f.get('research')?1:0, f.get('status')||'active').run();
          return new Response(null, { status: 302, headers: { 'Location': '/admin?tab=companies' } });
        } catch(e) {
          return new Response(null, { status: 302, headers: { 'Location': '/admin?tab=add-company' } });
        }
      }

      if (path === '/admin/update-company') {
        const f = await request.formData();
        const id = f.get('id');
        await env.DB.prepare('UPDATE companies SET company_name=?,website=?,directory_url=?,external_link=?,partnership_title=?,summary=?,description=?,contact_email=?,location=?,licence_in=?,licence_out=?,distribution=?,research=?,co_development=?,status=? WHERE id=?')
          .bind(f.get('company_name')||'', f.get('website')||'', f.get('directory_url')||'', f.get('external_link')||'', f.get('partnership_title')||'', f.get('summary')||'', f.get('description')||'', f.get('contact_email')||'', f.get('location')||'', f.get('licence_in')?1:0, f.get('licence_out')?1:0, f.get('distribution')?1:0, f.get('research')?1:0, f.get('co_development')?1:0, f.get('status')||'active', id).run();
        return new Response(null, { status: 302, headers: { 'Location': '/admin?tab=companies' } });
      }

      if (path === '/admin/toggle-company') {
        const f = await request.formData();
        await env.DB.prepare('UPDATE companies SET status=? WHERE id=?').bind(f.get('status'), f.get('id')).run();
        return new Response(null, { status: 302, headers: { 'Location': `/admin?tab=companies&q=${f.get('q')||''}&filter=${f.get('filter')||'all'}` } });
      }

      if (path === '/admin/delete-company') {
        const f = await request.formData();
        await env.DB.prepare('DELETE FROM companies WHERE id=?').bind(f.get('id')).run();
        return new Response(null, { status: 302, headers: { 'Location': '/admin?tab=companies' } });
      }
    }

    // ── Protected main app ──
    if (path === '/' || path === '/index.html' || path === '') {
      const payload = await verifyToken(getToken(request) || '', JWT_SECRET);
      if (!payload) return redirectToLogin(request);
      const user = await env.DB.prepare('SELECT first_login FROM users WHERE id=?').bind(payload.userId).first();
      if (user?.first_login) return new Response(null, { status: 302, headers: { 'Location': '/set-password' } });
    }

    // ── Serve static assets from Pages ──
    const pagesUrl = 'https://partnershiptree-dev.pages.dev' + url.pathname + url.search;
    return fetch(pagesUrl, { headers: request.headers });
  }
}
