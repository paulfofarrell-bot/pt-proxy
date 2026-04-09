async function hashPassword(password) { 
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createToken(payload, secret) {
  const header = btoa(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const body = btoa(JSON.stringify({...payload, exp: Math.floor(Date.now()/1000) + 604800}));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  return `${data}.${sigB64}`;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if(parts.length !== 3) return null;
    const data = `${parts[0]}.${parts[1]}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['verify']);
    const sig = Uint8Array.from(atob(parts[2].replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(data));
    if(!valid) return null;
    const payload = JSON.parse(atob(parts[1]));
    if(payload.exp < Math.floor(Date.now()/1000)) return null;
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

function redirectTo(url, clearCookie) {
  const headers = {'Location': url};
  if(clearCookie) headers['Set-Cookie'] = 'pt_session=; Path=/; HttpOnly; Secure; Max-Age=0';
  return new Response(null, {status:302, headers});
}

function html(content, status=200, extraHeaders={}) {
  return new Response(content, {status, headers:{'Content-Type':'text/html;charset=utf-8',...extraHeaders}});
}

const STYLES = `
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Lato',sans-serif;background:#0f2318;min-height:100vh;display:flex;align-items:center;justify-content:center;}
.card{background:#fff;border-radius:16px;padding:48px;width:100%;max-width:420px;box-shadow:0 24px 80px rgba(0,0,0,0.4);}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;}
.logo-text{font-size:18px;color:#1a3a2a;font-weight:700;letter-spacing:-.01em;}
.logo-sub{font-size:10px;color:#6b7c6b;letter-spacing:.06em;text-transform:uppercase;margin-top:1px;}
h1{font-size:24px;color:#1a3a2a;margin-bottom:8px;font-weight:700;}
p{font-size:14px;color:#6b7c6b;margin-bottom:28px;line-height:1.6;}
label{font-size:11px;font-weight:700;color:#1a3a2a;letter-spacing:.06em;text-transform:uppercase;display:block;margin-bottom:6px;}
input{width:100%;padding:12px 14px;border:1.5px solid #dde8de;border-radius:8px;font-size:14px;font-family:inherit;color:#1a3a2a;outline:none;margin-bottom:16px;}
input:focus{border-color:#c9a84c;}
.btn{width:100%;padding:14px;background:#1a3a2a;border:none;border-radius:8px;font-weight:800;font-size:15px;color:#fff;cursor:pointer;font-family:inherit;letter-spacing:.04em;}
.btn:hover{background:#0f2318;}
.error{background:#ffeaea;color:#c0392b;padding:12px;border-radius:8px;font-size:13px;font-weight:700;margin-bottom:20px;}
.notice{background:#f0f8f0;color:#1a6b2a;padding:14px;border-radius:8px;font-size:13px;margin-bottom:24px;line-height:1.6;}
.footer{margin-top:24px;text-align:center;font-size:12px;color:#6b7c6b;}
.footer a{color:#1a3a2a;font-weight:700;text-decoration:none;}
`;

const LOGO_SVG = `<svg width="36" height="36" viewBox="0 0 36 36" fill="none"><circle cx="18" cy="18" r="18" fill="#1a3a2a"/><path d="M18 8C18 8 10 14 10 20c0 4.4 3.6 8 8 8s8-3.6 8-8c0-6-8-12-8-12z" fill="#c9a84c" opacity=".9"/></svg>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const JWT_SECRET = env.JWT_SECRET || 'pt-fallback-secret';
    const MAIN_SITE = 'https://partnershiptree-dev.pages.dev';

    // ── CORS preflight ──
    if (method === 'OPTIONS') {
      return new Response(null, {headers:{
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }});
    }

    // ── Claude API proxy (requires valid session) ──
    if (path === '/' && method === 'POST') {
      const bearerToken = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
      const token = bearerToken || getToken(request);
      const payload = token ? await verifyToken(token, JWT_SECRET) : null;
      if (!payload) {
        return new Response(JSON.stringify({error:'Unauthorised'}), {status:401, headers:{'Content-Type':'application/json','Access-Control-Allow-Origin':'*'}});
      }
      const body = await request.json();
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify(body)
      });
      const data = await response.json();
      return new Response(JSON.stringify(data), {
        headers: {'Content-Type':'application/json','Access-Control-Allow-Origin':'*'}
      });
    }

    // ── Login page GET ──
    if (path === '/login' && method === 'GET') {
      const error = url.searchParams.get('error') || '';
      return html(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login — The Partnership Tree</title><link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" rel="stylesheet"><style>${STYLES}</style></head><body><div class="card"><div class="logo">${LOGO_SVG}<div><div class="logo-text">The Partnership Tree</div><div class="logo-sub">Life Science Partner Network</div></div></div><h1>Welcome back</h1><p>Sign in to access the partner search platform.</p>${error ? \`<div class="error">\${error}</div>\` : ''}<form method="POST" action="https://pt-proxy.paulf-ofarrell.workers.dev/login"><label>Email address</label><input type="email" name="email" placeholder="your@company.com" required autofocus/><label>Password</label><input type="password" name="password" placeholder="Your password" required/><button type="submit" class="btn">Sign In →</button></form><div class="footer">Need access? <a href="${MAIN_SITE}">Request a demo</a></div></div></body></html>`);
    }

    // ── Login POST ──
    if (path === '/login' && method === 'POST') {
      const form = await request.formData();
      const email = (form.get('email') || '').toLowerCase().trim();
      const password = form.get('password') || '';

      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND active = 1').bind(email).first();

      if (!user) {
        return redirectTo('/login?error=Invalid+email+or+password.');
      }

      const hashed = await hashPassword(password);
      const validHash = user.password_hash === hashed;
      const validTemp = user.password_hash === password;

      if (!validHash && !validTemp) {
        return redirectTo('/login?error=Invalid+email+or+password.');
      }

      const token = await createToken({userId: user.id, email: user.email, name: user.name}, JWT_SECRET);

      const dest = user.first_login ? '/set-password' : MAIN_SITE + '?pt_token=' + token;
      return new Response(null, {
        status: 302,
        headers: {
          'Set-Cookie': \`pt_session=\${token}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=604800; Domain=.paulf-ofarrell.workers.dev\`,
          'Location': dest
        }
      });
    }

    // ── Set password GET ──
    if (path === '/set-password' && method === 'GET') {
      const token = getToken(request);
      const payload = token ? await verifyToken(token, JWT_SECRET) : null;
      if (!payload) return redirectTo('/login?error=Please+log+in+first.');
      return html(\`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Set Password — The Partnership Tree</title><link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" rel="stylesheet"><style>\${STYLES}</style></head><body><div class="card"><div class="logo">\${LOGO_SVG}<div><div class="logo-text">The Partnership Tree</div><div class="logo-sub">Life Science Partner Network</div></div></div><h1>Set your password</h1><div class="notice">Welcome! This is your first login. Please set a personal password to secure your account.</div><div class="error" id="err" style="display:none"></div><form method="POST" action="https://pt-proxy.paulf-ofarrell.workers.dev/set-password"><label>New password</label><input type="password" name="password" id="pw" placeholder="Minimum 8 characters" required/><label>Confirm password</label><input type="password" name="confirm" id="pw2" placeholder="Repeat your password" required/><button type="submit" class="btn">Set Password & Continue →</button></form></div><script>document.querySelector('form').addEventListener('submit',function(e){var p=document.getElementById('pw').value,p2=document.getElementById('pw2').value,err=document.getElementById('err');if(p.length<8){e.preventDefault();err.textContent='Password must be at least 8 characters.';err.style.display='block';}else if(p!==p2){e.preventDefault();err.textContent='Passwords do not match.';err.style.display='block';}});</script></body></html>\`);
    }

    // ── Set password POST ──
    if (path === '/set-password' && method === 'POST') {
      const token = getToken(request);
      const payload = token ? await verifyToken(token, JWT_SECRET) : null;
      if (!payload) return redirectTo('/login?error=Please+log+in+first.');

      const form = await request.formData();
      const password = form.get('password') || '';
      const confirm = form.get('confirm') || '';

      if (password.length < 8 || password !== confirm) {
        return redirectTo('/set-password?error=Invalid+password.');
      }

      const hashed = await hashPassword(password);
      await env.DB.prepare('UPDATE users SET password_hash = ?, first_login = 0 WHERE id = ?').bind(hashed, payload.userId).run();

      return new Response(null, {
        status: 302,
        headers: {'Location': MAIN_SITE}
      });
    }

    // ── Logout ──
    if (path === '/logout') {
      return new Response(null, {
        status: 302,
        headers: {
          'Set-Cookie': 'pt_session=; Path=/; HttpOnly; Secure; Max-Age=0',
          'Location': '/login'
        }
      });
    }

    // ── Admin ──
    if (path === '/admin' && method === 'GET') {
      const token = getToken(request);
      const payload = token ? await verifyToken(token, JWT_SECRET) : null;
      if (!payload) return redirectTo('/login?error=Please+log+in+to+access+admin.');

      const { results } = await env.DB.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
      const users = results || [];

      return html(\`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin — The Partnership Tree</title><link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:'Lato',sans-serif;background:#f5f5f0;min-height:100vh;padding:40px 24px;}.container{max-width:960px;margin:0 auto;}h1{font-size:22px;color:#1a3a2a;margin-bottom:4px;font-weight:900;}.sub{font-size:13px;color:#6b7c6b;margin-bottom:28px;}.card{background:#fff;border-radius:12px;padding:28px;border:1.5px solid #dde8de;margin-bottom:24px;}h2{font-size:15px;color:#1a3a2a;margin-bottom:18px;font-weight:700;}label{font-size:11px;font-weight:700;color:#1a3a2a;letter-spacing:.06em;text-transform:uppercase;display:block;margin-bottom:5px;}input{width:100%;padding:10px 12px;border:1.5px solid #dde8de;border-radius:7px;font-size:13px;font-family:inherit;color:#1a3a2a;outline:none;margin-bottom:12px;}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}.btn{padding:10px 20px;background:#1a3a2a;border:none;border-radius:7px;font-weight:700;font-size:13px;color:#fff;cursor:pointer;font-family:inherit;}.btn-red{background:#c0392b;}table{width:100%;border-collapse:collapse;font-size:13px;}th{text-align:left;font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#6b7c6b;padding:8px 12px;border-bottom:2px solid #dde8de;}td{padding:10px 12px;border-bottom:1px solid #f0f0ea;color:#1a3a2a;vertical-align:middle;}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;}.bg{background:#e8f5e9;color:#1a6b2a;}.br{background:#ffeaea;color:#c0392b;}.ba{background:#fff8e1;color:#8a6000;}.logout{color:#c0392b;font-weight:700;text-decoration:none;font-size:13px;}</style></head><body><div class="container"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;"><h1>Platform Admin</h1><a href="https://pt-proxy.paulf-ofarrell.workers.dev/logout" class="logout">Log out</a></div><div class="sub">The Partnership Tree — User Management</div><div class="card"><h2>Create New User</h2><form method="POST" action="https://pt-proxy.paulf-ofarrell.workers.dev/admin/create-user"><div class="grid"><div><label>Full Name *</label><input type="text" name="name" placeholder="Jane Smith" required/></div><div><label>Company *</label><input type="text" name="company" placeholder="Pharma Co" required/></div></div><div class="grid"><div><label>Email *</label><input type="email" name="email" placeholder="jane@pharma.com" required/></div><div><label>Role</label><input type="text" name="role" placeholder="Head of BD"/></div></div><label>Temporary Password *</label><input type="text" name="temp_password" placeholder="e.g. Welcome2025" required style="margin-bottom:16px;"/><button type="submit" class="btn">Create User →</button></form></div><div class="card"><h2>Users (\${users.length})</h2><table><tr><th>Name</th><th>Company</th><th>Email</th><th>Status</th><th>Password</th><th>Created</th><th></th></tr>\${users.map(u=>\`<tr><td>\${u.name}</td><td>\${u.company}</td><td>\${u.email}</td><td><span class="badge \${u.active?'bg':'br'}">\${u.active?'Active':'Inactive'}</span></td><td><span class="badge \${u.first_login?'ba':'bg'}">\${u.first_login?'Temp':'Set'}</span></td><td>\${(u.created_at||'').substring(0,10)}</td><td><form method="POST" action="https://pt-proxy.paulf-ofarrell.workers.dev/admin/toggle-user" style="display:inline"><input type="hidden" name="id" value="\${u.id}"/><input type="hidden" name="active" value="\${u.active?0:1}"/><button type="submit" class="btn \${u.active?'btn-red':''}" style="padding:4px 10px;font-size:11px;">\${u.active?'Deactivate':'Activate'}</button></form></td></tr>\`).join('')}</table></div></div></body></html>\`);
    }

    // ── Admin create user ──
    if (path === '/admin/create-user' && method === 'POST') {
      const token = getToken(request);
      const payload = token ? await verifyToken(token, JWT_SECRET) : null;
      if (!payload) return redirectTo('/login');

      const form = await request.formData();
      const name = form.get('name') || '';
      const company = form.get('company') || '';
      const email = (form.get('email') || '').toLowerCase().trim();
      const role = form.get('role') || '';
      const temp_password = form.get('temp_password') || '';

      try {
        await env.DB.prepare('INSERT INTO users (email, password_hash, name, company, role, first_login, active) VALUES (?, ?, ?, ?, ?, 1, 1)')
          .bind(email, temp_password, name, company, role).run();
      } catch(e) {}

      return redirectTo('/admin');
    }

    // ── Admin toggle user ──
    if (path === '/admin/toggle-user' && method === 'POST') {
      const token = getToken(request);
      const payload = token ? await verifyToken(token, JWT_SECRET) : null;
      if (!payload) return redirectTo('/login');

      const form = await request.formData();
      await env.DB.prepare('UPDATE users SET active = ? WHERE id = ?').bind(form.get('active'), form.get('id')).run();
      return redirectTo('/admin');
    }

    // ── Check auth ──
    if (path === '/check-auth' && method === 'GET') {
      const bearerToken = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
      const cookieToken = getToken(request);
      const token = bearerToken || cookieToken;
      const payload = token ? await verifyToken(token, JWT_SECRET) : null;
      const corsHeaders = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      };
      if (!payload) {
        return new Response(JSON.stringify({authenticated: false}), { headers: corsHeaders });
      }
      return new Response(JSON.stringify({authenticated: true, name: payload.name, email: payload.email}), { headers: corsHeaders });
    }

    return new Response('Not found', {status: 404});
  }
}
