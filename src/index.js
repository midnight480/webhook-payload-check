/**
 * src/index.js
 * Cloudflare Worker — Webhook Payload Check
 *
 * - POST /hook/{token}          : Webhook受信（認証なし）
 * - GET  /                      : ログイン画面
 * - POST /login                 : ログイン処理
 * - POST /logout                : ログアウト
 * - GET  /dashboard             : ダッシュボード（要認証）
 * - GET  /api/tokens            : トークン一覧（要認証）
 * - POST /api/tokens            : トークン発行（要認証）
 * - DELETE /api/tokens/:id      : トークン削除（要認証）
 * - GET  /api/payloads          : Payload一覧（要認証）
 * - GET  /api/payloads/:id      : Payload詳細（要認証）
 * - DELETE /api/payloads/:id    : Payload削除（要認証）
 * - DELETE /api/payloads        : Payload全削除（要認証）
 * - GET  /api/download/json     : JSONダウンロード（要認証）
 * - GET  /api/download/csv      : CSVダウンロード（要認証）
 */

const COOKIE_NAME = 'session';
const SESSION_HOURS = 24;

// ─────────────────────────────────────────────────────────────
//  Utils
// ─────────────────────────────────────────────────────────────

function uuid() {
  return crypto.randomUUID();
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function getSessionToken(req) {
  const cookie = req.headers.get('Cookie') || '';
  const m = cookie.match(/session=([^;]+)/);
  return m ? m[1] : null;
}

async function getSession(env, req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return await env.DB.prepare(
    `SELECT * FROM sessions WHERE session_token=? AND expires_at > datetime('now')`
  ).bind(token).first();
}

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function htmlRes(content, status = 200) {
  return new Response(content, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function redirect(location, extraHeaders = {}) {
  return new Response(null, {
    status: 302,
    headers: { Location: location, ...extraHeaders },
  });
}

// ─────────────────────────────────────────────────────────────
//  Auth Middleware
// ─────────────────────────────────────────────────────────────

async function requireAuth(req, env) {
  const session = await getSession(env, req);
  if (!session) return redirect('/');
  return null;
}

async function requireAuthApi(req, env) {
  const session = await getSession(env, req);
  if (!session) return jsonRes({ error: 'Unauthorized' }, 401);
  return null;
}

// ─────────────────────────────────────────────────────────────
//  Main Router
// ─────────────────────────────────────────────────────────────

export default {
  async fetch(req, env) {
    try {
      const res = await route(req, env);
      // セキュリティヘッダーを全レスポンスに付与
      res.headers.set('X-Content-Type-Options', 'nosniff');
      res.headers.set('X-Frame-Options', 'DENY');
      res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
      return res;
    } catch (e) {
      console.error(e);
      return jsonRes({ error: 'Internal Server Error' }, 500);
    }
  },
};

async function route(req, env) {
  const url = new URL(req.url);
  const p = url.pathname;
  const m = req.method;

  // OPTIONS (CORS preflight) — Webhook受信向け
  if (m === 'OPTIONS' && p.startsWith('/hook/')) {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
        'Access-Control-Allow-Headers': '*',
      },
    });
  }

  // Webhook受信（認証なし）
  const hookMatch = p.match(/^\/hook\/([^/]+)$/);
  if (hookMatch) return receiveWebhook(req, env, url, hookMatch[1]);

  // ページ
  if (p === '/' && m === 'GET') return loginPage();
  if (p === '/login' && m === 'POST') return handleLogin(req, env, url);
  if (p === '/logout' && m === 'POST') return handleLogout(req, env);
  if (p === '/dashboard' && m === 'GET') {
    const err = await requireAuth(req, env);
    return err ?? dashboardPage(url);
  }

  // API（全て認証必要）
  if (p.startsWith('/api/')) {
    const err = await requireAuthApi(req, env);
    if (err) return err;

    // Tokens
    if (p === '/api/tokens') {
      if (m === 'GET') return getTokens(env);
      if (m === 'POST') return createToken(req, env);
    }
    const tokM = p.match(/^\/api\/tokens\/([^/]+)$/);
    if (tokM && m === 'DELETE') return deleteToken(env, tokM[1]);

    // Payloads
    if (p === '/api/payloads') {
      if (m === 'GET') return getPayloads(env, url.searchParams);
      if (m === 'DELETE') return deleteAllPayloads(env, url.searchParams);
    }
    const payM = p.match(/^\/api\/payloads\/([^/]+)$/);
    if (payM) {
      if (m === 'GET') return getPayload(env, payM[1]);
      if (m === 'DELETE') return deletePayload(env, payM[1]);
    }

    // Downloads
    if (p === '/api/download/json') return downloadJson(env, url.searchParams);
    if (p === '/api/download/csv') return downloadCsv(env, url.searchParams);
  }

  return new Response('Not Found', { status: 404 });
}

// ─────────────────────────────────────────────────────────────
//  Webhook Receiver
// ─────────────────────────────────────────────────────────────

async function receiveWebhook(req, env, url, tokenId) {
  const token = await env.DB.prepare('SELECT id FROM tokens WHERE id=?').bind(tokenId).first();
  if (!token) return jsonRes({ error: 'Token not found' }, 404);

  const headers = {};
  for (const [k, v] of req.headers.entries()) headers[k] = v;

  const body = await req.text().catch(() => '');

  const query = {};
  for (const [k, v] of url.searchParams.entries()) query[k] = v;

  const ip =
    req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For') ||
    'unknown';

  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO payloads (id, token_id, method, url, headers, body, query, ip)
     VALUES (?,?,?,?,?,?,?,?)`
  )
    .bind(id, tokenId, req.method, url.toString(), JSON.stringify(headers), body, JSON.stringify(query), ip)
    .run();

  return new Response(JSON.stringify({ success: true, id }), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// ─────────────────────────────────────────────────────────────
//  Auth Handlers
// ─────────────────────────────────────────────────────────────

async function handleLogin(req, env, url) {
  const form = await req.formData().catch(() => new FormData());
  const username = (form.get('username') || '').trim();
  const password = form.get('password') || '';

  if (!username || !password) {
    return loginPage('ユーザー名とパスワードを入力してください');
  }

  const pwHash = await sha256(password);
  const user = await env.DB.prepare(
    `SELECT id FROM users WHERE username=? AND password_hash=?`
  )
    .bind(username, pwHash)
    .first();

  if (!user) return loginPage('ユーザー名またはパスワードが正しくありません');

  const sessionToken = uuid();
  const expiresAt = new Date(Date.now() + SESSION_HOURS * 3_600_000)
    .toISOString()
    .replace('T', ' ')
    .split('.')[0];

  await env.DB.prepare(
    `INSERT INTO sessions (session_token, username, expires_at) VALUES (?,?,?)`
  )
    .bind(sessionToken, username, expiresAt)
    .run();

  // 期限切れセッションをクリーンアップ
  await env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= datetime('now')`).run();

  return redirect('/dashboard', {
    'Set-Cookie': `${COOKIE_NAME}=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_HOURS * 3600}`,
  });
}

async function handleLogout(req, env) {
  const token = getSessionToken(req);
  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE session_token=?').bind(token).run();
  }
  return redirect('/', {
    'Set-Cookie': `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
  });
}

// ─────────────────────────────────────────────────────────────
//  Token Handlers
// ─────────────────────────────────────────────────────────────

async function getTokens(env) {
  const { results } = await env.DB.prepare(
    `SELECT t.id, t.name, t.created_at, COUNT(p.id) as payload_count
     FROM tokens t
     LEFT JOIN payloads p ON t.id = p.token_id
     GROUP BY t.id
     ORDER BY t.created_at DESC`
  ).all();
  return jsonRes(results);
}

async function createToken(req, env) {
  let name = '';
  try {
    name = (await req.json()).name || '';
  } catch {}
  const id = uuid();
  await env.DB.prepare('INSERT INTO tokens (id, name) VALUES (?,?)').bind(id, name).run();
  const token = await env.DB.prepare('SELECT * FROM tokens WHERE id=?').bind(id).first();
  return jsonRes(token, 201);
}

async function deleteToken(env, id) {
  await env.DB.prepare('DELETE FROM payloads WHERE token_id=?').bind(id).run();
  await env.DB.prepare('DELETE FROM tokens WHERE id=?').bind(id).run();
  return jsonRes({ success: true });
}

// ─────────────────────────────────────────────────────────────
//  Payload Handlers
// ─────────────────────────────────────────────────────────────

async function getPayloads(env, q) {
  const tokenId = q.get('token');
  const limit = Math.min(parseInt(q.get('limit') || '200'), 500);
  const offset = parseInt(q.get('offset') || '0');

  const { results } = tokenId
    ? await env.DB.prepare(
        `SELECT * FROM payloads WHERE token_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
        .bind(tokenId, limit, offset)
        .all()
    : await env.DB.prepare(
        `SELECT * FROM payloads ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
        .bind(limit, offset)
        .all();

  return jsonRes(results);
}

async function getPayload(env, id) {
  const p = await env.DB.prepare('SELECT * FROM payloads WHERE id=?').bind(id).first();
  return p ? jsonRes(p) : jsonRes({ error: 'Not found' }, 404);
}

async function deletePayload(env, id) {
  await env.DB.prepare('DELETE FROM payloads WHERE id=?').bind(id).run();
  return jsonRes({ success: true });
}

async function deleteAllPayloads(env, q) {
  const tokenId = q.get('token');
  if (tokenId) {
    await env.DB.prepare('DELETE FROM payloads WHERE token_id=?').bind(tokenId).run();
  } else {
    await env.DB.prepare('DELETE FROM payloads').run();
  }
  return jsonRes({ success: true });
}

// ─────────────────────────────────────────────────────────────
//  Download Handlers
// ─────────────────────────────────────────────────────────────

async function downloadJson(env, q) {
  const tokenId = q.get('token');
  const { results } = tokenId
    ? await env.DB.prepare(
        'SELECT * FROM payloads WHERE token_id=? ORDER BY created_at DESC'
      )
        .bind(tokenId)
        .all()
    : await env.DB.prepare('SELECT * FROM payloads ORDER BY created_at DESC').all();

  const filename = tokenId ? `payloads-${tokenId.slice(0, 8)}.json` : 'payloads-all.json';
  return new Response(JSON.stringify(results, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  });
}

async function downloadCsv(env, q) {
  const tokenId = q.get('token');
  const { results } = tokenId
    ? await env.DB.prepare(
        'SELECT * FROM payloads WHERE token_id=? ORDER BY created_at DESC'
      )
        .bind(tokenId)
        .all()
    : await env.DB.prepare('SELECT * FROM payloads ORDER BY created_at DESC').all();

  const cols = ['id', 'token_id', 'method', 'url', 'ip', 'body', 'query', 'headers', 'created_at'];
  const esc = (v) => {
    if (v == null) return '';
    const s = String(v);
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };

  const csv = [
    cols.join(','),
    ...results.map((r) => cols.map((c) => esc(r[c])).join(',')),
  ].join('\r\n');

  const filename = tokenId ? `payloads-${tokenId.slice(0, 8)}.csv` : 'payloads-all.csv';
  return new Response('\uFEFF' + csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
    },
  });
}

// ─────────────────────────────────────────────────────────────
//  HTML Views
// ─────────────────────────────────────────────────────────────

function loginPage(error = null) {
  const errHtml = error
    ? `<div class="error-msg"><svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M7.002 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 4.995z"/></svg>${error}</div>`
    : '';

  return htmlRes(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Webhook Payload Check — ログイン</title>
  <meta name="description" content="Webhook受信・Payload確認サービスへのログイン">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #0a0e1a;
      --surface: rgba(255,255,255,0.04);
      --surface-hover: rgba(255,255,255,0.07);
      --border: rgba(255,255,255,0.1);
      --accent: #6366f1;
      --accent-glow: rgba(99,102,241,0.4);
      --accent2: #8b5cf6;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --error: #f87171;
      --success: #4ade80;
    }

    body {
      min-height: 100vh;
      background: var(--bg);
      font-family: 'Inter', sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      position: relative;
    }

    /* 背景アニメーション */
    body::before {
      content: '';
      position: fixed;
      width: 600px; height: 600px;
      top: -200px; left: -200px;
      background: radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 70%);
      animation: float 8s ease-in-out infinite;
    }
    body::after {
      content: '';
      position: fixed;
      width: 500px; height: 500px;
      bottom: -150px; right: -150px;
      background: radial-gradient(circle, rgba(139,92,246,0.12) 0%, transparent 70%);
      animation: float 10s ease-in-out infinite reverse;
    }
    @keyframes float {
      0%, 100% { transform: translate(0,0); }
      50% { transform: translate(30px, 30px); }
    }

    .card {
      position: relative;
      z-index: 1;
      width: 100%;
      max-width: 420px;
      margin: 1rem;
      background: rgba(15,20,40,0.85);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 2.5rem;
      backdrop-filter: blur(20px);
      box-shadow: 0 25px 50px rgba(0,0,0,0.5), 0 0 0 1px rgba(99,102,241,0.1);
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 2rem;
    }
    .logo-icon {
      width: 44px; height: 44px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 0 20px var(--accent-glow);
    }
    .logo-icon svg { width: 24px; height: 24px; fill: white; }
    .logo-text h1 { font-size: 1.1rem; font-weight: 700; color: var(--text); }
    .logo-text p { font-size: 0.75rem; color: var(--text-muted); }

    h2 {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 0.5rem;
    }
    .subtitle {
      color: var(--text-muted);
      font-size: 0.875rem;
      margin-bottom: 2rem;
    }

    .error-msg {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(248,113,113,0.1);
      border: 1px solid rgba(248,113,113,0.3);
      color: var(--error);
      padding: 0.75rem 1rem;
      border-radius: 10px;
      font-size: 0.875rem;
      margin-bottom: 1.25rem;
      animation: shake 0.4s ease;
    }
    @keyframes shake {
      0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)}
    }

    .form-group {
      margin-bottom: 1.25rem;
    }
    label {
      display: block;
      font-size: 0.8rem;
      font-weight: 500;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    .input-wrap {
      position: relative;
    }
    .input-wrap svg {
      position: absolute;
      left: 14px; top: 50%; transform: translateY(-50%);
      color: var(--text-muted);
      width: 16px; height: 16px;
    }
    input {
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.75rem 1rem 0.75rem 2.75rem;
      color: var(--text);
      font-size: 0.9375rem;
      font-family: 'Inter', sans-serif;
      transition: border-color 0.2s, box-shadow 0.2s;
      outline: none;
    }
    input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }

    .btn {
      width: 100%;
      padding: 0.875rem;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      border: none;
      border-radius: 10px;
      color: white;
      font-size: 0.9375rem;
      font-weight: 600;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: opacity 0.2s, transform 0.1s, box-shadow 0.2s;
      margin-top: 0.5rem;
      box-shadow: 0 4px 15px var(--accent-glow);
    }
    .btn:hover { opacity: 0.9; box-shadow: 0 6px 20px var(--accent-glow); }
    .btn:active { transform: scale(0.98); }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-icon">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 14.5v-9l6 4.5-6 4.5z"/></svg>
      </div>
      <div class="logo-text">
        <h1>Webhook Payload Check</h1>
        <p>Cloudflare Workers + D1</p>
      </div>
    </div>

    <h2>ログイン</h2>
    <p class="subtitle">ダッシュボードにアクセスするにはログインが必要です</p>

    ${errHtml}

    <form method="POST" action="/login">
      <div class="form-group">
        <label for="username">ユーザー名</label>
        <div class="input-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <input id="username" type="text" name="username" placeholder="admin" autocomplete="username" required>
        </div>
      </div>
      <div class="form-group">
        <label for="password">パスワード</label>
        <div class="input-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <input id="password" type="password" name="password" placeholder="••••••••" autocomplete="current-password" required>
        </div>
      </div>
      <button type="submit" class="btn">ログイン</button>
    </form>
  </div>
</body>
</html>`);
}

function dashboardPage(url) {
  const origin = url.origin;

  return htmlRes(`<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Webhook Payload Check — ダッシュボード</title>
  <meta name="description" content="受信したWebhookのPayload確認・管理ダッシュボード">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #070b14;
      --sidebar-bg: #0d1117;
      --panel-bg: #0f1520;
      --surface: rgba(255,255,255,0.04);
      --surface-hover: rgba(255,255,255,0.07);
      --surface-active: rgba(99,102,241,0.15);
      --border: rgba(255,255,255,0.08);
      --accent: #6366f1;
      --accent-light: #818cf8;
      --accent-glow: rgba(99,102,241,0.3);
      --accent2: #8b5cf6;
      --text: #e2e8f0;
      --text-muted: #64748b;
      --text-dim: #94a3b8;
      --error: #f87171;
      --success: #4ade80;
      --warning: #fbbf24;
      --method-get: #4ade80;
      --method-post: #60a5fa;
      --method-put: #fbbf24;
      --method-patch: #fb923c;
      --method-delete: #f87171;
    }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      height: 100vh;
      display: grid;
      grid-template-rows: 52px 1fr;
      grid-template-columns: 260px 340px 1fr;
      overflow: hidden;
    }

    /* ── Header ── */
    header {
      grid-column: 1 / -1;
      background: var(--sidebar-bg);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      padding: 0 1.25rem;
      gap: 1rem;
    }
    .header-logo {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      text-decoration: none;
    }
    .header-logo-icon {
      width: 30px; height: 30px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
    }
    .header-logo-icon svg { width: 16px; height: 16px; fill: white; }
    .header-title {
      font-size: 0.9rem;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.01em;
    }
    .header-spacer { flex: 1; }
    .header-refresh {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .refresh-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      background: var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
    .btn-logout {
      display: flex; align-items: center; gap: 0.4rem;
      padding: 0.4rem 0.9rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-muted);
      font-size: 0.8rem;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-logout:hover { background: var(--surface-hover); color: var(--text); }

    /* ── Sidebar (Tokens) ── */
    .sidebar {
      background: var(--sidebar-bg);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .sidebar-header {
      padding: 1rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .sidebar-title {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      flex: 1;
    }
    .btn-new-token {
      display: flex; align-items: center; gap: 0.3rem;
      padding: 0.35rem 0.7rem;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      border: none;
      border-radius: 6px;
      color: white;
      font-size: 0.75rem;
      font-weight: 600;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: opacity 0.2s;
      white-space: nowrap;
    }
    .btn-new-token:hover { opacity: 0.85; }

    .token-list { flex: 1; overflow-y: auto; padding: 0.5rem; }
    .token-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.65rem 0.75rem;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.15s;
      group: true;
    }
    .token-item:hover { background: var(--surface-hover); }
    .token-item.active { background: var(--surface-active); }
    .token-item.active .token-name { color: var(--accent-light); }
    .token-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--accent);
      flex-shrink: 0;
    }
    .token-info { flex: 1; min-width: 0; }
    .token-name {
      font-size: 0.8rem;
      font-weight: 500;
      color: var(--text);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .token-url {
      font-size: 0.7rem;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .token-count {
      font-size: 0.7rem;
      font-weight: 600;
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.15rem 0.45rem;
      border-radius: 99px;
      flex-shrink: 0;
    }
    .token-delete {
      opacity: 0;
      padding: 0.2rem;
      background: none;
      border: none;
      color: var(--error);
      cursor: pointer;
      border-radius: 4px;
      display: flex;
      transition: opacity 0.15s, background 0.15s;
    }
    .token-item:hover .token-delete { opacity: 1; }
    .token-delete:hover { background: rgba(248,113,113,0.1); }

    .empty-tokens {
      padding: 2rem 1rem;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.8rem;
    }
    .empty-tokens svg { display: block; margin: 0 auto 0.75rem; opacity: 0.3; }

    /* ── Payload List ── */
    .payload-list-panel {
      background: var(--panel-bg);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .payload-list-header {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .payload-list-title {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      flex: 1;
    }
    .btn-download {
      display: flex; align-items: center; gap: 0.3rem;
      padding: 0.3rem 0.6rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-muted);
      font-size: 0.72rem;
      font-weight: 500;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
    }
    .btn-download:hover { background: var(--surface-hover); color: var(--text); border-color: rgba(255,255,255,0.15); }
    .btn-delete-all {
      display: flex; align-items: center; gap: 0.3rem;
      padding: 0.3rem 0.6rem;
      background: rgba(248,113,113,0.08);
      border: 1px solid rgba(248,113,113,0.2);
      border-radius: 6px;
      color: var(--error);
      font-size: 0.72rem;
      font-weight: 500;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-delete-all:hover { background: rgba(248,113,113,0.15); }

    .payload-list { flex: 1; overflow-y: auto; }
    .payload-item {
      padding: 0.8rem 1rem;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      transition: background 0.15s;
      display: flex;
      gap: 0.75rem;
      align-items: flex-start;
    }
    .payload-item:hover { background: var(--surface-hover); }
    .payload-item.active { background: var(--surface-active); border-left: 2px solid var(--accent); }
    .method-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.65rem;
      font-weight: 700;
      padding: 0.2rem 0.45rem;
      border-radius: 4px;
      flex-shrink: 0;
      margin-top: 0.1rem;
      letter-spacing: 0.03em;
    }
    .method-GET    { background: rgba(74,222,128,0.15); color: var(--method-get); }
    .method-POST   { background: rgba(96,165,250,0.15); color: var(--method-post); }
    .method-PUT    { background: rgba(251,191,36,0.15); color: var(--method-put); }
    .method-PATCH  { background: rgba(251,146,60,0.15); color: var(--method-patch); }
    .method-DELETE { background: rgba(248,113,113,0.15); color: var(--method-delete); }
    .method-OTHER  { background: rgba(148,163,184,0.15); color: var(--text-dim); }

    .payload-meta { flex: 1; min-width: 0; }
    .payload-path {
      font-size: 0.8rem;
      color: var(--text);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      margin-bottom: 0.2rem;
    }
    .payload-sub {
      display: flex;
      gap: 0.75rem;
      font-size: 0.7rem;
      color: var(--text-muted);
    }
    .payload-body-preview {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.7rem;
      color: var(--text-muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      margin-top: 0.2rem;
    }
    .payload-del-btn {
      opacity: 0;
      background: none;
      border: none;
      color: var(--error);
      cursor: pointer;
      padding: 0.2rem;
      border-radius: 4px;
      transition: opacity 0.15s, background 0.15s;
      flex-shrink: 0;
    }
    .payload-item:hover .payload-del-btn { opacity: 1; }
    .payload-del-btn:hover { background: rgba(248,113,113,0.1); }

    .empty-payloads {
      padding: 3rem 1.5rem;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    .empty-payloads svg { display: block; margin: 0 auto 1rem; opacity: 0.3; }
    .empty-payloads h3 { font-size: 0.9rem; color: var(--text-dim); margin-bottom: 0.5rem; }

    .no-token-selected {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      gap: 1rem;
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    .no-token-selected svg { opacity: 0.2; }

    /* ── Detail Panel ── */
    .detail-panel {
      background: var(--bg);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .detail-empty {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      gap: 1rem;
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    .detail-empty svg { opacity: 0.15; }

    .detail-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: var(--panel-bg);
    }
    .detail-method-url {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.6rem;
    }
    .detail-url {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: var(--text);
      word-break: break-all;
      flex: 1;
    }
    .detail-meta {
      display: flex;
      gap: 1.25rem;
      font-size: 0.75rem;
      color: var(--text-muted);
      flex-wrap: wrap;
    }
    .detail-meta span { display: flex; align-items: center; gap: 0.3rem; }

    .detail-copy-btn {
      display: flex; align-items: center; gap: 0.35rem;
      padding: 0.35rem 0.75rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-muted);
      font-size: 0.75rem;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .detail-copy-btn:hover { background: var(--surface-hover); color: var(--text); }
    .detail-copy-btn.copied { color: var(--success); border-color: rgba(74,222,128,0.3); }

    .detail-tabs {
      display: flex;
      gap: 0;
      padding: 0 1.25rem;
      background: var(--panel-bg);
      border-bottom: 1px solid var(--border);
    }
    .detail-tab {
      padding: 0.65rem 1rem;
      font-size: 0.8rem;
      font-weight: 500;
      color: var(--text-muted);
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: color 0.15s, border-color 0.15s;
      background: none;
      border-top: none;
      border-left: none;
      border-right: none;
      font-family: 'Inter', sans-serif;
    }
    .detail-tab:hover { color: var(--text); }
    .detail-tab.active { color: var(--accent-light); border-bottom-color: var(--accent); }

    .detail-body { flex: 1; overflow-y: auto; padding: 1.25rem; }
    .detail-tab-content { display: none; }
    .detail-tab-content.active { display: block; }

    pre {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      line-height: 1.6;
      color: var(--text);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .json-key    { color: #60a5fa; }
    .json-string { color: #86efac; }
    .json-number { color: #fbbf24; }
    .json-bool   { color: #f472b6; }
    .json-null   { color: #94a3b8; }

    .kv-table { width: 100%; border-collapse: collapse; }
    .kv-table tr { border-bottom: 1px solid var(--border); }
    .kv-table tr:last-child { border-bottom: none; }
    .kv-table td {
      padding: 0.5rem 0.75rem;
      font-size: 0.8rem;
      vertical-align: top;
    }
    .kv-table td:first-child {
      color: var(--text-muted);
      font-weight: 500;
      white-space: nowrap;
      width: 35%;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
    }
    .kv-table td:last-child {
      color: var(--text);
      word-break: break-all;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 99px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

    /* ── Modal ── */
    .modal-overlay {
      display: none;
      position: fixed; inset: 0;
      background: rgba(0,0,0,0.7);
      z-index: 100;
      align-items: center;
      justify-content: center;
      backdrop-filter: blur(4px);
    }
    .modal-overlay.open { display: flex; }
    .modal {
      background: #131929;
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.75rem;
      width: 100%;
      max-width: 480px;
      margin: 1rem;
      box-shadow: 0 25px 50px rgba(0,0,0,0.6);
    }
    .modal h3 { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem; }
    .modal p { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.25rem; }
    .modal label { display: block; font-size: 0.78rem; font-weight: 500; color: var(--text-muted); margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 0.06em; }
    .modal input {
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.7rem 1rem;
      color: var(--text);
      font-family: 'Inter', sans-serif;
      font-size: 0.9rem;
      outline: none;
      margin-bottom: 1.25rem;
      transition: border-color 0.2s;
    }
    .modal input:focus { border-color: var(--accent); }
    .modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; }
    .btn-cancel {
      padding: 0.6rem 1.2rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-muted);
      font-size: 0.85rem;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-cancel:hover { color: var(--text); }
    .btn-create {
      padding: 0.6rem 1.2rem;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      border: none;
      border-radius: 8px;
      color: white;
      font-size: 0.85rem;
      font-weight: 600;
      font-family: 'Inter', sans-serif;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .btn-create:hover { opacity: 0.85; }

    /* ── Webhook URL Box ── */
    .webhook-url-box {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .webhook-url-box code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: var(--accent-light);
      flex: 1;
      word-break: break-all;
    }
    .btn-copy-url {
      background: none;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-muted);
      padding: 0.3rem 0.6rem;
      cursor: pointer;
      font-size: 0.72rem;
      white-space: nowrap;
      font-family: 'Inter', sans-serif;
      transition: all 0.2s;
    }
    .btn-copy-url:hover { color: var(--text); }

    /* ── Toast ── */
    .toast {
      position: fixed;
      bottom: 1.5rem; right: 1.5rem;
      background: #1e293b;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.75rem 1.1rem;
      font-size: 0.85rem;
      color: var(--text);
      z-index: 200;
      transform: translateY(100px);
      opacity: 0;
      transition: all 0.3s ease;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast.success { border-color: rgba(74,222,128,0.3); }
    .toast.error   { border-color: rgba(248,113,113,0.3); }
  </style>
</head>
<body>
  <!-- Header -->
  <header>
    <a class="header-logo" href="/dashboard">
      <div class="header-logo-icon">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 14.5v-9l6 4.5-6 4.5z"/></svg>
      </div>
      <span class="header-title">Webhook Payload Check</span>
    </a>
    <div class="header-spacer"></div>
    <div class="header-refresh">
      <div class="refresh-dot"></div>
      <span id="refresh-status">自動更新中</span>
    </div>
    <form method="POST" action="/logout" style="margin-left:0.75rem">
      <button type="submit" class="btn-logout">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        ログアウト
      </button>
    </form>
  </header>

  <!-- Sidebar: Token List -->
  <aside class="sidebar">
    <div class="sidebar-header">
      <span class="sidebar-title">Webhook URLs</span>
      <button class="btn-new-token" onclick="openNewTokenModal()">
        <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        新しいURL
      </button>
    </div>
    <div class="token-list" id="token-list">
      <div class="empty-tokens">
        <svg width="32" height="32" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
        URLを発行して<br>Webhookを受信しましょう
      </div>
    </div>
  </aside>

  <!-- Payload List -->
  <section class="payload-list-panel">
    <div class="payload-list-header">
      <span class="payload-list-title" id="payload-list-title">Payloads</span>
      <button class="btn-download" id="btn-dl-json" onclick="downloadPayloads('json')" title="JSON形式でダウンロード">
        <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        JSON
      </button>
      <button class="btn-download" id="btn-dl-csv" onclick="downloadPayloads('csv')" title="CSV形式でダウンロード" style="margin-left:0.3rem">
        <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        CSV
      </button>
      <button class="btn-delete-all" style="margin-left:0.3rem" onclick="deleteAllPayloads()">
        <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
        全削除
      </button>
    </div>
    <div class="payload-list" id="payload-list">
      <div class="no-token-selected">
        <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
        <span>左のURLを選択してください</span>
      </div>
    </div>
  </section>

  <!-- Detail Panel -->
  <section class="detail-panel" id="detail-panel">
    <div class="detail-empty" id="detail-empty">
      <svg width="56" height="56" fill="none" stroke="currentColor" stroke-width="1" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      <span>Payloadを選択すると詳細が表示されます</span>
    </div>
    <div id="detail-content" style="display:none; height:100%; display:none; flex-direction:column;">
      <div class="detail-header">
        <div class="detail-method-url">
          <span class="method-badge" id="detail-method"></span>
          <span class="detail-url" id="detail-url"></span>
          <button class="detail-copy-btn" onclick="copyDetail()" id="copy-body-btn">
            <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Bodyをコピー
          </button>
        </div>
        <div class="detail-meta">
          <span><svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><span id="detail-time"></span></span>
          <span><svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>IP: <span id="detail-ip"></span></span>
        </div>
      </div>
      <div class="detail-tabs">
        <button class="detail-tab active" onclick="switchTab('body')" id="tab-body">Body</button>
        <button class="detail-tab" onclick="switchTab('headers')" id="tab-headers">Headers</button>
        <button class="detail-tab" onclick="switchTab('query')" id="tab-query">Query</button>
        <button class="detail-tab" onclick="switchTab('raw')" id="tab-raw">Raw</button>
      </div>
      <div class="detail-body">
        <div class="detail-tab-content active" id="tab-content-body">
          <pre id="body-content"></pre>
        </div>
        <div class="detail-tab-content" id="tab-content-headers">
          <table class="kv-table" id="headers-table"></table>
        </div>
        <div class="detail-tab-content" id="tab-content-query">
          <table class="kv-table" id="query-table"></table>
        </div>
        <div class="detail-tab-content" id="tab-content-raw">
          <pre id="raw-content"></pre>
        </div>
      </div>
    </div>
  </section>

  <!-- New Token Modal -->
  <div class="modal-overlay" id="new-token-modal">
    <div class="modal">
      <h3>🔗 新しいWebhook URLを発行</h3>
      <p>用途を表す名前を入力してください（任意）。<br>発行されたURLにPOSTするとPayloadが記録されます。</p>
      <label for="token-name">名前（例: GitHub Webhook, Backlog）</label>
      <input type="text" id="token-name" placeholder="My Webhook" maxlength="100">
      <div class="modal-actions">
        <button class="btn-cancel" onclick="closeNewTokenModal()">キャンセル</button>
        <button class="btn-create" onclick="createToken()">発行する</button>
      </div>
    </div>
  </div>

  <!-- Created Token Modal -->
  <div class="modal-overlay" id="created-token-modal">
    <div class="modal">
      <h3>✅ Webhook URLを発行しました</h3>
      <p>以下のURLにHTTPリクエストを送信すると、Payloadが記録されます。<br>URLは後からも確認できます。</p>
      <div class="webhook-url-box">
        <code id="created-token-url"></code>
        <button class="btn-copy-url" onclick="copyCreatedUrl()">コピー</button>
      </div>
      <div class="modal-actions">
        <button class="btn-create" onclick="closeCreatedTokenModal()">閉じる</button>
      </div>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast"></div>

  <script>
    const BASE = '';
    const ORIGIN = '${origin}';
    let selectedTokenId = null;
    let selectedPayloadId = null;
    let currentPayloads = [];
    let currentTokens = [];
    let autoRefreshTimer = null;
    let createdTokenUrl = '';

    // ── Toast ──
    function showToast(msg, type = 'success') {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.className = 'toast ' + type + ' show';
      clearTimeout(t._timer);
      t._timer = setTimeout(() => t.classList.remove('show'), 3000);
    }

    // ── Tokens ──
    async function loadTokens() {
      try {
        const res = await fetch('/api/tokens');
        if (!res.ok) return;
        currentTokens = await res.json();
        renderTokenList();
      } catch {}
    }

    function renderTokenList() {
      const el = document.getElementById('token-list');
      if (!currentTokens.length) {
        el.innerHTML = \`<div class="empty-tokens">
          <svg width="32" height="32" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
          URLを発行して<br>Webhookを受信しましょう
        </div>\`;
        return;
      }
      el.innerHTML = currentTokens.map(t => \`
        <div class="token-item \${t.id === selectedTokenId ? 'active' : ''}" onclick="selectToken('\${t.id}')">
          <div class="token-dot"></div>
          <div class="token-info">
            <div class="token-name">\${escHtml(t.name || 'Unnamed')}</div>
            <div class="token-url">/hook/\${t.id.slice(0,18)}...</div>
          </div>
          <span class="token-count">\${t.payload_count}</span>
          <button class="token-delete" title="削除" onclick="event.stopPropagation(); deleteToken('\${t.id}', '\${escHtml(t.name || 'Unnamed')}')">
            <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
          </button>
        </div>
      \`).join('');
    }

    function selectToken(id) {
      selectedTokenId = id;
      selectedPayloadId = null;
      document.getElementById('detail-empty').style.display = 'flex';
      document.getElementById('detail-content').style.display = 'none';
      renderTokenList();
      loadPayloads();
    }

    async function createToken() {
      const name = document.getElementById('token-name').value.trim();
      try {
        const res = await fetch('/api/tokens', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name })
        });
        if (!res.ok) throw new Error();
        const token = await res.json();
        closeNewTokenModal();
        await loadTokens();
        selectToken(token.id);
        createdTokenUrl = ORIGIN + '/hook/' + token.id;
        document.getElementById('created-token-url').textContent = createdTokenUrl;
        document.getElementById('created-token-modal').classList.add('open');
      } catch {
        showToast('エラーが発生しました', 'error');
      }
    }

    async function deleteToken(id, name) {
      if (!confirm(\`"\${name}" とその受信履歴をすべて削除しますか？\`)) return;
      await fetch('/api/tokens/' + id, { method: 'DELETE' });
      if (selectedTokenId === id) {
        selectedTokenId = null;
        selectedPayloadId = null;
        document.getElementById('payload-list').innerHTML = \`
          <div class="no-token-selected">
            <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
            <span>左のURLを選択してください</span>
          </div>\`;
        document.getElementById('detail-empty').style.display = 'flex';
        document.getElementById('detail-content').style.display = 'none';
      }
      await loadTokens();
      showToast('削除しました');
    }

    function openNewTokenModal() {
      document.getElementById('token-name').value = '';
      document.getElementById('new-token-modal').classList.add('open');
      setTimeout(() => document.getElementById('token-name').focus(), 100);
    }
    function closeNewTokenModal() {
      document.getElementById('new-token-modal').classList.remove('open');
    }
    function closeCreatedTokenModal() {
      document.getElementById('created-token-modal').classList.remove('open');
    }
    function copyCreatedUrl() {
      navigator.clipboard.writeText(createdTokenUrl);
      showToast('URLをコピーしました！');
    }

    // ── Payloads ──
    async function loadPayloads(silent = false) {
      if (!selectedTokenId) return;
      try {
        const res = await fetch('/api/payloads?token=' + selectedTokenId);
        if (!res.ok) return;
        const payloads = await res.json();

        const changed = JSON.stringify(payloads.map(p => p.id)) !== JSON.stringify(currentPayloads.map(p => p.id));
        currentPayloads = payloads;

        if (changed || !silent) {
          renderPayloadList();
          await loadTokens(); // count更新
        }
      } catch {}
    }

    function renderPayloadList() {
      const el = document.getElementById('payload-list');
      const token = currentTokens.find(t => t.id === selectedTokenId);
      document.getElementById('payload-list-title').textContent =
        token ? (token.name || 'Unnamed') + ' — Payloads' : 'Payloads';

      if (!currentPayloads.length) {
        el.innerHTML = \`<div class="empty-payloads">
          <svg width="40" height="40" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
          <h3>Payloadなし</h3>
          Webhook URLにリクエストを送信してください
        </div>\`;
        return;
      }

      el.innerHTML = currentPayloads.map(p => {
        const methodClass = ['GET','POST','PUT','PATCH','DELETE'].includes(p.method) ? p.method : 'OTHER';
        const bodyPreview = p.body ? p.body.slice(0, 60).replace(/\\n/g, ' ') : '(empty)';
        return \`
        <div class="payload-item \${p.id === selectedPayloadId ? 'active' : ''}" onclick="selectPayload('\${p.id}')">
          <span class="method-badge method-\${methodClass}">\${p.method}</span>
          <div class="payload-meta">
            <div class="payload-path">\${escUrl(p.url)}</div>
            <div class="payload-sub">
              <span>\${formatTime(p.created_at)}</span>
              <span>\${escHtml(p.ip || '')}</span>
            </div>
            <div class="payload-body-preview">\${escHtml(bodyPreview)}</div>
          </div>
          <button class="payload-del-btn" title="削除" onclick="event.stopPropagation(); deletePayload('\${p.id}')">
            <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
          </button>
        </div>\`;
      }).join('');
    }

    function selectPayload(id) {
      selectedPayloadId = id;
      renderPayloadList();
      const p = currentPayloads.find(x => x.id === id);
      if (!p) return;

      const methodClass = ['GET','POST','PUT','PATCH','DELETE'].includes(p.method) ? p.method : 'OTHER';
      document.getElementById('detail-method').textContent = p.method;
      document.getElementById('detail-method').className = 'method-badge method-' + methodClass;
      document.getElementById('detail-url').textContent = p.url;
      document.getElementById('detail-time').textContent = formatTimeFull(p.created_at);
      document.getElementById('detail-ip').textContent = p.ip || 'unknown';

      // Body tab
      let bodyText = p.body || '';
      try {
        const parsed = JSON.parse(bodyText);
        document.getElementById('body-content').innerHTML = syntaxHighlight(JSON.stringify(parsed, null, 2));
      } catch {
        document.getElementById('body-content').innerHTML = escHtml(bodyText) || '<span style="color:var(--text-muted)">(empty)</span>';
      }

      // Headers tab
      let headers = {};
      try { headers = JSON.parse(p.headers || '{}'); } catch {}
      document.getElementById('headers-table').innerHTML = Object.entries(headers)
        .map(([k,v]) => \`<tr><td>\${escHtml(k)}</td><td>\${escHtml(v)}</td></tr>\`).join('');

      // Query tab
      let query = {};
      try { query = JSON.parse(p.query || '{}'); } catch {}
      const queryEntries = Object.entries(query);
      document.getElementById('query-table').innerHTML = queryEntries.length
        ? queryEntries.map(([k,v]) => \`<tr><td>\${escHtml(k)}</td><td>\${escHtml(v)}</td></tr>\`).join('')
        : '<tr><td colspan="2" style="color:var(--text-muted);padding:1rem">クエリパラメータなし</td></tr>';

      // Raw tab
      document.getElementById('raw-content').textContent = JSON.stringify(p, null, 2);

      switchTab('body');
      document.getElementById('detail-empty').style.display = 'none';
      document.getElementById('detail-content').style.display = 'flex';
      document.getElementById('detail-content').style.flexDirection = 'column';
      document.getElementById('detail-content').style.height = '100%';
    }

    async function deletePayload(id) {
      await fetch('/api/payloads/' + id, { method: 'DELETE' });
      if (selectedPayloadId === id) {
        selectedPayloadId = null;
        document.getElementById('detail-empty').style.display = 'flex';
        document.getElementById('detail-content').style.display = 'none';
      }
      currentPayloads = currentPayloads.filter(p => p.id !== id);
      renderPayloadList();
      await loadTokens();
      showToast('削除しました');
    }

    async function deleteAllPayloads() {
      if (!selectedTokenId) return;
      if (!confirm('このURLの受信履歴をすべて削除しますか？')) return;
      await fetch('/api/payloads?token=' + selectedTokenId, { method: 'DELETE' });
      currentPayloads = [];
      selectedPayloadId = null;
      document.getElementById('detail-empty').style.display = 'flex';
      document.getElementById('detail-content').style.display = 'none';
      renderPayloadList();
      await loadTokens();
      showToast('全件削除しました');
    }

    // ── Downloads ──
    function downloadPayloads(fmt) {
      const tokenParam = selectedTokenId ? '?token=' + selectedTokenId : '';
      window.location.href = '/api/download/' + fmt + tokenParam;
    }

    // ── Tabs ──
    function switchTab(name) {
      ['body','headers','query','raw'].forEach(t => {
        document.getElementById('tab-' + t).classList.toggle('active', t === name);
        document.getElementById('tab-content-' + t).classList.toggle('active', t === name);
      });
    }

    // ── Copy ──
    function copyDetail() {
      const body = document.getElementById('body-content').textContent;
      navigator.clipboard.writeText(body);
      const btn = document.getElementById('copy-body-btn');
      btn.textContent = 'コピー済み ✓';
      btn.classList.add('copied');
      setTimeout(() => { btn.innerHTML = \`<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Bodyをコピー\`; btn.classList.remove('copied'); }, 2000);
    }

    // ── Helpers ──
    function escHtml(s) {
      return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    function escUrl(u) {
      try { return escHtml(new URL(u).pathname + new URL(u).search); }
      catch { return escHtml(u); }
    }

    function formatTime(s) {
      if (!s) return '';
      const d = new Date(s.includes('T') ? s : s + 'Z');
      return d.toLocaleString('ja-JP',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
    }

    function formatTimeFull(s) {
      if (!s) return '';
      const d = new Date(s.includes('T') ? s : s + 'Z');
      return d.toLocaleString('ja-JP');
    }

    function syntaxHighlight(json) {
      return escHtml(json)
        .replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
        .replace(/: "(.*?)"/g, ': <span class="json-string">"$1"</span>')
        .replace(/: (\\d+(\\.\\d+)?)/g, ': <span class="json-number">$1</span>')
        .replace(/: (true|false)/g, ': <span class="json-bool">$1</span>')
        .replace(/: null/g, ': <span class="json-null">null</span>');
    }

    // ── Auto Refresh ──
    function startAutoRefresh() {
      stopAutoRefresh();
      autoRefreshTimer = setInterval(async () => {
        await loadPayloads(true);
        await loadTokens();
      }, 5000);
    }
    function stopAutoRefresh() {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    }

    // ── Modal keyboard ──
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        closeNewTokenModal();
        closeCreatedTokenModal();
      }
      if (e.key === 'Enter' && document.getElementById('new-token-modal').classList.contains('open')) {
        createToken();
      }
    });

    // ── Init ──
    loadTokens();
    startAutoRefresh();
  </script>
</body>
</html>`);
}
