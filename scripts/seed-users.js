#!/usr/bin/env node
/**
 * scripts/seed-users.js
 *
 * .env に設定した ADMIN_USERNAME / ADMIN_PASSWORD を
 * Cloudflare D1 の users テーブルへ INSERT または UPDATE します。
 *
 * Usage:
 *   npm run seed          # リモート (本番) D1 に反映
 *   npm run seed:local    # ローカル D1 に反映
 */

import { createHash } from 'crypto';
import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

// ── .env 手動パース ──────────────────────────────────────────────
const envPath = resolve(process.cwd(), '.env');
if (!existsSync(envPath)) {
  console.error('❌  .env が見つかりません。.env.example をコピーして設定してください。');
  process.exit(1);
}

const env = {};
readFileSync(envPath, 'utf-8')
  .split('\n')
  .forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) return;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
    env[key] = val;
  });

// ── 設定値チェック ────────────────────────────────────────────────
const username = env.ADMIN_USERNAME;
const password = env.ADMIN_PASSWORD;

if (!username || !password) {
  console.error('❌  .env に ADMIN_USERNAME と ADMIN_PASSWORD を設定してください。');
  process.exit(1);
}

// ── パスワードハッシュ (SHA-256 with pepper) ──────────────────────
const pepper = env.PASSWORD_PEPPER || '';
const passwordHash = createHash('sha256').update(pepper + ':' + password).digest('hex');

// ── SQL 生成 ──────────────────────────────────────────────────────
// ON CONFLICT で username が存在する場合は UPDATE
// パラメータはエスケープしてSQLインジェクションを防止
const escapeSql = (s) => s.replace(/'/g, "''");
const safeUsername = escapeSql(username);
const safeHash = escapeSql(passwordHash);
const sql = `INSERT INTO users (username, password_hash) VALUES ('${safeUsername}', '${safeHash}') ON CONFLICT(username) DO UPDATE SET password_hash='${safeHash}', updated_at=datetime('now');`;

// ── wrangler d1 execute 実行 ──────────────────────────────────────
const isLocal = process.argv.includes('--local');
const target  = isLocal ? '--local' : '--remote';

console.log(`\n🔑  ユーザー "${username}" を D1 に反映します (${isLocal ? 'ローカル' : 'リモート'})...`);

try {
  execSync(
    `wrangler d1 execute webhook-payload-check ${target} --command "${sql.replace(/"/g, '\\"')}"`,
    { stdio: 'inherit' }
  );
  console.log(`✅  ユーザー "${username}" のシードが完了しました。\n`);
} catch (e) {
  console.error('❌  シード失敗:', e.message);
  process.exit(1);
}
