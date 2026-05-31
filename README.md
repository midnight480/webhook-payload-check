# Webhook Payload Check

webhook.site ライクな、Webhook受信・Payload確認サービスです。  
Cloudflare Workers + Cloudflare D1 で動作します。

## 機能

- 🔗 **Webhook URL発行** — ダッシュボードからUUIDベースのURLを何本でも発行
- 📥 **Payload受信** — 認証なしで `GET/POST/PUT/PATCH/DELETE` すべてのメソッドを受信
- 🔐 **ダッシュボード認証** — ID/Passwordでのみ確認画面にアクセス可能
- 📋 **リアルタイム確認** — 5秒ポーリングで自動更新
- 🎨 **JSON整形表示** — シンタックスハイライト付きで見やすく
- ⬇️ **ダウンロード** — JSON・CSV形式でPayloadをエクスポート（トークン別絞り込み対応）
- 🗑️ **削除** — 単件・全件削除に対応

## アーキテクチャ

```
外部サービス
    │
    │ POST /hook/{token}  ← 認証なし（公開）
    ▼
Cloudflare Worker (src/index.js)
    │
    ├── Webhook受信 → Cloudflare D1 (payloads テーブル)
    ├── GET  /              ログイン画面
    ├── POST /login         D1セッション発行
    ├── GET  /dashboard     ダッシュボード（要認証）
    └── GET  /api/*         JSON API（要認証）

Cloudflare D1
    ├── users     (ID/Password管理)
    ├── sessions  (セッション管理)
    ├── tokens    (Webhook URL管理)
    └── payloads  (受信データ)
```

## セットアップ

### 1. リポジトリのクローン

```bash
git clone <repository-url>
cd webhook-payload-check
npm install
```

### 2. Cloudflare D1 データベースの作成

```bash
npm run db:create
```

実行後に表示される `database_id` を `wrangler.toml` に設定：

```toml
[[d1_databases]]
binding = "DB"
database_name = "webhook-payload-check"
database_id = "ここにIDを貼り付け"
```

### 3. D1 スキーマの適用

```bash
# 本番D1に適用
npm run db:init

# ローカル開発用D1に適用
npm run db:init:local
```

### 4. 管理者ユーザーの設定

`.env.example` をコピーして `.env` を作成：

```bash
cp .env.example .env
```

`.env` を編集：

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password
```

D1 に INSERT/UPDATE：

```bash
# 本番D1に反映
npm run seed

# ローカル開発用D1に反映
npm run seed:local
```

> ✅ `ADMIN_USERNAME` が存在する場合は `UPDATE`、存在しない場合は `INSERT` されます。

### 5. ローカル開発

```bash
npm run dev
```

ブラウザで `http://localhost:8787` を開く。

### 6. デプロイ

```bash
npm run deploy
```

## ディレクトリ構成

```
webhook-payload-check/
├── .env.example          # 環境変数テンプレート
├── .env                  # 実際の認証情報（gitignoreされる）
├── .gitignore
├── wrangler.toml         # Cloudflare Worker設定
├── package.json
├── schema.sql            # D1テーブル定義
├── scripts/
│   └── seed-users.js     # .env → D1 INSERT/UPDATE
├── src/
│   └── index.js          # Worker本体（ルーティング・ハンドラ・HTML）
└── README.md
```

## エンドポイント

### Webhook受信（認証不要）

| Method | Path | 説明 |
|--------|------|------|
| `*` | `/hook/{token}` | 全メソッド受信。200 `{"success":true,"id":"..."}` を返す |

### 管理画面（要ログイン）

| Method | Path | 説明 |
|--------|------|------|
| `GET` | `/` | ログイン画面 |
| `POST` | `/login` | ログイン処理 |
| `POST` | `/logout` | ログアウト |
| `GET` | `/dashboard` | ダッシュボード |

### JSON API（要認証Cookie）

| Method | Path | 説明 |
|--------|------|------|
| `GET` | `/api/tokens` | トークン一覧 |
| `POST` | `/api/tokens` | トークン発行 `{"name":"..."}` |
| `DELETE` | `/api/tokens/:id` | トークン削除（Payloadも含む） |
| `GET` | `/api/payloads?token=:id` | Payload一覧 |
| `GET` | `/api/payloads/:id` | Payload詳細 |
| `DELETE` | `/api/payloads/:id` | 単件削除 |
| `DELETE` | `/api/payloads?token=:id` | トークン別全削除 |
| `GET` | `/api/download/json?token=:id` | JSONダウンロード |
| `GET` | `/api/download/csv?token=:id` | CSVダウンロード |

## 使い方

### 1. ダッシュボードにログイン

`https://your-worker.workers.dev` → ID/Passwordでログイン

### 2. Webhook URLを発行

「新しいURL」ボタンをクリック → 名前を入力 → 「発行する」

発行されたURL例：
```
https://your-worker.workers.dev/hook/6886bbb7-0d65-4c89-bfeb-aa1ac3fba454
```

### 3. 外部サービスに登録

GitHub、Backlog、Slackなどのwebhook設定画面に上記URLを登録。

### 4. Payloadを確認

ダッシュボードに戻ると5秒以内に受信データが表示されます。

### 5. ダウンロード

「⬇ JSON」「⬇ CSV」ボタンでエクスポート。

## D1 テーブル設計

### users
| カラム | 型 | 説明 |
|--------|-----|------|
| id | INTEGER PK | |
| username | TEXT UNIQUE | ユーザー名 |
| password_hash | TEXT | SHA-256ハッシュ |
| created_at | TEXT | |
| updated_at | TEXT | UPDATEで更新 |

### sessions
| カラム | 型 | 説明 |
|--------|-----|------|
| session_token | TEXT UNIQUE | ランダムUUID |
| username | TEXT | |
| expires_at | TEXT | 24時間後 |

### tokens
| カラム | 型 | 説明 |
|--------|-----|------|
| id | TEXT PK | UUID（Webhook URL末尾） |
| name | TEXT | 用途名（任意） |

### payloads
| カラム | 型 | 説明 |
|--------|-----|------|
| id | TEXT PK | UUID |
| token_id | TEXT | 紐付くトークン |
| method | TEXT | HTTPメソッド |
| url | TEXT | リクエストURL |
| headers | TEXT | JSON文字列 |
| body | TEXT | リクエストボディ |
| query | TEXT | クエリパラメータ（JSON） |
| ip | TEXT | 送信元IP |

## セキュリティ

- パスワードは **SHA-256** でハッシュ化してD1に保存
- セッションは **D1backed UUID** で管理（SESSION_SECRET不要）
- Cookie は `HttpOnly; Secure; SameSite=Lax` で保護
- Webhook受信エンドポイントは **認証なし**（設計通り）
- `.env` は `.gitignore` に含まれており、コミットされない
- セキュリティヘッダー: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- Content-Security-Policy でリソース読み込み元を制限
- 全IDパラメータにUUID形式バリデーション
- Webhookペイロードサイズ制限（512KB）
- ダウンロードAPIのレコード数制限（10,000件）
- ログインのタイミング攻撃対策
- 期限切れセッションの自動クリーンアップ
- エラーレスポンスで内部情報を非公開

## ライセンス

MIT
