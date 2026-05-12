# rage.lua — Web + License Server

## Deploying to Render

### 1. Push to GitHub

```
git init
git add .
git commit -m "initial"
gh repo create rage-web --private --source=. --push
```
(or create the repo on github.com and push manually)

### 2. Create Render Services

Go to https://render.com → New → Blueprint → connect your repo.
Render reads `render.yaml` and creates:
- A **web service** (Node.js)
- A **PostgreSQL database** (free tier)

It automatically injects `DATABASE_URL` and generates `JWT_SECRET`.

### 3. First Admin Account

The **first user to register** on your site automatically becomes admin.
Register at `https://your-site.onrender.com/register`.

### 4. rage.lua Integration

In `rage.lua`, set your verify URL:
```lua
local LICENSE_URL = 'https://your-site.onrender.com/verify'
```

The verify endpoint accepts:
```
POST /verify
{ "key": "RAGE-XXXX-XXXX-XXXX", "hwid": "<player hwid>" }

Response: { "ok": true/false, "msg": "..." }
```

### 5. Granting Keys

1. Log in as admin → `/admin`
2. Click **Generate Keys**, enter product name + expiry
3. Assign the key to a user OR copy the key code and give it to them
4. User logs into `/dashboard` to see their active keys

---

## Local Development

```bash
npm install
cp .env.example .env
# Fill in DATABASE_URL and JWT_SECRET in .env
npm run dev
```

Open http://localhost:3000
