# 🐦 Raven Chat v5

A full-featured real-time messaging app built with Node.js, Socket.io, and NeDB.

## 🚀 Deploy to Render

### خطوات النشر على Render
1. ارفع الكود على GitHub
2. اذهب لـ [render.com](https://render.com) ← New ← Web Service
3. اربط الـ GitHub repo
4. Render بيقرأ `render.yaml` تلقائياً ويضبط كل شي

### إعدادات يدوية (بديل)
- **Build Command:** `npm install`
- **Start Command:** `npm start`
- **Environment Variables:**
  - `JWT_SECRET` → أي string طويل عشوائي
  - `NODE_ENV` → `production`

## ⚠️ ملاحظة عن الداتا
الـ free tier على Render يمسح الداتا عند كل redeploy.
لو تبي داتا دائمة، أضف Render Disk وضع:
- `DATA_DIR` = `/var/data`

## 💻 تشغيل محلي
```bash
npm install
npm run dev
```
