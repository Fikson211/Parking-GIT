# Parking GIT (Node.js + PostgreSQL)

## Railway (самый быстрый способ)
1) Залей проект в GitHub.
2) Railway → New Project → Deploy from GitHub Repo.
3) Railway → Add Plugin → PostgreSQL.
4) В сервисе **Web** → Variables:
   - `DATABASE_URL` (обычно Railway добавляет сам после подключения Postgres)
   - `SESSION_SECRET` (любой длинный текст)
   - (опционально) `ADMIN_PHONE`, `ADMIN_PIN`, `ADMIN_FIO`
5) Web → Settings → Start Command: `npm start` (по умолчанию)
6) Web → Networking → Domain → Generate Domain.

Приложение само создаст таблицы в БД и (если нет такого телефона) создаст админа по `ADMIN_PHONE`.

## Локально
```bash
npm i
set DATABASE_URL=postgresql://...
set SESSION_SECRET=dev
npm start
```
Открой: http://localhost:8080
