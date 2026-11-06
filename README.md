# EGZO License API

Сервер проверки ключей для Railway. В репозиторий не добавляются реальные ключи, токены, `.env` и пароли.

## Railway

1. Создай проект Railway.
2. Нажми **New → PostgreSQL**.
3. Нажми **New → GitHub Repo** и выбери этот репозиторий.
4. В сервисе API добавь Variables:

   - `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`
   - `ADMIN_API_KEY` = длинный случайный пароль
   - `LICENSE_PEPPER` = другой длинный случайный пароль

5. В **Networking** сгенерируй публичный домен. Это будет адрес API, например `https://...up.railway.app`.

## Добавление ключей

Отправь запрос только со своего компьютера. Не публикуй `ADMIN_API_KEY`.

```powershell
$headers = @{ "X-Admin-Key" = "ТВОЙ_ADMIN_API_KEY" }
$body = @{ duration_days = 14; keys = @("egzo-пример-ключ") } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://ТВОЙ-ДОМЕН/v1/admin/licenses" -Headers $headers -ContentType "application/json" -Body $body
```

Проверка для лоадера: `POST /v1/licenses/validate` с JSON `{"key":"...","device_id":"..."}`.
