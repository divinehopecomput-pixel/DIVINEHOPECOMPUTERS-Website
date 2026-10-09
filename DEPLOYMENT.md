# Deployment checklist

## Hosting architecture
This is a Node.js application, not a GitHub Pages-only site. Deploy the Node server to a Node-compatible host (or Docker host) and provision MySQL 8+ separately. Configure the app service to run `npm start`; use port supplied by the host.

## Environment variables
Set these in the hosting provider's secret/environment settings:
- `NODE_ENV=production`
- `PORT` (usually injected by host)
- `APP_URL=https://your-domain.example`
- `CORS_ORIGINS=https://your-domain.example` (exact origins only)
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- `DB_SSL=true` if required by the managed MySQL provider
- `JWT_SECRET` (long random secret, 32+ characters)
- `PAYSTACK_SECRET_KEY` (server-only secret)
- `PAYSTACK_CALLBACK_URL=https://your-domain.example/payment/callback`
- `ADMIN_PASSWORD_HASH` can be a bcrypt hash used as a fallback comparison, but an admin row must exist in the database.

Never place real keys in GitHub files, client-side JavaScript or screenshots.

## Database setup
Run `database/schema.sql` against the production MySQL instance. Create a restricted database user and insert an admin row with a bcrypt hash. Back up the database before updates.

## Paystack
Configure the webhook to `https://your-domain.example/api/payments/paystack/webhook`. Test card and mobile money payments in test mode. Confirm the order is marked paid only after amount/currency/reference verification, and verify failed, abandoned, duplicate webhook and stock-restoration scenarios before going live.

## After deploy
- Confirm `/api/health` returns `{"status":"ok"}`.
- Add products at `/admin`.
- Check checkout callback and webhook delivery.
- Configure domain and HTTPS.
- Set database backups, logs, alerts and privacy/returns policies.
- Replace placeholder business contact details and verify product prices, images, inventory and delivery policies.

The repository contains application code only. Deployment, database provisioning, DNS, Paystack merchant approval and secret configuration require actions in the relevant provider accounts.
