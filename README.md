# SlideMind

A full-stack MVP for turning user-authorized screen captures into editable AI presentations.

## Run

1. Install Node.js 20+.
2. Run `npm install`.
3. Copy `.env.example` to `.env`.
4. Set `OPENAI_API_KEY`.
5. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` for first-run admin creation.
6. For real email verification/reset, configure SMTP.
7. Run `npm start`.
8. Open http://localhost:3000

## Important

- The browser's screen-capture API requires explicit user permission.
- The application is designed for material the user is authorized to capture.
- Admins cannot view passwords or bypass the registered-email verification flow.
- Configure HTTPS and `COOKIE_SECURE=true` in production.
- Replace the bootstrap admin password immediately.
- For production scale, move SQLite to a managed database and put file/object storage behind a private bucket.
- Add rate limiting, CSRF protection appropriate to your deployment architecture, centralized logging, backups, monitoring, and a secrets manager before public launch.

## AI

The server sends captured images to the configured OpenAI Responses API and requests structured slide JSON. Keep your API key server-side; never put it in browser JavaScript.

## Export

PPTX export creates editable text/shapes rather than simply embedding the captured screenshot.

## Admin support workflow

1. Admin creates a support request for a user.
2. User sees the request after signing in and explicitly approves it.
3. The user's registered email receives a security code.
4. The admin can complete the authorized password-help action only with that code.
5. The admin never sees the existing password and cannot retrieve it.

This is deliberately stronger than an unrestricted admin password-reset mechanism.
