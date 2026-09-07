# QU — Queue, without the waiting

QU is a production-oriented queue management SaaS for physical service businesses. Customers join a queue, receive a secure ticket, leave the waiting area, and return when their turn is approaching.

## What is included

- Customer self-service queue joining
- Company-first queue setup with services and stations
- Secure customer ticket access tokens and QR/public company access
- Staff queue controls: Call, Arrive, Start, Finish, Skip, No-show, Cancel
- Station/service compatibility checks
- Automatic no-show handling and configurable grace period
- Persistent SQLite database with WAL mode
- Real-time Server-Sent Events for queue updates
- Wait-time ranges based on recent service history and station capacity
- Owner and staff roles with organization/company isolation
- Immutable queue event history
- Rate limiting and bounded request bodies
- Password hashing with Node crypto scrypt
- Signed session tokens with HMAC-SHA256
- Responsive customer, staff and owner interfaces
- **Zero npm runtime dependencies**

## Requirements

Node.js **22.5+**. Node 24 is recommended.

This build intentionally uses Node's built-in `node:sqlite`, so there is no native npm dependency to compile.

## Run

```bash
cd backend
npm install
npm start
```

Open http://localhost:3000

## Demo accounts

Owner:
`owner@qu.local`
`password`

Receptionist:
`reception@qu.local`
`password`

Company access is configured at the organization level rather than via a branch code.

## Production configuration

Set these environment variables before deployment:

- `NODE_ENV=production`
- `QU_JWT_SECRET=<long random secret>`
- `QU_DB_PATH=/persistent/path/qu.sqlite`
- `PORT=3000`
- `HOST=0.0.0.0`

For a serious multi-instance deployment, move persistence from SQLite to PostgreSQL and put a shared event/notification layer behind the API. The domain boundaries in `backend/src/services/queue.js` are intentionally designed so that migration can be done without rewriting the frontend.

## Architecture

```text
Browser
  │
  ├── Customer UI ──┐
  ├── Staff UI ─────┼── HTTP JSON API
  └── Owner UI ─────┘        │
                             ├── Auth / authorization
                             ├── Queue domain service
                             ├── No-show worker
                             ├── SSE real-time events
                             └── SQLite persistence
```

## Important production boundary

This is a strong pilot-ready codebase, not a claim that one ZIP file is magically enterprise infrastructure. Before a high-volume public launch, add PostgreSQL, HTTPS/reverse proxy, managed secrets, backups, observability, OTP/SMS/WhatsApp provider integration, CI, and load testing.
# QueueOS

## Deploy on Render

1. Push this folder to a GitHub repository.
2. In Render, choose **New > Blueprint** and select that repository.
3. Render detects [`render.yaml`](./render.yaml) and creates the web service.
4. Set `QU_PLATFORM_OWNER_EMAIL` and `QU_PLATFORM_OWNER_PASSWORD` when prompted.
5. Deploy. Render provides an HTTPS URL such as `https://qu-queue.onrender.com`.

The included persistent disk keeps the SQLite database under `/var/data`. Review
Render's current free-plan storage and availability limits before using this for
real businesses.
