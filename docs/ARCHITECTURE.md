# QU Architecture

## Domain rules

Queue entries use an explicit state machine:

`WAITING → CALLED → ARRIVED → SERVING → COMPLETED`

Side paths include cancellation, skip and no-show. Terminal tickets may be restored except completed tickets.

A customer ticket is identified by a numeric database ID plus a high-entropy access token. The token is never stored in plaintext.

## Tenant isolation

Authenticated staff are tied to an organization and branch. Every owner/staff branch lookup verifies the requested branch belongs to the authenticated organization.

Customers have no authenticated staff role and can only access their own ticket when they present the ticket access token.

## Concurrency

Ticket numbering is performed inside a SQLite transaction using a per-branch/per-day counter. Queue transitions use an optimistic status check so a stale receptionist action cannot silently overwrite a newer state.

## Real-time

SSE broadcasts branch-scoped queue events. Customer pages also poll as a resilience fallback.

## Scaling path

SQLite/WAL is suitable for a pilot or single application instance. For multiple application instances, use PostgreSQL for durable shared state and Redis/pub-sub or another shared event system for real-time fan-out.
