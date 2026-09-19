# Procurely — Mini B2B RFQ Marketplace

Procurely is a compact full-stack application where buyers create and manage RFQs, and suppliers find open requirements and submit one quotation per RFQ.

## Live Demo

[Open the live application](https://b2b-rfq-platform.onrender.com)

## Technology

- **Backend:** Node.js built-in HTTP server and REST API
- **Database:** SQLite via Node's built-in `node:sqlite` module (persistent local `data/rfq.db`)
- **Auth:** Node crypto `scrypt` password hashing and signed bearer tokens
- **Frontend:** Responsive vanilla HTML, CSS and JavaScript (no build step)

## Run locally

1. Install Node.js 22.5+ (Node 24 is recommended for the built-in SQLite API).
2. Copy `.env.example` to `.env` and use a long random `JWT_SECRET`.
3. Run `npm start`, then visit `http://localhost:3000`.

The database is created automatically on first launch. Create a Buyer account to publish an RFQ, then create a separate Supplier account to browse and quote it.

## Architecture

The Node HTTP server owns API routes, authorization, validation and database access. It serves the static single-page frontend from `public/`. SQLite has three relational tables (`users`, `rfqs`, `quotations`) with foreign keys and a unique `(rfq_id, supplier_id)` constraint. Signed bearer-token checks authenticate protected routes and enforce Buyer/Supplier permissions before a query is performed. In production, the server refuses to start without an explicit `JWT_SECRET`.

## API overview

- `POST /api/auth/signup`, `POST /api/auth/login`
- `GET/POST /api/rfqs`, `GET /api/rfqs/mine`, `GET/PUT /api/rfqs/:id`
- `GET /api/rfqs/:id/quotations`, `POST /api/rfqs/:id/quotations`
- `GET /api/quotations/mine`

## Deployment

This app can run on a Node host such as Render or Railway: set the start command to `npm start`, use Node 22.5+, provide a strong `JWT_SECRET`, and attach persistent storage because the SQLite database is stored on disk. For production scale, replace SQLite with managed PostgreSQL, add rate limiting, and store authentication in an HTTP-only secure cookie.

## Assumptions / limitations

- Currency is shown as INR but price is a generic numeric quote.
- RFQs stay open until their deadline; a manual close/award workflow is intentionally out of scope.
- Supplier quotations are immutable after submission; suppliers may submit one quote per RFQ.
- The default JWT development secret is for local development only and must be changed in production.
