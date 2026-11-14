# CipherVote — Secure E-Voting System

College project for a four-member team. Member 4 owns the Flask app, UI, integration, and dashboards. This repository provides a runnable integration shell and replaceable stubs for Members 1–3.

> **Academic demonstration only.** This is not an election-grade system. Do not use it for public, governmental, organizational, or otherwise consequential elections. It has not undergone independent cryptographic, privacy, accessibility, or security review.

## Stack and agreed integration contract

- Python 3.11+, Flask, Flask-WTF/CSRF, SQLite, Bootstrap 5, Chart.js.
- `users`: login identity, password hash, role and one-vote eligibility flag.
- `candidates`: candidate display data.
- `vote_tokens`: one short-lived, single-use token per voter.
- `ballots`: anonymous receipt id, random commitment hash, previous hash, chain hash, timestamp. There is no voter id and no candidate field.
- `tally_counts`: candidate id and aggregate count only; no voter or ballot id.
- `security_events`: event type, severity, score, reviewed flag, and simulated-data flag.
- Member 1: authentication/eligibility implementation; expose its Blueprint as `members.member1_auth.bp`.
- Member 2: cryptography/receipt verification implementation; expose `members.member2_crypto.bp`.
- Member 3: anomaly detection implementation; expose `members.member3_ml.bp`.
- Current mount points: `/member1`, `/member2`, `/member3`. Keep the shared schema and response contract unless the full team agrees on a migration.
- Vote API: `POST /api/vote/token` (authenticated voter, CSRF header) returns a short-lived token; `POST /api/vote/cast` accepts `candidate_id`, `token`, and CSRF form token, returns only `{receipt: {ballot_id, ballot_hash}}`.

### Privacy and verification boundary

The browser briefly shows the selected candidate for confirmation. After submission, the response contains only receipt metadata; the vote page does not retain the choice, and the app does not log or store a voter-to-candidate mapping. Server storage increments an aggregate count in the same transaction that records an anonymous receipt.

That design means the hash chain can detect edits to anonymous receipt records, but it **cannot independently recompute each candidate tally from ballot contents** because those contents are intentionally discarded. Results are released only when the receipt chain verifies, but the aggregate tally table itself is not a zero-knowledge proof or cryptographic tally. Document this limitation in the viva. If the team needs a cryptographically auditable tally, agree on an encrypted-ballot and decryption/aggregation protocol with Member 2 before merging; do not add a plaintext candidate field to `ballots`.

## Repository layout

```text
secure_evoting/
├── app.py
├── config.py
├── database/{db.py,schema.sql}
├── members/{member1_auth.py,member2_crypto.py,member3_ml.py}
├── templates/                 # Bootstrap pages and accessible form states
├── static/css/app.css
├── tests/test_integration.py
├── seed_demo.py
├── requirements.txt
└── .env.example
```

## Setup (VS Code / Windows PowerShell)

1. Open the `secure_evoting` folder in VS Code.
2. In Terminal, create and activate a virtual environment:

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Set environment variables for this PowerShell window. Create a unique local secret (do not commit it):

   ```powershell
   $env:SECRET_KEY = (py -c "import secrets; print(secrets.token_hex(32))")
   $env:DATABASE_PATH = "instance/evoting.db"
   $env:DEMO_ADMIN_PASSWORD = "AdminDemo!2026"
   $env:DEMO_VOTER_PASSWORD = "VoterDemo!2026"
   ```

   For a long-lived local setup, copy `.env.example` to `.env` and load it with your preferred environment-variable loader; `.env` is ignored by Git. Flask itself reads the process environment and does not parse `.env` automatically.

4. Seed demo data, then start the app:

   ```powershell
   py seed_demo.py
   py -m flask --app app run --debug
   ```

5. Open <http://127.0.0.1:5000>. VS Code users can select **CipherVote Flask** in Run and Debug after installing the Python and Python Debugger extensions. To run checks: `py -m pytest`.

Demo accounts (unless overridden above): `admin` / `AdminDemo!2026`; voters `voter01`–`voter20` / `VoterDemo!2026`. These predictable passwords are for local viva demonstrations only.

## Viva demo script (about two minutes)

1. Open `/` and point out the academic-demo notice and dark responsive interface.
2. Sign in as `voter01`. Open **Vote**, request a token, select a candidate, review the confirmation modal, and confirm.
3. Show the receipt page. It shows only ballot id and receipt hash. Return to the dashboard; it says submitted but never reveals the selection. Try voting again and show the duplicate-vote rejection.
4. Sign out; sign in as `admin`. The dashboard shows voter/ballot counts, candidates, and chain controls. Close the election, verify the chain, then tally.
5. Open **Results** and show aggregate bar/pie charts, valid-ballot count, and no voter-to-candidate view.
6. Open **Security** and point out severity labels, review action, score chart, and the visible simulated-data labels.
7. Optional tamper demo: in a local SQLite browser, alter one `ballots.chain_hash`, refresh results, and show the integrity failure and withheld tally. Run `py seed_demo.py` afterwards to reset.

## Member 4 integration checklist

- [ ] Agree the schema and endpoint contract above with all members before replacing stubs.
- [ ] Member 1: preserve password hashing, voter/admin role checks, and unique voter eligibility; run login and duplicate-vote tests.
- [ ] Member 2: review token entropy, expiry, hash chain format, receipt verification, and documented tally privacy boundary; never expose candidate choice through the receipt API.
- [ ] Member 3: provide a stable scoring function and event schema; label synthetic training/demo data and scores as simulated.
- [ ] Keep every browser form and state-changing API request CSRF-protected; ensure API clients send `X-CSRFToken`.
- [ ] Ensure SQL updates for eligibility, token consumption, anonymous receipt insertion, and aggregate increment are atomic.
- [ ] Verify admin-only routes, escaped template output, generic error pages, no secrets in JavaScript, and no voter-choice pair in DB/logs.
- [ ] Run `py -m pytest`, test narrow mobile viewport, and perform the manual demo from a clean seed.
- [ ] Review the project with the faculty/team before any non-demo deployment; no production readiness is claimed.

## Architecture

`create_app()` loads environment-backed config, initializes CSRF/database hooks, and registers three member Blueprints. Routes render Jinja pages and use the SQLite helper for short-lived requests. A voter first requests a random, expiring token. On confirmation, the cast route verifies role, election state, candidate, token, and one-vote eligibility; one database transaction consumes the token, marks eligibility used, increments an unlinked candidate aggregate, and writes an anonymous chained receipt. The browser receives receipt metadata only. The admin closes the election, checks the receipt chain, and releases the aggregate results. The security page reads event records and draws a Chart.js score line.

## Likely viva questions

1. **Why separate `users` and `ballots`?** To prevent a direct database relation from a voter account to a ballot record.
2. **How is a second vote prevented?** A single-use, expiring token plus a `has_voted` flag updated transactionally; a database uniqueness constraint prevents multiple active tokens per user.
3. **What does the receipt hash prove?** It identifies an anonymous receipt record and links it into the chain; it does not prove the chosen candidate or the correctness of the aggregate tally.
4. **How is tampering detected?** Each chain hash is recomputed from its previous hash, receipt id, and receipt commitment. A mismatch blocks tally release.
5. **Why not store the choice in the ballot row?** That would permit a direct vote-content lookup and violate the project's ballot privacy goal.
6. **How are results calculated?** As aggregate candidate counters updated during a successful vote transaction, shown only after election close and chain verification.
7. **Is the tally cryptographically verifiable?** Not in this prototype. Independent tally proof would require an agreed encrypted-ballot protocol and a cryptographic aggregation design.
8. **What protects forms from CSRF?** Flask-WTF's global CSRF protection; HTML forms include hidden tokens and the token API checks the `X-CSRFToken` header.
9. **What does the ML module do?** The stub is an integration point; demo events and sample anomaly scores are explicitly labelled simulated until Member 3 supplies a model.
10. **Can this be used for a real election?** No. It is a student demonstration and lacks independent review, hardened operations, coercion resistance, verifiable cryptographic tallying, and certification.
