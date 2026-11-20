# Alpine Slalom official QR leaderboard

Standalone Next.js app. The Quest never contacts this server. Only an explicit, valid phone form submission inserts an official score. Scanning/preview and signature validation are read-only. No local-score import or backfill endpoint exists. Nothing has been deployed or connected to a live database.

## Local setup

Use Node 20.19.2 or a compatible supported release. `npm ci`, `npm test`, `npm run build`, then `npm start`. Use the custom server, not `next start`: local mode binds only `127.0.0.1`, checks the actual peer address and Host, rejects forwarded requests, and marks requests internally before allowing local admin authentication. Do not put a reverse proxy or tunnel in front of local mode. The app cannot accept a local PIN through an ordinary Next server.

Copy `.env.example` to the ignored `.env.local`. Enter `ADMIN_LOCAL_PIN` privately in that file; it has no default. The exact local file is `<app-directory>/.env.local`. Never put it in chat, source, a `NEXT_PUBLIC_` variable or a command-line argument. Set a separately generated `SESSION_SECRET` of at least 32 characters privately. All admin verification is server-side. Sessions are HttpOnly, SameSite Strict, expire after one hour, and are Secure in public mode. Sign-in has a global eight-attempt/15-minute rate limit; claim requests have a bounded 300/minute global limit. Use one server process; multiple replicas require a shared rate-limit store before operation. Restart resets in-memory rate limits. Do not expose the Node inspector.

For future public hosting set `ADMIN_MODE=public`, an HTTPS `APP_ORIGIN`, and a separate high-entropy `ADMIN_PUBLIC_CREDENTIAL` of at least 16 characters. Four-digit credentials and missing public credentials fail closed. Public mode never uses the local PIN. Keep Node bound to loopback behind your own HTTPS reverse proxy. Configure the proxy to suppress request bodies, authorization/cookies, and sensitive logging; do not add analytics or third-party scripts. HTTPS and the real domain/port have not been configured.

## Database: additive legacy-compatible migration

Review and personally apply `migrations/001_official_qr.sql` as the database/table owner on PostgreSQL 14+ or self-hosted Supabase. It targets exact quoted schema `"velo-leaderboard"` and legacy table `entries`. Existing rows, defaults, privileges, policies and nullable legacy phone values are preserved. Fresh installs receive the stated legacy table shape with RLS enabled and no public policy. Incompatible column/constraint shapes fail the transaction. Rerunning the migration does not remove or backfill scores. Nothing runs this migration automatically.

New official submissions insert one legacy-compatible `entries` row and one private `qr_signed_claims` row, linked by a non-cascading foreign key. `entries.id` keeps its existing UUID default; the stable signed run UUID is separately unique in `qr_signed_claims.run_id`. Historical entries have no fabricated email, signed completion time or claim marker and never appear on the official admin board. Official ranking reads immutable signed name/time snapshots in `qr_signed_claims`, ordered integer milliseconds, signed completion milliseconds, then run UUID. It does not trust later legacy edits. Entry dates for new rows derive from signed completion time in UTC.

New QR email and phone are stored **only** in the private companion table. New `entries.phone_number` is explicitly NULL, so existing legacy readers cannot silently gain new QR contacts. The two QR companion tables have RLS enabled, no direct-reader policies, and default ACL grants are removed only from those new private tables/functions. Existing `entries` access and database default privileges are not rewritten. Database owners/superusers remain trusted administrators. Do not grant new QR functions or private tables to anonymous/browser roles or add broad private-table RLS policies.

Runtime now uses server-only Supabase HTTP RPC. See [SUPABASE-HTTP-SETUP.md](SUPABASE-HTTP-SETUP.md) for the four existing environment names, additive migration 002, dedicated alpine_qr_api profile, service-role trust boundary and operator acceptance steps. No direct PostgreSQL runtime connection is used. Apply 001 then 002; neither runs automatically.

Signature verification occurs after a read-only key lookup and before any claim write. The submit transaction rechecks active key/device/event/not-before time under a row lock, serializes each run ID, and writes only on first valid form submission. Preview/status are read-only. Repeats never overwrite rows/contacts and never return stored contacts. Shared/exclusive advisory locks coordinate submissions with optional maintenance. The admin shows only linked signed claims, with 50-row pagination.

For an owner-chosen fresh legacy board, see `maintenance/README.md` and the separate **manual opt-in** `maintenance/manual_reset_legacy_entries.sql`. Apply migration 001 first, back up/preview, then explicitly confirm in the same owner session. The script removes only unclaimed legacy entries, protects signed claims and other schemas, and refuses unsafe dependencies. It is outside migration discovery and is never executed by the app. It has not been executed on any live database.

## Headset enrollment and URL

On an authorized device update, preserve application data and its Android Keystore. Configure `offline-qr-config.json` in the app's persistent data directory, outside source and APK. This example contains no secret:

```json
{"enabled":false,"provisionKey":true,"keyRegistered":false,"deviceId":"REPLACE_WITH_32_LOWERCASE_HEX_UUID","eventId":"REPLACE_WITH_EVENT_SLUG","publicUrl":"https://leaderboard.example.invalid/scan"}
```

Replace the placeholder URL with the actual HTTPS `/scan` URL (under 200 characters, no query, fragment or credentials), and set the same event slug in server `EVENT_ID`. The `.invalid` placeholder deliberately cannot produce a QR. After operator provisioning is enabled, the next eligible completion generates a P-256 signing key in Android Keystore, and exports **only** `offline-qr-public-key.pem` and `offline-qr-key-id.txt`. Private key bytes are nonexportable and never embedded in source/APK or copied to the server. This enrollment run is local-only. Register that public PEM and device/event in `/admin`, then set `provisionKey=false`, `keyRegistered=true`, `enabled=true` in the device config. Make a NEW run after registration. Old runs are never enumerated for QR signing. Revoking the key in admin blocks subsequent validation/submission, including scans of old receipts. There is no reactivation endpoint; key replacement requires explicit operator work.

Keep the offline headset clock accurate. Completion time is signed and cannot be corrected after a run; future times over two minutes and new submissions older than the configured window (seven days by default, maximum thirty) are rejected. Already recorded matching submissions remain stable while the key is active. Configure and check the clock before the event. Hardware-backed storage availability depends on the Quest; the implementation requires Android Keystore nonexportable keys but does not claim StrongBox attestation.

## Protocol and privacy

Version 1 uses canonical UTF-8 JSON in fixed key order: `v,kid,device,event,run,name,ms,at,scope`. Scope is `fast/summit-competition-v2-r3-5s-r1`. The envelope is base64url(JSON) + `.` + base64url(ECDSA SHA-256 DER signature). Android Java signs; Node verifies the same bytes, fixed schema, version, scope, event, public key fingerprint, activation time and revocation before any claim write. Authoritative Name/Time come only from the signed payload. Email and international phone are the only editable claim fields. The unique ID and signed payload hash remain unchanged on rescan.

The QR URL uses `/scan#r=...`; fragments never reach HTTP access logs. A head bootstrap removes the fragment and query from browser history immediately, then passes it once in memory to the form. No local/session storage, analytics, third-party fonts or payload logging. Reload after history stripping requires rescanning. POST bodies carry the receipt and contacts to your own HTTPS endpoint only. API contact responses are private/no-store. Staff may return to the local board with the right trigger immediately; the photographed QR remains independent of the headset and requires no acknowledgment.

## Verification and remaining acceptance

`npm test`: signature/tampering/version/scope, revocation, pre-registration replay, expiration, no insert on scan, exactly one insert on explicit submission, concurrent duplicate first-write, no contact disclosure, integer ordering, unauthorized/expired sessions, rate limits and public fail-closed tests. Receipt/auth unit tests use an in-memory repository; migration and RPC tests additionally execute disposable PGlite PostgreSQL. No live DB is used.

`node test/cross-runtime.mjs <fixture-directory>` verifies the actual Unity C# payload signed by a temporary in-memory Java key in Node, then decodes Nayuki QR matrices with jsQR. Fixtures contain a public key and synthetic run only; no private key is persisted. Final QR size is 420 UI pixels; 420/450/600 pixel decoding passed. The earlier 300-pixel sample failed and the final game layout was enlarged accordingly.

Run `node test/browser.mjs` with the loopback app running for mocked mobile scan/form/submission/history and unauthorized admin checks. Browser screenshots are under `test-evidence`. Mock routing is test-only, never a server bypass. `npm run build` passed without database configuration. Real deployment acceptance, multi-session concurrency/revocation races, mobile camera scanning through the actual TV crop, Quest Keystore provisioning, headset clock, and public TLS remain operator acceptance work.

Still needed: public HTTPS domain/port and event ID, migration approval/application and scoped database logins, private session/admin configuration, authorized device provisioning and public-key registration. Do not send privileged secrets in chat.

## Final unbranded palette provenance

The web UI uses no logos, sponsor names, branded images or game footage. Background `#10202B` follows the event operator's explicit color direction; no identical existing asset token was found, so this is not claimed as a recovered historical value. Action/header cyan `#5EC7F5` is the nearest 8-bit RGB conversion of the existing game `Ice` / ski stripe color `(0.37, 0.78, 0.96)` in `SlalomGame.cs` and `SlalomHUD.cs`. Fields/panels `#061721` derive from the existing ski carbon material `(0.025, 0.09, 0.13)` in `SlalomGame.CreateSkis`. Text is `#ECF6FA`, muted text `#A7BDC8`, focus outline `#FFFFFF`, and error text `#FFC0AD`. These are source color values, not a claim about calibrated rendered pixel colors. Measured text/background contrast is 15.14:1; action text/cyan 8.68:1; muted text 8.51:1. Evidence: `test-evidence/palette-contrast.json` and final mobile screenshots.

## Disposable SQL verification

`npm test` also runs `test/migration.test.mjs` against fresh in-memory PGlite PostgreSQL instances, not an endpoint. Tests exercise fresh and legacy-seeded installation, harmless reruns, legacy row/default/policy/ACL preservation, inherited legacy-reader contact isolation, read-only preview, exactly one linked submission, duplicate first-write, incompatible schema rollback, opt-in reset, preservation of signed and other-schema rows, and refusal of unsafe dependencies. The local Docker engine was unavailable; PGlite is real PostgreSQL compiled to WASM with one exclusive connection. Multi-session advisory-lock contention and the intended hosting roles/TLS still need operator acceptance testing. No live database was contacted. [PGlite documentation](https://pglite.dev/docs/).
