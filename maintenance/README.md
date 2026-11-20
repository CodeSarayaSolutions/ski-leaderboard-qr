# Manual prelaunch legacy reset — never an automatic migration

The owner may choose a fresh **web** leaderboard by deleting legacy rows that have no signed-claim link. This is optional, destructive, and unrelated to local headset/Windows scores. Nothing in the app or normal migration invokes this script. No reset has been executed against a live database.

## Order and review

1. Back up the database (including `"velo-leaderboard".entries`, `qr_signed_claims`, keys, policies and privileges), and verify the backup can be restored. Stop unrelated legacy writers for a predictable preview.
2. Review and personally apply `migrations/001_official_qr.sql` first. It is additive and rerunnable and **never deletes** existing score rows. Do not reset before the migration.
3. Preview counts as the database owner. These queries do not show contacts:

```sql
SELECT count(*) AS legacy_candidates
FROM "velo-leaderboard".entries e
WHERE NOT EXISTS (
  SELECT 1 FROM "velo-leaderboard".qr_signed_claims c WHERE c.entry_id=e.id
);
SELECT count(*) AS protected_signed_entries
FROM "velo-leaderboard".qr_signed_claims;
```

4. Only if the deletion is intended, open a dedicated owner session and **separately** execute:

```sql
SET alpine.confirm_legacy_reset = 'DELETE LEGACY WEB ENTRIES ONLY';
```

5. In the same session, execute the entire `maintenance/manual_reset_legacy_entries.sql` file. Do not paste it into migration discovery or an application startup command. It requires the exact session confirmation; returns only the number of removed legacy rows; and commits atomically. If a check fails, issue `ROLLBACK`, close the session and investigate. Do not weaken safety checks just to make it run.
6. Recheck counts and start/restart the event. A successful script clears its confirmation setting. Another reset requires a new deliberate confirmation.

## Effects and fail-closed behavior

The only modifying statement is a DELETE of unclaimed rows in exact table `"velo-leaderboard".entries`. This removes their legacy name/time/date/nullable phone values. It does not clear signed claims, signed entries, keys, other schemas, or any headset records. It uses no TRUNCATE, CASCADE or DROP. Normal migration reruns never invoke it.

The transaction verifies migration version, column types, primary/unique/non-cascading foreign keys and the private claims RLS shape. It refuses partition/inheritance, user triggers, rewrite rules and any unexpected inbound foreign-key dependency (including an otherwise harmless reference in another schema), rather than risking cascading effects. Owner privileges are required; `row_security=off` fails instead of silently applying a partial reset through filtering policies.

A shared advisory lock in every signed submission and the reset's matching exclusive lock serialize maintenance with official claims. Entries and claims table locks also protect the selection/deletion against ordinary writes while the reset runs. Lock acquisition has a five-second timeout; retry deliberately when busy. A legacy writer can add new legacy rows after the reset commits, which is why stopping legacy writers before launch is recommended. True multi-session lock behavior still needs verification on the intended PostgreSQL deployment.

Disposable tests use in-memory PGlite PostgreSQL only. They check fresh/seeded/rerun migration behavior, contact isolation, removal of legacy rows while preserving signed/other-schema rows, explicit confirmation, and refusal of unsafe dependencies. PGlite has one database connection; it does not replace production concurrency/permissions acceptance testing. No live endpoint is used.
