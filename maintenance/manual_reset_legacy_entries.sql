-- MANUAL OPT-IN ONLY. Outside migrations. Owner runs personally after 001.
-- First back up and run the preview in maintenance/README.md.
-- Deliberately set this session value separately before executing this file:
-- SET alpine.confirm_legacy_reset = 'DELETE LEGACY WEB ENTRIES ONLY';
BEGIN;
SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';
SET LOCAL row_security = off;
DO $confirm$
BEGIN
 IF current_setting('alpine.confirm_legacy_reset',true) IS DISTINCT FROM 'DELETE LEGACY WEB ENTRIES ONLY' THEN
  RAISE EXCEPTION 'Reset not authorized: set the documented exact session confirmation separately';
 END IF;
 IF to_regclass('"velo-leaderboard".entries') IS NULL
 OR to_regclass('"velo-leaderboard".qr_signed_claims') IS NULL
 OR to_regprocedure('"velo-leaderboard".qr_v2_migration_version()') IS NULL THEN
  RAISE EXCEPTION 'Apply and verify migration 001 before this manual reset';
 END IF;
 IF "velo-leaderboard".qr_v2_migration_version()<>2 THEN RAISE EXCEPTION 'Unexpected migration version'; END IF;
END $confirm$;

-- Same lock order as qr_v2_submit: this waits for in-flight claims and excludes new claims.
SELECT pg_advisory_xact_lock(172318,1);
LOCK TABLE "velo-leaderboard".entries IN ACCESS EXCLUSIVE MODE;
LOCK TABLE "velo-leaderboard".qr_signed_claims IN SHARE ROW EXCLUSIVE MODE;

DO $safety$
DECLARE entries_id oid := '"velo-leaderboard".entries'::regclass;
 claims_id oid := '"velo-leaderboard".qr_signed_claims'::regclass;
 spec record; actual record; id_att smallint; entry_att smallint; run_att smallint;
BEGIN
 IF EXISTS(SELECT FROM pg_class WHERE oid IN (entries_id,claims_id) AND relkind<>'r')
 OR EXISTS(SELECT FROM pg_inherits WHERE inhrelid IN (entries_id,claims_id) OR inhparent IN (entries_id,claims_id)) THEN
  RAISE EXCEPTION 'Unsafe reset: partitioned/inherited/non-table dependency';
 END IF;
 FOR spec IN SELECT * FROM (VALUES
  ('entries','id','uuid'::regtype,true),('entries','participant_name','varchar'::regtype,true),
  ('entries','time_ms','int4'::regtype,true),('entries','entry_date','date'::regtype,true),
  ('entries','created_at','timestamptz'::regtype,true),('entries','phone_number','varchar'::regtype,false),
  ('qr_signed_claims','run_id','uuid'::regtype,true),('qr_signed_claims','entry_id','uuid'::regtype,true),
  ('qr_signed_claims','kid','text'::regtype,true),('qr_signed_claims','device','uuid'::regtype,true),('qr_signed_claims','event','text'::regtype,true),('qr_signed_claims','scope','text'::regtype,true),('qr_signed_claims','submitted_at','timestamptz'::regtype,true),('qr_signed_claims','participant_name','text'::regtype,true),('qr_signed_claims','time_ms','int4'::regtype,true),
  ('qr_signed_claims','completed_at_ms','int8'::regtype,true),('qr_signed_claims','payload_hash','text'::regtype,true),
  ('qr_signed_claims','email','text'::regtype,true),('qr_signed_claims','phone_number','text'::regtype,true)
 ) AS expected(tbl,col,typ,required) LOOP
  SELECT atttypid,attnotnull INTO actual FROM pg_attribute WHERE attrelid=format('%I.%I','velo-leaderboard',spec.tbl)::regclass AND attname=spec.col AND attnum>0 AND NOT attisdropped;
  IF NOT FOUND OR actual.atttypid<>spec.typ OR actual.attnotnull<>spec.required THEN RAISE EXCEPTION 'Unsafe reset shape: %.%',spec.tbl,spec.col; END IF;
 END LOOP;
 SELECT attnum INTO id_att FROM pg_attribute WHERE attrelid=entries_id AND attname='id';
 SELECT attnum INTO entry_att FROM pg_attribute WHERE attrelid=claims_id AND attname='entry_id';
 SELECT attnum INTO run_att FROM pg_attribute WHERE attrelid=claims_id AND attname='run_id';
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid=entries_id AND contype='p' AND conkey=ARRAY[id_att])
 OR NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid=claims_id AND contype='p' AND conkey=ARRAY[run_att])
 OR NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid=claims_id AND contype='u' AND conkey=ARRAY[entry_att])
 OR NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid=claims_id AND confrelid=entries_id AND contype='f' AND conkey=ARRAY[entry_att] AND confkey=ARRAY[id_att] AND convalidated AND confdeltype IN ('a','r')) THEN
  RAISE EXCEPTION 'Unsafe reset: signed claim primary/unique/foreign key protection missing';
 END IF;
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid=entries_id AND contype='c' AND convalidated AND regexp_replace(pg_get_constraintdef(oid),'[[:space:]()]','','g')='CHECKtime_ms>0')
 OR EXISTS(SELECT FROM pg_attribute WHERE attrelid=entries_id AND attname IN ('id','created_at') AND NOT atthasdef) THEN RAISE EXCEPTION 'Unsafe reset: legacy check/default shape changed'; END IF;
 IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid=claims_id)
 OR EXISTS(SELECT FROM pg_policy WHERE polrelid=claims_id) THEN RAISE EXCEPTION 'Unsafe reset: unexpected signed-claim privacy policy'; END IF;
 IF EXISTS(SELECT FROM pg_trigger WHERE tgrelid=entries_id AND NOT tgisinternal)
 OR EXISTS(SELECT FROM pg_rewrite WHERE ev_class=entries_id) THEN
  RAISE EXCEPTION 'Unsafe reset: entries has user triggers or rewrite rules; review manually';
 END IF;
 IF EXISTS(SELECT FROM pg_constraint WHERE confrelid=entries_id AND contype='f'
  AND NOT(conrelid=claims_id AND conkey=ARRAY[entry_att] AND confkey=ARRAY[id_att] AND convalidated AND confdeltype IN ('a','r'))) THEN
  RAISE EXCEPTION 'Unsafe reset: additional incoming foreign-key dependency; no data changed';
 END IF;
END $safety$;

-- Only legacy/unclaimed entries are removed. Signed claims and all other tables stay intact.
WITH removed AS (
 DELETE FROM "velo-leaderboard".entries e
 WHERE NOT EXISTS(SELECT 1 FROM "velo-leaderboard".qr_signed_claims c WHERE c.entry_id=e.id)
 RETURNING e.id
) SELECT count(*) AS legacy_entries_removed FROM removed;
COMMIT;
RESET alpine.confirm_legacy_reset;
