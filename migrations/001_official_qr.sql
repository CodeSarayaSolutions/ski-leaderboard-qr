-- Additive, rerunnable migration. Review/apply personally; never run automatically.
-- PostgreSQL 14+. Existing legacy rows, defaults, ACLs and policies are not changed.
BEGIN;
DO $owner$ BEGIN IF current_user IN ('qr_claim','qr_admin') THEN RAISE EXCEPTION 'Apply as the database/table owner, never an application role'; END IF; END $owner$;
CREATE SCHEMA IF NOT EXISTS "velo-leaderboard";
DO $migration$
DECLARE fresh boolean := to_regclass('"velo-leaderboard".entries') IS NULL;
BEGIN
 IF fresh THEN
  CREATE TABLE "velo-leaderboard".entries (
   id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
   participant_name varchar NOT NULL,
   time_ms integer NOT NULL CHECK (time_ms > 0),
   entry_date date NOT NULL,
   created_at timestamptz NOT NULL DEFAULT now(),
   phone_number varchar
  );
  ALTER TABLE "velo-leaderboard".entries ENABLE ROW LEVEL SECURITY;
 END IF;
END $migration$;

-- Reject incompatible legacy shapes without editing any row or legacy definition.
DO $shape$
DECLARE spec record; actual record; table_id oid := '"velo-leaderboard".entries'::regclass;
BEGIN
 IF (SELECT relkind FROM pg_class WHERE oid=table_id)<>'r'
 OR EXISTS(SELECT FROM pg_inherits WHERE inhrelid=table_id OR inhparent=table_id) THEN
  RAISE EXCEPTION 'entries must be an ordinary non-inherited table; review schema manually';
 END IF;
 FOR spec IN SELECT * FROM (VALUES
  ('id','uuid'::regtype,true),('participant_name','varchar'::regtype,true),
  ('time_ms','int4'::regtype,true),('entry_date','date'::regtype,true),
  ('created_at','timestamptz'::regtype,true),('phone_number','varchar'::regtype,false)
 ) AS expected(name,typ,required) LOOP
  SELECT atttypid,attnotnull INTO actual FROM pg_attribute WHERE attrelid=table_id AND attname=spec.name AND attnum>0 AND NOT attisdropped;
  IF NOT FOUND OR actual.atttypid<>spec.typ OR actual.attnotnull<>spec.required THEN
   RAISE EXCEPTION 'Incompatible entries column: %',spec.name;
  END IF;
 END LOOP;
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid=table_id AND contype='p'
   AND conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=table_id AND attname='id')]::smallint[]) THEN
  RAISE EXCEPTION 'entries needs its existing single-column UUID id primary key';
 END IF;
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid=table_id AND contype='c' AND convalidated
   AND regexp_replace(pg_get_constraintdef(oid),'[[:space:]()]','','g')='CHECKtime_ms>0') THEN
  RAISE EXCEPTION 'Cannot verify the existing entries time_ms > 0 check';
 END IF;
 IF EXISTS(SELECT FROM pg_attribute WHERE attrelid=table_id AND attnum>0 AND NOT attisdropped
   AND attname NOT IN ('id','participant_name','time_ms','entry_date','created_at','phone_number')
   AND attnotnull AND NOT atthasdef AND attidentity='' AND attgenerated='') THEN
  RAISE EXCEPTION 'Additional required entries column has no default';
 END IF;
 IF EXISTS(SELECT FROM pg_attribute WHERE attrelid=table_id AND attname IN ('id','created_at') AND NOT atthasdef) THEN
  RAISE EXCEPTION 'Preserve/provide the existing id and created_at defaults before migration';
 END IF;
END $shape$;

DO $roles$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='qr_claim') THEN CREATE ROLE qr_claim NOLOGIN; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='qr_admin') THEN CREATE ROLE qr_admin NOLOGIN; END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname IN ('qr_claim','qr_admin') AND (rolsuper OR rolbypassrls)) THEN
  RAISE EXCEPTION 'QR roles must not have SUPERUSER or BYPASSRLS';
 END IF;
END $roles$;
GRANT USAGE ON SCHEMA "velo-leaderboard" TO qr_claim,qr_admin;

CREATE TABLE IF NOT EXISTS "velo-leaderboard".qr_device_keys (
 kid text PRIMARY KEY CHECK(kid ~ '^[a-f0-9]{32}$'), public_pem text NOT NULL,
 device uuid NOT NULL, event text NOT NULL CHECK(event ~ '^[a-zA-Z0-9_-]{1,64}$'),
 active boolean NOT NULL DEFAULT true, not_before_ms bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS "velo-leaderboard".qr_signed_claims (
 run_id uuid PRIMARY KEY,
 entry_id uuid NOT NULL UNIQUE REFERENCES "velo-leaderboard".entries(id),
 kid text NOT NULL REFERENCES "velo-leaderboard".qr_device_keys(kid),
 device uuid NOT NULL, event text NOT NULL,
 participant_name text NOT NULL CHECK(length(participant_name) BETWEEN 1 AND 24),
 time_ms integer NOT NULL CHECK(time_ms BETWEEN 1 AND 3725000),
 completed_at_ms bigint NOT NULL,
 scope text NOT NULL CHECK(scope='fast/summit-competition-v2-r3-5s-r1'),
 payload_hash text NOT NULL CHECK(payload_hash ~ '^[a-f0-9]{64}$'),
 email text NOT NULL CHECK(length(email)<=254),
 phone_number text NOT NULL CHECK(phone_number ~ '^\+[1-9][0-9]{6,14}$'),
 submitted_at timestamptz NOT NULL DEFAULT now()
);
DO $private_shape$
DECLARE spec record; actual record;
BEGIN
 FOR spec IN SELECT * FROM (VALUES
 ('qr_device_keys','kid','text'::regtype),('qr_device_keys','public_pem','text'::regtype),
 ('qr_device_keys','device','uuid'::regtype),('qr_device_keys','event','text'::regtype),
 ('qr_device_keys','active','bool'::regtype),('qr_device_keys','not_before_ms','int8'::regtype),
 ('qr_signed_claims','run_id','uuid'::regtype),('qr_signed_claims','entry_id','uuid'::regtype),
 ('qr_signed_claims','kid','text'::regtype),('qr_signed_claims','device','uuid'::regtype),
 ('qr_signed_claims','event','text'::regtype),('qr_signed_claims','participant_name','text'::regtype),
 ('qr_signed_claims','time_ms','int4'::regtype),('qr_signed_claims','completed_at_ms','int8'::regtype),
 ('qr_signed_claims','scope','text'::regtype),('qr_signed_claims','payload_hash','text'::regtype),
 ('qr_signed_claims','email','text'::regtype),('qr_signed_claims','phone_number','text'::regtype),
 ('qr_signed_claims','submitted_at','timestamptz'::regtype)
 ) AS expected(tbl,col,typ) LOOP
  SELECT a.atttypid,a.attnotnull INTO actual FROM pg_attribute a WHERE a.attrelid=format('%I.%I','velo-leaderboard',spec.tbl)::regclass AND a.attname=spec.col AND a.attnum>0 AND NOT a.attisdropped;
  IF NOT FOUND OR actual.atttypid<>spec.typ OR NOT actual.attnotnull THEN RAISE EXCEPTION 'Incompatible QR companion column %.%',spec.tbl,spec.col; END IF;
 END LOOP;
 IF (SELECT count(*) FROM pg_attribute WHERE attrelid='"velo-leaderboard".qr_device_keys'::regclass AND attnum>0 AND NOT attisdropped)<>6
 OR (SELECT count(*) FROM pg_attribute WHERE attrelid='"velo-leaderboard".qr_signed_claims'::regclass AND attnum>0 AND NOT attisdropped)<>13 THEN RAISE EXCEPTION 'Unexpected QR companion columns'; END IF;
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='"velo-leaderboard".qr_signed_claims'::regclass AND contype='p' AND conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid='"velo-leaderboard".qr_signed_claims'::regclass AND attname='run_id')]::smallint[])
 OR NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='"velo-leaderboard".qr_signed_claims'::regclass AND contype='u' AND conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid='"velo-leaderboard".qr_signed_claims'::regclass AND attname='entry_id')]::smallint[])
 OR NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='"velo-leaderboard".qr_device_keys'::regclass AND contype='p' AND conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid='"velo-leaderboard".qr_device_keys'::regclass AND attname='kid')]::smallint[]) THEN RAISE EXCEPTION 'QR companion primary/unique constraints are incompatible'; END IF;
 IF EXISTS(SELECT FROM pg_policy WHERE polrelid IN ('"velo-leaderboard".qr_signed_claims'::regclass,'"velo-leaderboard".qr_device_keys'::regclass)) THEN
  RAISE EXCEPTION 'Unexpected QR companion policy: review privacy before migration';
 END IF;
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='"velo-leaderboard".qr_signed_claims'::regclass AND confrelid='"velo-leaderboard".entries'::regclass AND contype='f' AND convalidated AND confdeltype IN ('a','r')) THEN
  RAISE EXCEPTION 'Signed claims must have a non-cascading entries foreign key';
 END IF;
END $private_shape$;
CREATE INDEX IF NOT EXISTS qr_signed_claims_rank ON "velo-leaderboard".qr_signed_claims(time_ms,completed_at_ms,run_id);
ALTER TABLE "velo-leaderboard".qr_device_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE "velo-leaderboard".qr_signed_claims ENABLE ROW LEVEL SECURITY;

-- Remove inherited default ACL grants on the TWO new private tables only.
-- Existing entries ACLs, policies and database default privileges remain untouched.
DO $private_acl$
DECLARE tab text; grantee_name text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['qr_device_keys','qr_signed_claims'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM PUBLIC','velo-leaderboard',tab);
  FOR grantee_name IN SELECT DISTINCT pg_get_userbyid(a.grantee) FROM pg_class c
   CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=format('%I.%I','velo-leaderboard',tab)::regclass AND a.grantee<>0 AND a.grantee<>c.relowner LOOP
   EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM %I','velo-leaderboard',tab,grantee_name);
  END LOOP;
 END LOOP;
END $private_acl$;

CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_lookup_key(k text)
RETURNS TABLE(kid text,public_pem text,device uuid,event text,active boolean,not_before_ms bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT * FROM "velo-leaderboard".qr_device_keys WHERE qr_device_keys.kid=k
$$;
CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_receipt_status(r uuid,h text)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce((SELECT CASE WHEN payload_hash=h THEN 'saved' ELSE 'conflict' END FROM "velo-leaderboard".qr_signed_claims WHERE run_id=r),'new')
$$;
CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_submit(r uuid,k text,d uuid,e text,n text,t integer,a bigint,s text,h text,em text,ph text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE keyrow "velo-leaderboard".qr_device_keys; oldrow "velo-leaderboard".qr_signed_claims; linked_entry uuid;
BEGIN
 -- Shared prelaunch-reset lock BEFORE table locks; reset takes its exclusive counterpart.
 PERFORM pg_advisory_xact_lock_shared(172318,1);
 SELECT * INTO keyrow FROM "velo-leaderboard".qr_device_keys WHERE kid=k FOR SHARE;
 IF NOT FOUND OR NOT keyrow.active OR keyrow.device<>d OR keyrow.event<>e OR a<keyrow.not_before_ms
  OR a>(extract(epoch FROM clock_timestamp())*1000)::bigint+120000 OR s<>'fast/summit-competition-v2-r3-5s-r1' THEN RETURN 'rejected'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(r::text,0));
 SELECT * INTO oldrow FROM "velo-leaderboard".qr_signed_claims WHERE run_id=r;
 IF FOUND THEN
  IF oldrow.payload_hash=h AND oldrow.kid=k AND oldrow.device=d AND oldrow.event=e THEN RETURN 'saved'; END IF;
  RETURN 'conflict';
 END IF;
 -- New form submission only. Never copy phone/email into the legacy-readable table.
 INSERT INTO "velo-leaderboard".entries(participant_name,time_ms,entry_date,phone_number)
 VALUES(n,t,(to_timestamp(a/1000.0) AT TIME ZONE 'UTC')::date,NULL) RETURNING id INTO linked_entry;
 INSERT INTO "velo-leaderboard".qr_signed_claims(run_id,entry_id,kid,device,event,participant_name,time_ms,completed_at_ms,scope,payload_hash,email,phone_number)
 VALUES(r,linked_entry,k,d,e,n,t,a,s,h,em,ph);
 RETURN 'saved';
END $$;
CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_list_scores(skip integer,take integer)
RETURNS TABLE(run_id uuid,entry_id uuid,participant_name text,time_ms integer,completed_at_ms bigint,entry_date date,email text,phone_number text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT s.run_id,s.entry_id,s.participant_name,s.time_ms,s.completed_at_ms,(to_timestamp(s.completed_at_ms/1000.0) AT TIME ZONE 'UTC')::date,s.email,s.phone_number
 FROM "velo-leaderboard".qr_signed_claims s ORDER BY s.time_ms,s.completed_at_ms,s.run_id OFFSET greatest(0,skip) LIMIT least(50,greatest(1,take))
$$;
CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_list_keys()
RETURNS SETOF "velo-leaderboard".qr_device_keys LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT * FROM "velo-leaderboard".qr_device_keys ORDER BY event,device,kid $$;
CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_register_key(k text,p text,d uuid,e text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN INSERT INTO "velo-leaderboard".qr_device_keys VALUES(k,p,d,e,true,(extract(epoch FROM clock_timestamp())*1000)::bigint); END $$;
CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_revoke_key(k text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$ UPDATE "velo-leaderboard".qr_device_keys SET active=false WHERE kid=k $$;
CREATE OR REPLACE FUNCTION "velo-leaderboard".qr_v2_migration_version()
RETURNS integer LANGUAGE sql SET search_path=pg_catalog AS $$ SELECT 2 $$;

-- Do not inherit broad legacy EXECUTE defaults on these new QR functions.
DO $function_acl$
DECLARE f record; grantee_name text;
BEGIN
 FOR f IN SELECT p.oid,p.proowner,p.proacl,p.oid::regprocedure AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='velo-leaderboard' AND p.proname IN ('qr_v2_lookup_key','qr_v2_receipt_status','qr_v2_submit','qr_v2_list_scores','qr_v2_list_keys','qr_v2_register_key','qr_v2_revoke_key','qr_v2_migration_version') LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature);
  FOR grantee_name IN SELECT DISTINCT pg_get_userbyid(a.grantee) FROM aclexplode(coalesce(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantee<>0 AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f.signature,grantee_name);
  END LOOP;
 END LOOP;
END $function_acl$;
GRANT EXECUTE ON FUNCTION "velo-leaderboard".qr_v2_lookup_key(text),"velo-leaderboard".qr_v2_receipt_status(uuid,text),"velo-leaderboard".qr_v2_submit(uuid,text,uuid,text,text,integer,bigint,text,text,text,text) TO qr_claim;
GRANT EXECUTE ON FUNCTION "velo-leaderboard".qr_v2_list_scores(integer,integer),"velo-leaderboard".qr_v2_list_keys(),"velo-leaderboard".qr_v2_register_key(text,text,uuid,text),"velo-leaderboard".qr_v2_revoke_key(text) TO qr_admin;
COMMIT;
