-- Owner-applied follow-up to 001. No data reset, gateway config, or automatic execution.
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $preflight$ BEGIN
 IF current_user IN ('anon','authenticated','service_role','qr_claim','qr_admin','qr_api_owner') THEN RAISE EXCEPTION 'Apply as migration owner'; END IF;
 IF to_regprocedure('"velo-leaderboard".qr_v2_migration_version()') IS NULL THEN RAISE EXCEPTION 'Apply 001 first'; END IF;
 IF "velo-leaderboard".qr_v2_migration_version()<>2 THEN RAISE EXCEPTION 'Unexpected 001 version'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='service_role') THEN RAISE EXCEPTION 'Supabase service_role must already exist'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='qr_api_owner') THEN CREATE ROLE qr_api_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='qr_api_owner' AND (rolcanlogin OR rolinherit OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication))
 OR EXISTS(SELECT FROM pg_auth_members WHERE roleid='qr_api_owner'::regrole OR member='qr_api_owner'::regrole) THEN RAISE EXCEPTION 'qr_api_owner must be an isolated non-login role'; END IF;
END $preflight$;
CREATE SCHEMA IF NOT EXISTS alpine_qr_api;
-- Refuse a colliding namespace instead of revoking unrelated application privileges.
DO $shape$ BEGIN
 IF EXISTS(SELECT FROM pg_class WHERE relnamespace='alpine_qr_api'::regnamespace)
 OR EXISTS(SELECT FROM pg_proc WHERE pronamespace='alpine_qr_api'::regnamespace AND
  (proname NOT IN ('lookup_key','receipt_status','submit','list_scores','list_keys','register_key','revoke_key') OR proowner<>'qr_api_owner'::regrole))
 OR EXISTS(SELECT FROM pg_type WHERE typnamespace='alpine_qr_api'::regnamespace) THEN RAISE EXCEPTION 'API namespace collision: review before proceeding'; END IF;
END $shape$;

-- These are the only underlying capabilities of the non-login wrapper owner.
GRANT USAGE ON SCHEMA "velo-leaderboard" TO qr_api_owner;
GRANT EXECUTE ON FUNCTION "velo-leaderboard".qr_v2_lookup_key(text),"velo-leaderboard".qr_v2_receipt_status(uuid,text),"velo-leaderboard".qr_v2_submit(uuid,text,uuid,text,text,integer,bigint,text,text,text,text),"velo-leaderboard".qr_v2_list_scores(integer,integer),"velo-leaderboard".qr_v2_list_keys(),"velo-leaderboard".qr_v2_register_key(text,text,uuid,text),"velo-leaderboard".qr_v2_revoke_key(text) TO qr_api_owner;
-- Global only for this NEW isolated role; other owners' defaults are untouched.
ALTER DEFAULT PRIVILEGES FOR ROLE qr_api_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE OR REPLACE FUNCTION alpine_qr_api.lookup_key(k text)
RETURNS TABLE(kid text,public_pem text,device uuid,event text,active boolean,not_before_ms bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT * FROM "velo-leaderboard".qr_v2_lookup_key(k) $$;
CREATE OR REPLACE FUNCTION alpine_qr_api.receipt_status(r uuid,h text)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT "velo-leaderboard".qr_v2_receipt_status(r,h) $$;
CREATE OR REPLACE FUNCTION alpine_qr_api.submit(r uuid,k text,d uuid,e text,n text,t integer,a bigint,s text,h text,em text,ph text)
RETURNS text LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT "velo-leaderboard".qr_v2_submit(r,k,d,e,n,t,a,s,h,em,ph) $$;
CREATE OR REPLACE FUNCTION alpine_qr_api.list_scores(skip integer,take integer)
RETURNS TABLE(run_id uuid,entry_id uuid,participant_name text,time_ms integer,completed_at_ms bigint,entry_date date,email text,phone_number text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT * FROM "velo-leaderboard".qr_v2_list_scores(skip,take) $$;
CREATE OR REPLACE FUNCTION alpine_qr_api.list_keys()
RETURNS TABLE(kid text,public_pem text,device uuid,event text,active boolean,not_before_ms bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT * FROM "velo-leaderboard".qr_v2_list_keys() $$;
CREATE OR REPLACE FUNCTION alpine_qr_api.register_key(k text,p text,d uuid,e text)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT "velo-leaderboard".qr_v2_register_key(k,p,d,e) $$;
CREATE OR REPLACE FUNCTION alpine_qr_api.revoke_key(k text)
RETURNS void LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT "velo-leaderboard".qr_v2_revoke_key(k) $$;

-- No default PUBLIC EXECUTE window: all definitions and revokes commit atomically.
-- Strip inherited grants (including anon/authenticated) only inside this dedicated API.
DO $acl$
DECLARE f record; who text;
BEGIN
 REVOKE ALL ON SCHEMA alpine_qr_api FROM PUBLIC;
 FOR who IN SELECT DISTINCT pg_get_userbyid(a.grantee) FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.oid='alpine_qr_api'::regnamespace AND a.grantee<>0 AND a.grantee<>n.nspowner LOOP
  EXECUTE format('REVOKE ALL ON SCHEMA alpine_qr_api FROM %I',who);
 END LOOP;
 GRANT USAGE,CREATE ON SCHEMA alpine_qr_api TO qr_api_owner;
 FOR f IN SELECT p.oid,p.proowner,p.proacl,p.oid::regprocedure AS signature FROM pg_proc p WHERE p.pronamespace='alpine_qr_api'::regnamespace LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature);
  FOR who IN SELECT DISTINCT pg_get_userbyid(a.grantee) FROM aclexplode(coalesce(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantee<>0 AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f.signature,who);
  END LOOP;
  EXECUTE format('ALTER FUNCTION %s OWNER TO qr_api_owner',f.signature);
  EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',f.signature);
 END LOOP;
 REVOKE CREATE ON SCHEMA alpine_qr_api FROM qr_api_owner;
 GRANT USAGE ON SCHEMA alpine_qr_api TO service_role;
END $acl$;
-- Fail closed if anon/authenticated inherit unexpected API access through other roles.
DO $verify$ DECLARE who text; f record; BEGIN
 IF (SELECT count(*) FROM pg_proc WHERE pronamespace='alpine_qr_api'::regnamespace)<>7 THEN RAISE EXCEPTION 'Unexpected API overloads'; END IF;
 FOREACH who IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=who) THEN
   IF has_schema_privilege(who,'alpine_qr_api','USAGE') THEN RAISE EXCEPTION 'Unexpected inherited API schema privilege for %',who; END IF;
   FOR f IN SELECT oid FROM pg_proc WHERE pronamespace='alpine_qr_api'::regnamespace OR (pronamespace='"velo-leaderboard"'::regnamespace AND proname LIKE 'qr_v2_%') LOOP
    IF has_function_privilege(who,f.oid,'EXECUTE') THEN RAISE EXCEPTION 'Unexpected inherited RPC privilege for %',who; END IF;
   END LOOP;
   IF has_table_privilege(who,'"velo-leaderboard".qr_signed_claims','SELECT') OR has_table_privilege(who,'"velo-leaderboard".qr_device_keys','SELECT') THEN RAISE EXCEPTION 'Unexpected private table privilege for %',who; END IF;
  END IF;
 END LOOP;
END $verify$;
COMMIT;
