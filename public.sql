/*
 Date: 13/12/2025 22:42:54
*/


-- ----------------------------
-- Table structure for doc_changes
-- ----------------------------
DROP TABLE IF EXISTS "public"."doc_changes";
CREATE TABLE "public"."doc_changes" (
  "tenant" varchar(255) COLLATE "pg_catalog"."default" NOT NULL,
  "id" varchar(255) COLLATE "pg_catalog"."default" NOT NULL,
  "change_id" int4 NOT NULL,
  "user_id" varchar(255) COLLATE "pg_catalog"."default" NOT NULL,
  "user_id_original" varchar(255) COLLATE "pg_catalog"."default" NOT NULL,
  "user_name" varchar(255) COLLATE "pg_catalog"."default" NOT NULL,
  "change_data" text COLLATE "pg_catalog"."default" NOT NULL,
  "change_date" timestamp(6) NOT NULL
)
;

-- ----------------------------
-- Table structure for task_result
-- ----------------------------
DROP TABLE IF EXISTS "public"."task_result";
CREATE TABLE "public"."task_result" (
  "tenant" varchar(255) COLLATE "pg_catalog"."default" NOT NULL,
  "id" varchar(255) COLLATE "pg_catalog"."default" NOT NULL,
  "status" int2 NOT NULL,
  "status_info" int4 NOT NULL,
  "created_at" timestamp(6) DEFAULT now(),
  "last_open_date" timestamp(6) NOT NULL,
  "user_index" int4 NOT NULL DEFAULT 1,
  "change_id" int4 NOT NULL DEFAULT 0,
  "callback" text COLLATE "pg_catalog"."default" NOT NULL,
  "baseurl" text COLLATE "pg_catalog"."default" NOT NULL,
  "password" text COLLATE "pg_catalog"."default",
  "additional" text COLLATE "pg_catalog"."default"
)
;

-- ----------------------------
-- Function structure for merge_db
-- ----------------------------
DROP FUNCTION IF EXISTS "public"."merge_db"("_tenant" varchar, "_id" varchar, "_status" int2, "_status_info" int4, "_last_open_date" timestamp, "_user_index" int4, "_change_id" int4, "_callback" text, "_baseurl" text, OUT "isupdate" bpchar, OUT "userindex" int4);
CREATE FUNCTION "public"."merge_db"(IN "_tenant" varchar, IN "_id" varchar, IN "_status" int2, IN "_status_info" int4, IN "_last_open_date" timestamp, IN "_user_index" int4, IN "_change_id" int4, IN "_callback" text, IN "_baseurl" text, OUT "isupdate" bpchar, OUT "userindex" int4)
  RETURNS "pg_catalog"."record" AS $BODY$
DECLARE
	t_var "task_result"."user_index"%TYPE;
BEGIN
	LOOP
		-- first try to update the key
		-- note that "a" must be unique
		IF ((_callback <> '') IS TRUE) AND ((_baseurl <> '') IS TRUE) THEN
			UPDATE "task_result" SET last_open_date=_last_open_date, user_index=user_index+1,callback=_callback,baseurl=_baseurl WHERE tenant = _tenant AND id = _id RETURNING user_index into userindex;
		ELSE
			UPDATE "task_result" SET last_open_date=_last_open_date, user_index=user_index+1 WHERE tenant = _tenant AND id = _id RETURNING user_index into userindex;
		END IF;
		IF found THEN
			isupdate := 'true';
			RETURN;
		END IF;
		-- not there, so try to insert the key
		-- if someone else inserts the same key concurrently,
		-- we could get a unique-key failure
		BEGIN
			INSERT INTO "task_result"(tenant, id, status, status_info, last_open_date, user_index, change_id, callback, baseurl) VALUES(_tenant, _id, _status, _status_info, _last_open_date, _user_index, _change_id, _callback, _baseurl) RETURNING user_index into userindex;
			isupdate := 'false';
			RETURN;
		EXCEPTION WHEN unique_violation THEN
			-- do nothing, and loop to try the UPDATE again
		END;
	END LOOP;
END;
$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;

-- ----------------------------
-- Primary Key structure for table doc_changes
-- ----------------------------
ALTER TABLE "public"."doc_changes" ADD CONSTRAINT "doc_changes_pkey" PRIMARY KEY ("tenant", "id", "change_id");

-- ----------------------------
-- Primary Key structure for table task_result
-- ----------------------------
ALTER TABLE "public"."task_result" ADD CONSTRAINT "task_result_pkey" PRIMARY KEY ("tenant", "id");
