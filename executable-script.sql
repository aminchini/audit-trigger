CREATE SCHEMA audit;
REVOKE ALL ON SCHEMA audit FROM public;

CREATE TABLE audit.default_table (
    event_id bigserial primary key,
    schema_name text not null,
    table_name text not null,
    relid oid not null,
    session_user_name text,
    action_tstamp_tx TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_stm TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_clk TIMESTAMP WITH TIME ZONE NOT NULL,
    transaction_id bigint,
    application_name text,
    client_addr inet,
    client_port integer,
    client_query text,
    action TEXT NOT NULL CHECK (action IN ('I','D','U', 'T')),
    row_data jsonb,
    changed_fields jsonb,
    statement_only boolean not null
);

REVOKE ALL ON audit.default_table FROM public;
CREATE INDEX default_table_relid_idx ON audit.default_table(relid);
CREATE INDEX default_table_action_tstamp_tx_stm_idx ON audit.default_table(action_tstamp_stm);
CREATE INDEX default_table_action_idx ON audit.default_table(action);

CREATE OR REPLACE FUNCTION jsonb_remove_keys(
	jdata JSONB,
	keys TEXT[]
)
RETURNS JSONB AS $$
DECLARE
	result JSONB;
	len INT;
	target TEXT;
BEGIN
	len = array_length(keys, 1);
	result = jdata;
    IF len > 0 THEN
        FOR i IN 1..len LOOP
            target = keys[i];
            IF (jdata ? target) THEN
                result = (result - target);
            END IF;
        END LOOP;
    END IF;
	RETURN result;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION audit.if_modified_func() RETURNS TRIGGER AS $body$
DECLARE
    audit_row audit.default_table;
    include_values boolean;
    log_diffs boolean;
    excluded_cols text[] = ARRAY[]::text[];
    table_name text;
    _q_text text;
BEGIN
    IF TG_WHEN <> 'AFTER' THEN
        RAISE EXCEPTION 'audit.if_modified_func() may only run as an AFTER trigger';
    END IF;
    table_name = TG_ARGV[0];
    audit_row = ROW(
        nextval('audit.'|| table_name ||'_event_id_seq'), -- event_id
        TG_TABLE_SCHEMA::text,                        -- schema_name
        TG_TABLE_NAME::text,                          -- table_name
        TG_RELID,                                     -- relation OID for much quicker searches
        session_user::text,                           -- session_user_name
        current_timestamp,                            -- action_tstamp_tx
        statement_timestamp(),                        -- action_tstamp_stm
        clock_timestamp(),                            -- action_tstamp_clk
        txid_current(),                               -- transaction ID
        current_setting('application_name'),          -- client application
        inet_client_addr(),                           -- client_addr
        inet_client_port(),                           -- client_port
        current_query(),                              -- top-level query or queries (if multi statement) from client
        substring(TG_OP,1,1),                         -- action
        NULL, NULL,                                   -- row_data, changed_fields
        'f'                                           -- statement_only
        );

    IF NOT TG_ARGV[1]::boolean IS DISTINCT FROM 'f'::boolean THEN
        audit_row.client_query = NULL;
    END IF;

    IF TG_ARGV[2] IS NOT NULL THEN
        excluded_cols = TG_ARGV[2]::text[];
    END IF;
    
    IF (TG_OP = 'UPDATE' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = jsonb_remove_keys(row_to_json(OLD.*)::jsonb, excluded_cols);
        SELECT jsonb_remove_keys(jsonb_object_agg(DIFF.key, DIFF.value), excluded_cols)
        FROM (
            SELECT D.key, D.value FROM jsonb_each_text(row_to_json(NEW.*)::jsonb) D
            EXCEPT
            SELECT D.key, D.value FROM jsonb_each_text(row_to_json(OLD.*)::jsonb) D
        ) DIFF
        INTO audit_row.changed_fields;
        IF audit_row.changed_fields IS NULL OR audit_row.changed_fields = '{}'::jsonb THEN
            -- All changed fields are ignored. Skip this update.
            RETURN NULL;
        END IF;
    ELSIF (TG_OP = 'DELETE' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = jsonb_remove_keys(row_to_json(OLD.*)::jsonb, excluded_cols);
    ELSIF (TG_OP = 'INSERT' AND TG_LEVEL = 'ROW') THEN
        audit_row.row_data = jsonb_remove_keys(row_to_json(NEW.*)::jsonb, excluded_cols);
    ELSIF (TG_LEVEL = 'STATEMENT' AND TG_OP IN ('INSERT','UPDATE','DELETE','TRUNCATE')) THEN
        audit_row.statement_only = 't';
    ELSE
        RAISE EXCEPTION '[audit.if_modified_func] - Trigger func added as trigger for unhandled case: %, %',TG_OP, TG_LEVEL;
        RETURN NULL;
    END IF;
    _q_text = 'INSERT INTO audit.' || table_name || ' SELECT ($1).*;';
    EXECUTE  _q_text using audit_row;
    RETURN NULL;
END;
$body$
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION audit.create_table(audit_table_name text) RETURNS void AS $body$
DECLARE
BEGIN

    EXECUTE 'CREATE TABLE IF NOT EXISTS audit.' || audit_table_name || '(
    event_id bigserial primary key,
    schema_name text not null,
    table_name text not null,
    relid oid not null,
    session_user_name text,
    action_tstamp_tx TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_stm TIMESTAMP WITH TIME ZONE NOT NULL,
    action_tstamp_clk TIMESTAMP WITH TIME ZONE NOT NULL,
    transaction_id bigint,
    application_name text,
    client_addr inet,
    client_port integer,
    client_query text,
    action TEXT NOT NULL CHECK (action IN (''I'',''D'',''U'', ''T'')),
    row_data jsonb,
    changed_fields jsonb,
    statement_only boolean not null
    );';
    EXECUTE 'REVOKE ALL ON audit.' || audit_table_name || ' FROM public;';
    EXECUTE 'CREATE INDEX IF NOT EXISTS ' || audit_table_name || '_relid_idx ON audit.' || audit_table_name || '(relid);';
    EXECUTE 'CREATE INDEX IF NOT EXISTS ' || audit_table_name || '_action_tstamp_tx_stm_idx ON audit.' || audit_table_name || '(action_tstamp_stm);';
    EXECUTE 'CREATE INDEX IF NOT EXISTS ' || audit_table_name || '_action_idx ON audit.' || audit_table_name || '(action);';
END;
$body$
language 'plpgsql';


CREATE OR REPLACE FUNCTION audit.audit_table(target_table regclass, audit_rows boolean, audit_query_text boolean, ignored_cols text[], audit_table_name text) RETURNS void AS $body$
DECLARE
  stm_targets text = 'INSERT OR UPDATE OR DELETE OR TRUNCATE';
  _q_txt text;
  _ignored_cols_snip text = '';
BEGIN
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_row ON ' || target_table;
    EXECUTE 'DROP TRIGGER IF EXISTS audit_trigger_stm ON ' || target_table;

    PERFORM audit.create_table(audit_table_name);

    IF audit_rows THEN
        IF array_length(ignored_cols,1) > 0 THEN
            _ignored_cols_snip = ', ' || quote_literal(ignored_cols);
        END IF;
        _q_txt = 'CREATE TRIGGER audit_trigger_row AFTER INSERT OR UPDATE OR DELETE ON ' || 
                 target_table || 
                 ' FOR EACH ROW EXECUTE PROCEDURE audit.if_modified_func(' || quote_literal(audit_table_name) || ', ' ||
                 quote_literal(audit_query_text) || _ignored_cols_snip || ');';
        RAISE NOTICE '%',_q_txt;
        EXECUTE _q_txt;
        stm_targets = 'TRUNCATE';
    ELSE
    END IF;

    _q_txt = 'CREATE TRIGGER audit_trigger_stm AFTER ' || stm_targets || ' ON ' ||
             target_table ||
             ' FOR EACH STATEMENT EXECUTE PROCEDURE audit.if_modified_func(' || quote_literal(audit_table_name) || ',' ||
             quote_literal(audit_query_text) || ');';
    RAISE NOTICE '%',_q_txt;
    EXECUTE _q_txt;

END;
$body$
language 'plpgsql';

CREATE OR REPLACE FUNCTION audit.audit_table(target_table regclass, audit_rows boolean, audit_query_text boolean, ignored_cols text[]) RETURNS void AS $body$
SELECT audit.audit_table($1, $2, $3, $4, 'default_table');
$body$ LANGUAGE 'sql';

CREATE OR REPLACE FUNCTION audit.audit_table(target_table regclass, audit_rows boolean, audit_query_text boolean) RETURNS void AS $body$
SELECT audit.audit_table($1, $2, $3, ARRAY[]::text[]);
$body$ LANGUAGE 'sql';

CREATE OR REPLACE FUNCTION audit.audit_table(target_table regclass) RETURNS void AS $body$
SELECT audit.audit_table($1, BOOLEAN 't', BOOLEAN 't');
$body$ LANGUAGE 'sql';

CREATE OR REPLACE VIEW audit.tableslist AS 
    SELECT DISTINCT
        triggers.trigger_schema AS schema,
        triggers.event_object_table AS audited_table,
        'audit.' || split_part(triggers.action_statement, '''', 2) AS logging_table
    FROM information_schema.triggers
    WHERE triggers.trigger_name::text IN ('audit_trigger_row'::text, 'audit_trigger_stm'::text)  
    ORDER BY 1, 2, 3;

