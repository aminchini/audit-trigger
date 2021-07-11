CREATE TABLE test_table
(
    id SERIAL PRIMARY KEY,
    name text,
    age integer,
    lang text,
    badges jsonb,
    creation_dt timestamp without time zone
);

SELECT audit.audit_table('test_table');
SELECT audit.audit_table('test_table', true, false, '{lang}');
SELECT audit.audit_table('test_table', true, true, '{lang}', 'test_table');

-------------------

CREATE TABLE test(name TEXT, age INTEGER, is_man BOOLEAN DEFAULT TRUE, etc jsonb);
SELECT audit.audit_table('test', 'true', 'false', '{}', 'test_cahnges');