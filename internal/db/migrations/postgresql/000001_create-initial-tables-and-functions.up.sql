CREATE TYPE private_key_type AS ENUM ('RSA', 'ECDSA', 'ED25519');

create table x509_private_keys
(
    id              uuid             not null primary key,
    type            private_key_type not null,
    pem_block_type  varchar          not null,
    bytes_hash      bytea            not null,
    bytes           bytea            not null,
    public_key_hash bytea            not null,
    created_at      timestamp        not null
);

create unique index x509_certificate_private_keys_bytes_hash_uindex on x509_private_keys (bytes_hash);
create index x509_certificate_private_keys_public_key_hash_uindex on x509_private_keys (public_key_hash);

create table x509_certificates
(
    id                    uuid      not null primary key,
    common_name           text      not null,
    subject_alt_names     text[]    not null,
    issuer_hash           bytea     not null,
    subject_hash          bytea     not null,
    bytes_hash            bytea     not null,
    bytes                 bytea     not null,
    public_key_hash       bytea     not null,
    parent_certificate_id uuid references x509_certificates (id),
    private_key_id        uuid references x509_private_keys (id) on delete restrict,
    not_before            timestamp not null,
    not_after             timestamp not null,
    created_at            timestamp not null
);

create index x509_certificates_subject_alt_names_index on x509_certificates (subject_alt_names);
create index x509_certificates_issuer_hash_index on x509_certificates (issuer_hash);
create index x509_certificates_subject_hash_index on x509_certificates (subject_hash);
create unique index x509_certificates_bytes_hash_uindex on x509_certificates (bytes_hash);
create index x509_certificates_public_key_hash_uindex on x509_certificates (public_key_hash);

create table x509_certificate_subscriptions
(
    id                  uuid      not null primary key,
    subject_alt_names   text[]    not null,
    include_private_key bool      not null,
    created_at          timestamp not null
);

create index x509_certificate_subscriptions_subject_alt_names_index
    on x509_certificate_subscriptions (subject_alt_names);

create index x509_certificate_subscriptions_created_at_index
    on x509_certificate_subscriptions (created_at);

-- drop function get_certificate_chain(p_certificate_start_id uuid);
CREATE
    OR REPLACE FUNCTION get_certificate_updates(
    p_input_subject_alternative_names TEXT[], -- Array of input SANs the certificate must include
    p_after_parameter TIMESTAMP -- Timestamp to filter certificates created in the db after this date
)
    RETURNS TABLE
            (
                id                    uuid,
                common_name           text,
                subject_alt_names     text[],
                issuer_hash           bytea,
                subject_hash          bytea,
                bytes                 bytea,
                bytes_hash            bytea,
                public_key_hash       bytea,
                parent_certificate_id uuid,
                private_key_id        uuid,
                not_before            timestamp,
                not_after             timestamp,
                created_at            timestamp
            )
AS
$$
BEGIN
    RETURN QUERY
        -- CTE 1: Create a table with subject alternative names (SANs) and common name from the input
        WITH input_subject_identifiers AS (SELECT UNNEST(p_input_subject_alternative_names) AS subject_identifier),
             -- CTE 2: Rank certificates based on SANs and expiration date
             ranked_certificates AS (SELECT *,
                                            RANK()
                                            OVER (PARTITION BY xc.subject_alt_names ORDER BY xc.not_after DESC) AS rank
                                     FROM x509_certificates as xc
                                     WHERE
                                       -- Find certificates that are still active and created after a specific point in time
                                         xc.created_at > p_after_parameter
                                       AND xc.not_before < NOW()
                                       AND xc.not_after > NOW()
                                       -- Find certificates that don't cover all input SANs and exclude them from the result
                                       AND NOT EXISTS (SELECT 1
                                                       FROM input_subject_identifiers
                                                       WHERE NOT EXISTS (SELECT 1
                                                                         FROM UNNEST(xc.subject_alt_names || ARRAY [xc.common_name]) AS certificate_subject_identifier
                                                                         WHERE certificate_subject_identifier =
                                                                               input_subject_identifiers.subject_identifier
                                                                            -- Match wildcard SANs too
                                                                            OR input_subject_identifiers.subject_identifier LIKE
                                                                               REPLACE(certificate_subject_identifier, '*', '%') ESCAPE
                                                                               '$')))
-- Get certificates with the highest rank based on SANs and expiration date
        SELECT ranked_certificates.id,
               ranked_certificates.common_name,
               ranked_certificates.subject_alt_names,
               ranked_certificates.issuer_hash,
               ranked_certificates.subject_hash,
               ranked_certificates.bytes,
               ranked_certificates.bytes_hash,
               ranked_certificates.public_key_hash,
               ranked_certificates.parent_certificate_id,
               ranked_certificates.private_key_id,
               ranked_certificates.not_before,
               ranked_certificates.not_after,
               ranked_certificates.created_at
        FROM ranked_certificates
        WHERE rank = 1;
END;
$$
    LANGUAGE plpgsql;

-- drop function get_certificate_updates(p_input_subject_alternative_names TEXT[], p_after_parameter TIMESTAMP);
CREATE
    OR REPLACE FUNCTION get_certificate_chain(p_certificate_start_id uuid)
    RETURNS TABLE
            (
                id                    uuid,
                common_name           TEXT,
                subject_alt_names     TEXT[],
                issuer_hash           BYTEA,
                subject_hash          BYTEA,
                bytes                 BYTEA,
                bytes_hash            BYTEA,
                public_key_hash       BYTEA,
                parent_certificate_id uuid,
                private_key_id        uuid,
                not_before            TIMESTAMP,
                not_after             TIMESTAMP,
                created_at            TIMESTAMP,
                depth                 INTEGER
            )
AS
$$
BEGIN
    RETURN QUERY WITH RECURSIVE cert_chain AS (
        -- Base case: Select a certificate with a specific public_id as starting point
        SELECT x.id,
               x.common_name,
               x.subject_alt_names,
               x.issuer_hash,
               x.subject_hash,
               x.bytes,
               x.bytes_hash,
               x.public_key_hash,
               x.parent_certificate_id,
               x.private_key_id,
               x.not_before,
               x.not_after,
               x.created_at,
               1 AS depth
        FROM x509_certificates x
        WHERE x.id = p_certificate_start_id

        UNION ALL

        -- Recursive case: Find the parent certificate of the current certificate and add it to the results
        SELECT c.id,
               c.common_name,
               c.subject_alt_names,
               c.issuer_hash,
               c.subject_hash,
               c.bytes,
               c.bytes_hash,
               c.public_key_hash,
               c.parent_certificate_id,
               c.private_key_id,
               c.not_before,
               c.not_after,
               c.created_at,
               cc.depth + 1
        FROM x509_certificates c
                 JOIN cert_chain cc ON c.id = cc.parent_certificate_id)

-- Final query to output the certificate chain
                 SELECT cert_chain.id,
                        cert_chain.common_name,
                        cert_chain.subject_alt_names,
                        cert_chain.issuer_hash,
                        cert_chain.subject_hash,
                        cert_chain.bytes,
                        cert_chain.bytes_hash,
                        cert_chain.public_key_hash,
                        cert_chain.parent_certificate_id,
                        cert_chain.private_key_id,
                        cert_chain.not_before,
                        cert_chain.not_after,
                        cert_chain.created_at,
                        cert_chain.depth
                 FROM cert_chain
                 ORDER BY depth;
END;
$$
    LANGUAGE plpgsql;
