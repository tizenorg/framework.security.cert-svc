


PRAGMA foreign_keys = ON; BEGIN TRANSACTION;



CREATE TABLE OCSPResponseStorage (
    cert_chain TEXT not null,
    end_entity_check INT ,
    ocsp_status INT ,
    next_update_time BIGINT ,
    PRIMARY KEY(cert_chain, end_entity_check) ,


CHECK(1) );

CREATE TABLE CRLResponseStorage (
    distribution_point TEXT primary key not null,
    crl_body TEXT not null,
    next_update_time BIGINT ,
CHECK(1) );

COMMIT;
BEGIN TRANSACTION; CREATE TABLE DB_VERSION_6d8092083d41289ab1c349aeaad617bc (version INT); COMMIT;


