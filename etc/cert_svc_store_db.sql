
PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE ssl (
    gname               TEXT not null,
    certificate         TEXT not null,
    file_hash           TEXT not null,
    subject_hash        TEXT not null,
    common_name         TEXT not null,
    enabled             INT not null,
    is_root_app_enabled INT not null);

CREATE TABLE wifi (
    gname               TEXT PRIMARY KEY not null,
    common_name         TEXT not null,
    private_key_gname   TEXT,
    associated_gname    TEXT,
    is_root_cert        INT,
    enabled             INT not null,
    is_root_app_enabled INT not null);

CREATE TABLE vpn (
    gname               TEXT PRIMARY KEY not null,
    common_name         TEXT not null,
    private_key_gname   TEXT,
    associated_gname    TEXT,
    is_root_cert        INT,
    enabled             INT not null,
    is_root_app_enabled INT not null);

CREATE TABLE email (
    gname               TEXT PRIMARY KEY not null,
    common_name         TEXT not null,
    private_key_gname   TEXT,
    associated_gname    TEXT,
    is_root_cert        INT,
    enabled             INT not null,
    is_root_app_enabled INT not null);

CREATE TABLE disabled_certs (
    gname               TEXT PRIMARY KEY not null,
    certificate         TEXT not null);

COMMIT;

