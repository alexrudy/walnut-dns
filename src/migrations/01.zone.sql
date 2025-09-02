-- DNS Zone file
CREATE TABLE IF NOT EXISTS zone (
    id STRING NOT NULL PRIMARY KEY,
    name STRING NOT NULL,
    zone_type INTEGER NOT NULL, -- Primary / Secondary / External
    allow_axfr BOOLEAN NOT NULL,
    dns_class INTEGER NOT NULL -- almost always IN
);
CREATE INDEX IF NOT EXISTS idx_zone_name ON zone (lower(name));

-- DNS records
CREATE TABLE IF NOT EXISTS record (
    id STRING NOT NULL PRIMARY KEY,
    zone_id STRING REFERENCES zone (id) ON DELETE CASCADE,
    query_id STRING REFERENCES query (id) ON DELETE CASCADE,
    soa_serial INTEGER,
    name_labels STRING,
    dns_class INTEGER NOT NULL,
    ttl INTEGER,
    record_type INTEGER NOT NULL,
    rdata BLOB NOT NULL,
    mdns_cache_flush BOOLEAN NOT NULL,
    expires STRING,
    glue BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_record_zone_id ON record (zone_id);
CREATE INDEX IF NOT EXISTS idx_cache_record_query_id ON record (query_id);

-- DNS Queries
CREATE TABLE IF NOT EXISTS query (
    id STRING NOT NULL PRIMARY KEY,
    name STRING NOT NULL,
    record_type INTEGER NOT NULL,
    dns_class INTEGER NOT NULL,
    response_code INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    last_access INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_query_lookup ON query (name, record_type, dns_class);
CREATE INDEX IF NOT EXISTS idx_query_expires ON query (expires);
CREATE INDEX IF NOT EXISTS idx_query_last_access ON query (last_access);
