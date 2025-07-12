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
    zone_id STRING NOT NULL REFERENCES zone (id) ON DELETE CASCADE,
    soa_serial INTEGER,
    name_labels STRING,
    dns_class INTEGER NOT NULL,
    ttl INTEGER,
    record_type INTEGER NOT NULL,
    rdata BLOB NOT NULL,
    mdns_cache_flush BOOLEAN NOT NULL,
    expires STRING
);
CREATE INDEX IF NOT EXISTS idx_record_zone_id ON record (zone_id);
