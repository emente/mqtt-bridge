-- ---------------------------------------------------------------------------
-- Schema for storing decoded ETSI ITS-G5 (C-ITS) messages captured by the
-- esp32-c3-bridge and forwarded over MQTT.
--
-- Layout rationale (tuned for a live map viewer):
--   * `stations` and `denm_events` hold only the LATEST known state per
--     station / hazard event (upserted in place). These stay small no
--     matter how long the bridge has been running, so "give me everything
--     currently on the map" is a plain full-table scan / spatial query
--     with no aggregation needed.
--   * `cam_messages` is an append-only time series (one row per received
--     CAM) for trails, playback and heatmaps, with its own spatial index.
--   * `its_messages` is the complete decode log for EVERY facility-layer
--     message type the bridge sees (CAM, DENM, SPATEM, MAPEM, IVIM, SREM,
--     SSEM, CPM, or header-only for anything not ASN.1-decoded), each with
--     its full lower-layer (802.11 / GeoNetworking / BTP) and facility
--     layer decode stored as JSON. This is the audit trail; a map viewer
--     normally never touches it.
--   * `packets` is the raw archive of every MQTT `its/+/packet` payload.
--
-- Geometry columns use SRID 0 (unqualified Cartesian), storing
-- POINT(longitude, latitude) i.e. (X, Y) = (lon, lat) -- the ordering most
-- web map libraries (Leaflet, MapLibre, GeoJSON) expect. This deliberately
-- avoids SRID 4326, whose MySQL/EPSG-mandated axis order is (lat, lon) and
-- is a common source of swapped-coordinate bugs. Spatial indexes still
-- accelerate MBRContains()/ST_Contains() bounding-box viewport queries;
-- true geodesic functions (ST_Distance_Sphere etc.) work fine on SRID-0
-- points as long as you keep in mind the units are degrees, not meters.
-- ---------------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS its_bridge
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE its_bridge;

-- Dedicated login for mqtt_to_mysql.py. Uncomment and pick your own
-- password (then put the same value in mqtt-bridge/.env, see .env.example),
-- rather than using the MySQL root account from the ingest script.
--
-- CREATE USER IF NOT EXISTS 'its_bridge'@'%' IDENTIFIED BY 'change-me';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON its_bridge.* TO 'its_bridge'@'%';
-- FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------------
-- Bridge device bookkeeping (its/<device_id>/status, /info, /stats)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS devices (
    device_id           VARCHAR(16)  NOT NULL,
    mac                  CHAR(17)     NULL,
    firmware_version     VARCHAR(96)  NULL,
    hardware_version     VARCHAR(32)  NULL,
    last_status          ENUM('online','offline') NULL,
    last_status_at        DATETIME(3)  NULL,
    -- The bridge/sniffer has no GPS -- these are set manually (there's no
    -- ingester code path that writes them) to the receiver's known fixed
    -- install location, purely so the map viewer can draw a "receiver
    -- line" from a station to whichever bridge picked it up. NULL means
    -- unset; that device just doesn't get a receiver line.
    latitude_deg          DECIMAL(10,7) NULL,
    longitude_deg          DECIMAL(10,7) NULL,
    first_seen           DATETIME(3) NOT NULL,
    last_seen            DATETIME(3)  NOT NULL,
    PRIMARY KEY (device_id)
) ENGINE=InnoDB;

-- Migrating an existing database created before latitude_deg/longitude_deg
-- existed? Run this instead of re-running the CREATE TABLE above:
--
-- ALTER TABLE devices
--     ADD COLUMN latitude_deg  DECIMAL(10,7) NULL,
--     ADD COLUMN longitude_deg DECIMAL(10,7) NULL;
--
-- Then set each receiver's real position by hand, e.g.:
-- UPDATE devices SET latitude_deg = 49.0057, longitude_deg = 8.3948 WHERE device_id = 'its-g5-bridge-xxxxxx';

CREATE TABLE IF NOT EXISTS device_stats (
    id                       BIGINT UNSIGNED AUTO_INCREMENT,
    device_id                VARCHAR(16)  NOT NULL,
    received_at              DATETIME(3)  NOT NULL,
    temp_c                   DECIMAL(5,2) NULL,
    rssi_dbm                 SMALLINT     NULL,
    -- Fields below come from the "sniffer" sub-object of the bridge's
    -- stats payload: statistics the esp32-c5-sniffer sends the bridge over
    -- its own UART link (separate from the bridge's own temp/rssi above),
    -- which the bridge relays as-is. NULL when no sniffer stats have been
    -- received yet (e.g. the sniffer is offline or an older firmware).
    sniffer_uptime_ms        BIGINT UNSIGNED NULL,
    sniffer_sent_packets     BIGINT UNSIGNED NULL,
    sniffer_dropped_packets  BIGINT UNSIGNED NULL,
    sniffer_queued           SMALLINT UNSIGNED NULL,
    sniffer_queue_size       SMALLINT UNSIGNED NULL,
    sniffer_rssi_dbm         SMALLINT NULL,
    sniffer_age_ms           BIGINT UNSIGNED NULL,
    -- The bridge's own SD card (packet logging, see SD_CARD.md) -- not the
    -- sniffer's. sd_found reflects whether SD.begin() succeeded at boot;
    -- sd_packets_written is a running total since the bridge's own last
    -- power-up (not reset by "sddelete" starting a fresh log file).
    sd_found                 BOOLEAN NULL,
    sd_packets_written       BIGINT UNSIGNED NULL,
    PRIMARY KEY (id),
    KEY idx_device_stats_device_time (device_id, received_at)
) ENGINE=InnoDB;

-- Migrating an existing database created before the sniffer_* columns
-- existed? Run this instead of re-running the CREATE TABLE above (which is
-- a no-op once the table already exists):
--
-- ALTER TABLE device_stats
--     ADD COLUMN sniffer_uptime_ms       BIGINT UNSIGNED NULL,
--     ADD COLUMN sniffer_sent_packets    BIGINT UNSIGNED NULL,
--     ADD COLUMN sniffer_dropped_packets BIGINT UNSIGNED NULL,
--     ADD COLUMN sniffer_queued          SMALLINT UNSIGNED NULL,
--     ADD COLUMN sniffer_queue_size      SMALLINT UNSIGNED NULL,
--     ADD COLUMN sniffer_rssi_dbm        SMALLINT NULL,
--     ADD COLUMN sniffer_age_ms          BIGINT UNSIGNED NULL;
--
-- Migrating an existing database created before sd_found/sd_packets_written
-- existed? Run this instead:
--
-- ALTER TABLE device_stats
--     ADD COLUMN sd_found           BOOLEAN NULL,
--     ADD COLUMN sd_packets_written BIGINT UNSIGNED NULL;

-- ---------------------------------------------------------------------------
-- Raw packet archive (its/<device_id>/packet, before decoding)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS packets (
    id              BIGINT UNSIGNED AUTO_INCREMENT,
    device_id       VARCHAR(16)     NOT NULL,
    mqtt_topic      VARCHAR(128)    NOT NULL,
    received_at     DATETIME(3)     NOT NULL,
    raw_len         SMALLINT UNSIGNED NOT NULL,
    raw_payload     VARBINARY(2600) NOT NULL,
    lower_layer_error VARCHAR(255)  NULL,
    PRIMARY KEY (id),
    KEY idx_packets_device_time (device_id, received_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Complete decode log: one row per ITS facility-layer PDU found in a packet.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS its_messages (
    id                BIGINT UNSIGNED AUTO_INCREMENT,
    packet_id         BIGINT UNSIGNED NOT NULL,
    device_id         VARCHAR(16)     NOT NULL,
    received_at       DATETIME(3)     NOT NULL,

    -- ItsPduHeader
    protocol_version  TINYINT UNSIGNED NULL,
    message_id        TINYINT UNSIGNED NULL,
    message_type      VARCHAR(16)      NULL,   -- 'cam', 'denm', 'spatem', ...
    station_id        INT UNSIGNED     NULL,
    asn1_variant      VARCHAR(16)      NULL,   -- which ASN.1 module decoded it, e.g. 'denm_v2'
    decode_error      TEXT             NULL,

    source_mac        CHAR(17)         NULL,   -- 802.11 source address

    ieee80211_json    LONGTEXT NULL,
    llc_json          LONGTEXT NULL,
    gn_json           LONGTEXT NULL,
    btp_json          LONGTEXT NULL,
    decoded_json      LONGTEXT NULL,            -- full ASN.1-decoded facility message

    PRIMARY KEY (id),
    KEY idx_its_messages_station_time (station_id, received_at),
    KEY idx_its_messages_type_time (message_type, received_at),
    KEY idx_its_messages_device_time (device_id, received_at),
    CONSTRAINT fk_its_messages_packet FOREIGN KEY (packet_id) REFERENCES packets (id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- CAM history (append-only time series, for trails / playback / heatmaps)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cam_messages (
    id                      BIGINT UNSIGNED AUTO_INCREMENT,
    device_id               VARCHAR(16)  NOT NULL,
    station_id              INT UNSIGNED NOT NULL,
    received_at             DATETIME(3)  NOT NULL,
    generation_delta_time   SMALLINT UNSIGNED NULL,
    station_type            TINYINT UNSIGNED NULL,

    latitude_deg            DECIMAL(10,7) NOT NULL,
    longitude_deg           DECIMAL(10,7) NOT NULL,
    altitude_m              DECIMAL(8,2)  NULL,
    position                POINT NOT NULL,

    heading_deg             DECIMAL(5,1)  NULL,
    speed_m_s               DECIMAL(6,2)  NULL,
    drive_direction         VARCHAR(16)   NULL,
    vehicle_length_m        DECIMAL(5,1)  NULL,
    vehicle_width_m         DECIMAL(4,1)  NULL,

    -- Only populated for RSU-sent CAMs (highFrequencyContainer choice
    -- "rsuContainerHighFrequency"): a JSON array of the protected/tolling
    -- zones the RSU is announcing, each with its own lat/lon/radius/type.
    -- heading_deg/speed_m_s/vehicle_*_m stay NULL for these (RSUs don't move).
    protected_zones_json    LONGTEXT NULL,

    decoded_json            LONGTEXT NULL,

    PRIMARY KEY (id),
    KEY idx_cam_station_time (station_id, received_at),
    KEY idx_cam_device_time (device_id, received_at),
    SPATIAL KEY idx_cam_position (position)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- "Live" latest-known position per station (fast source for a current map)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS stations (
    station_id              INT UNSIGNED NOT NULL,
    device_id                VARCHAR(16)  NOT NULL,
    station_type             TINYINT UNSIGNED NULL,
    last_message_type        VARCHAR(16)  NOT NULL,

    latitude_deg             DECIMAL(10,7) NOT NULL,
    longitude_deg            DECIMAL(10,7) NOT NULL,
    altitude_m               DECIMAL(8,2)  NULL,
    position                 POINT NOT NULL,

    heading_deg               DECIMAL(5,1) NULL,
    speed_m_s                 DECIMAL(6,2) NULL,
    vehicle_length_m          DECIMAL(5,1) NULL,
    vehicle_width_m           DECIMAL(4,1) NULL,

    -- Latest trailer(s) reported for this station via CPM (see
    -- cpm_messages.trailers_json for the same shape). Only CPM carries
    -- trailer data, so a CAM/DENM upsert for the same station leaves this
    -- column untouched (COALESCE in the upsert) rather than clearing it.
    trailer_json              LONGTEXT NULL,

    first_seen                DATETIME(3) NOT NULL,
    last_seen                 DATETIME(3) NOT NULL,

    PRIMARY KEY (station_id),
    KEY idx_stations_last_seen (last_seen),
    SPATIAL KEY idx_stations_position (position)
) ENGINE=InnoDB;

-- Migrating an existing database created before trailer_json existed? Run
-- this instead of re-running the CREATE TABLE above (a no-op once the table
-- already exists):
--
-- ALTER TABLE stations ADD COLUMN trailer_json LONGTEXT NULL;

-- ---------------------------------------------------------------------------
-- DENM hazard/event markers: one row per (originating station, action
-- sequence number), upserted as updates/cancellations for that same event
-- arrive. Query `WHERE is_active` for what to draw on a map right now.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS denm_events (
    originating_station_id   INT UNSIGNED NOT NULL,
    sequence_number          SMALLINT UNSIGNED NOT NULL,

    device_id                 VARCHAR(16)  NOT NULL,
    station_id                 INT UNSIGNED NULL,
    station_type                TINYINT UNSIGNED NULL,

    cause_code                  SMALLINT UNSIGNED NULL,
    sub_cause_code               SMALLINT UNSIGNED NULL,
    termination                   VARCHAR(32) NULL,
    is_active                     BOOLEAN NOT NULL DEFAULT TRUE,

    detection_time                 BIGINT NULL,  -- ms since 2004-01-01T00:00:00Z (TimestampIts)
    reference_time                  BIGINT NULL,
    validity_duration_s              INT UNSIGNED NULL,
    expires_at                        DATETIME(3) NULL,

    latitude_deg                      DECIMAL(10,7) NOT NULL,
    longitude_deg                     DECIMAL(10,7) NOT NULL,
    altitude_m                         DECIMAL(8,2) NULL,
    position                            POINT NOT NULL,

    decoded_json                         LONGTEXT NULL,

    first_received_at                     DATETIME(3) NOT NULL,
    last_received_at                       DATETIME(3) NOT NULL,

    PRIMARY KEY (originating_station_id, sequence_number),
    KEY idx_denm_active (is_active, last_received_at),
    SPATIAL KEY idx_denm_position (position)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- CPM (Collective Perception Message): the sender's own position/type, plus
-- what its sensors perceived. One row per CPM in cpm_messages (append-only,
-- like cam_messages), with each perceived object in a child row in
-- cpm_perceived_objects. Perceived-object x/y/z are relative Cartesian
-- offsets in metres from the reporting station (not absolute lat/lon) --
-- converting to map coordinates needs the parent row's position *and*
-- heading, which the ingester deliberately doesn't attempt (see
-- its_decoder.extract_cpm_fields' docstring).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cpm_messages (
    id                      BIGINT UNSIGNED AUTO_INCREMENT,
    device_id               VARCHAR(16)  NOT NULL,
    station_id              INT UNSIGNED NOT NULL,
    received_at             DATETIME(3)  NOT NULL,
    asn1_variant            VARCHAR(16)  NULL,   -- 'cpm_v1' or 'cpm_v2'
    origin_kind             VARCHAR(32)  NULL,   -- 'originatingVehicleContainer' / 'originatingRsuContainer' / NULL
    station_type            TINYINT UNSIGNED NULL,

    latitude_deg            DECIMAL(10,7) NOT NULL,
    longitude_deg           DECIMAL(10,7) NOT NULL,
    altitude_m              DECIMAL(8,2)  NULL,
    position                POINT NOT NULL,

    num_perceived_objects   SMALLINT UNSIGNED NULL,
    trailers_json           LONGTEXT NULL,        -- non-null only if the sending vehicle reported a trailer
    decoded_json            LONGTEXT NULL,

    PRIMARY KEY (id),
    KEY idx_cpm_station_time (station_id, received_at),
    KEY idx_cpm_device_time (device_id, received_at),
    SPATIAL KEY idx_cpm_position (position)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cpm_perceived_objects (
    id                        BIGINT UNSIGNED AUTO_INCREMENT,
    cpm_message_id            BIGINT UNSIGNED NOT NULL,
    object_id                 INT UNSIGNED     NULL,
    x_m                       DECIMAL(8,2)     NULL,  -- relative to the reporting station, East-positive
    y_m                       DECIMAL(8,2)     NULL,  -- relative to the reporting station, North-positive
    z_m                       DECIMAL(8,2)     NULL,
    measurement_delta_time_ms SMALLINT         NULL,
    object_age_ms             SMALLINT UNSIGNED NULL,
    classification            VARCHAR(64)      NULL,  -- e.g. 'vehicleSubClass:5', best-effort summary; full detail in the parent's decoded_json

    PRIMARY KEY (id),
    KEY idx_cpm_objects_message (cpm_message_id),
    CONSTRAINT fk_cpm_perceived_objects_message FOREIGN KEY (cpm_message_id) REFERENCES cpm_messages (id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Traffic light state: one row per (region, intersection, signal group),
-- upserted in place like `stations`/`denm_events` so a live map can query
-- "what's the current signal state" directly. Only the current (nearest-
-- term) phase is kept, not predicted future ones. No position is stored --
-- SPATEM doesn't carry intersection geometry, that's in the corresponding
-- MAPEM (see `intersections` below); join on (region, intersection_id) to
-- place a signal state on the map.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS traffic_light_states (
    id                 BIGINT UNSIGNED AUTO_INCREMENT,
    intersection_id    INT UNSIGNED NOT NULL,
    region             INT UNSIGNED NOT NULL DEFAULT 0,  -- 0 = region not specified (IntersectionReferenceID.region is OPTIONAL)
    signal_group       INT UNSIGNED NOT NULL,

    device_id          VARCHAR(16)  NOT NULL,
    station_id         INT UNSIGNED NULL,

    event_state        VARCHAR(40)  NULL,   -- e.g. 'protected-Movement-Allowed', 'stop-And-Remain'
    -- TimeMark (dsrc_2_2_1.asn): tenths of a second into the current OR
    -- NEXT UTC hour (not minute), 0-36000; 36000 = indefinite future,
    -- 36001 = unknown/undefined. Resolving to an absolute time needs the
    -- current-hour-vs-next-hour disambiguation described there -- see
    -- timeMarkToDate() in citsviewer/app.js.
    min_end_time       INT UNSIGNED NULL,
    max_end_time       INT UNSIGNED NULL,
    likely_end_time    INT UNSIGNED NULL,

    first_received_at  DATETIME(3) NOT NULL,
    last_received_at   DATETIME(3) NOT NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_traffic_light_group (region, intersection_id, signal_group),
    KEY idx_traffic_light_last_seen (last_received_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Traffic light state HISTORY: append-only, one row per actual state
-- CHANGE (not one per SPATEM -- a signal group is typically reported many
-- times per minute with the same event_state, logging every single one
-- would grow this unbounded for no benefit). store_spatem() only inserts
-- here when the new event_state differs from what was already in
-- traffic_light_states for that group, immediately before overwriting it.
-- This is what citsviewer's "stats" feature (% time spent in each state)
-- is computed from; traffic_light_states itself only ever holds the
-- current phase, not history.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS traffic_light_state_history (
    id                 BIGINT UNSIGNED AUTO_INCREMENT,
    intersection_id    INT UNSIGNED NOT NULL,
    region             INT UNSIGNED NOT NULL DEFAULT 0,
    signal_group       INT UNSIGNED NOT NULL,
    event_state        VARCHAR(40)  NULL,
    changed_at         DATETIME(3)  NOT NULL,

    PRIMARY KEY (id),
    KEY idx_tl_history_group_time (region, intersection_id, signal_group, changed_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Intersection / lane geometry from MAPEM, upserted in place per
-- (region, intersection_id) like `stations`/`denm_events` -- a MAPEM
-- normally repeats unchanged until the physical layout is revised (tracked
-- via `revision`), so only the latest copy is worth keeping. `lanes_json` is
-- a JSON array of {lane_id, name, ingress_approach, egress_approach, points}
-- with `points` an already-resolved [[lon,lat], ...] polyline (see
-- its_decoder.extract_mapem_fields -- the ingester does the NodeXY offset
-- accumulation so consumers don't have to). Join against
-- `traffic_light_states` on (region, intersection_id) to place a live
-- signal state at this intersection's position.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intersections (
    intersection_id     INT UNSIGNED NOT NULL,
    region               INT UNSIGNED NOT NULL DEFAULT 0,  -- 0 = region not specified (IntersectionReferenceID.region is OPTIONAL)

    device_id             VARCHAR(16)  NOT NULL,
    station_id             INT UNSIGNED NULL,

    name                    VARCHAR(64)  NULL,
    revision                 TINYINT UNSIGNED NULL,

    latitude_deg              DECIMAL(10,7) NOT NULL,
    longitude_deg               DECIMAL(10,7) NOT NULL,
    altitude_m                    DECIMAL(8,2) NULL,
    position                        POINT NOT NULL,

    lanes_json                       LONGTEXT NULL,
    decoded_json                       LONGTEXT NULL,

    first_received_at                   DATETIME(3) NOT NULL,
    last_received_at                     DATETIME(3) NOT NULL,

    PRIMARY KEY (region, intersection_id),
    KEY idx_intersections_last_seen (last_received_at),
    SPATIAL KEY idx_intersections_position (position)
) ENGINE=InnoDB;
