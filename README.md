# mqtt-bridge: ITS-G5 MQTT -> MySQL

Subscribes to the MQTT topics published by `esp32-c3-bridge`
(`its/<device_id>/packet|status|info|stats`), fully decodes each captured
ITS-G5 (802.11p) frame, and stores the result in MySQL.

Decode pipeline (see `its_layers.py` / `its_decoder.py`):

```
IEEE 802.11p (OCB) MAC header
  -> LLC/SNAP
    -> GeoNetworking (ETSI EN 302 636-4-1)
      -> BTP-A / BTP-B (ETSI EN 302 636-5-1)
        -> ASN.1 UPER facility layer message (CAM / DENM / SPATEM / MAPEM /
           IVIM / SREM / SSEM / CPM / POIM / EV-RSR / TISTPG / EVCSN /
           RTCMEM / VAM / SAEM -- ETSI TS 102894-2 + friends)
```

Field names/byte layouts and the ASN.1 schemas (`asn1/*.asn`) are taken
from https://codeberg.org/opentrafficmap/cits-to-json and its upstream
https://github.com/consider-it/C-ITS-Parser, which decode this exact same
MQTT payload format.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Create the database and tables:

```bash
mysql -u root -p < schema.sql
```

Optionally create a dedicated MySQL user for the bridge (see the commented
`CREATE USER` block near the top of `schema.sql`).

Copy `.env.example` to `.env` and fill in your MQTT and MySQL credentials:

```bash
cp .env.example .env
```

Then run:

```bash
python mqtt_to_mysql.py
```

All settings can also be passed as CLI flags (`--mysql-host`, `--mqtt-user`,
...) or environment variables instead of `.env` -- see `python
mqtt_to_mysql.py --help`.

## What gets stored where

- **`packets`** -- raw archive of every `its/+/packet` payload received.
- **`its_messages`** -- the complete decode of every facility-layer message
  (any type), including the full lower-layer breakdown (802.11 / LLC / GN /
  BTP) and the full ASN.1-decoded body, all as JSON. This is the audit
  trail / source of truth; nothing is discarded even for message types that
  don't get a dedicated table below.
- **`cam_messages`** -- one row per received CAM (append-only time series),
  with indexed lat/lon and a spatial index, for trails/playback/heatmaps.
  RSU-sent CAMs (as opposed to vehicle ones) populate `protected_zones_json`
  (the DSRC/tolling zones the RSU is announcing) instead of
  heading/speed/vehicle dimensions, which don't apply to a stationary RSU.
- **`stations`** -- latest known position per station, upserted in place.
  This is what a live map should query for "what's out there right now" --
  it stays small regardless of how long the bridge has been running. Also
  updated by CPM (see below), tagged via `last_message_type`.
- **`denm_events`** -- one row per DENM action (`originatingStationId` +
  `sequenceNumber`), upserted as updates/repetitions arrive. Query `WHERE
  is_active` for hazards currently in effect.
- **`cpm_messages`** / **`cpm_perceived_objects`** -- one row per received
  CPM (the sender's own position/type, like `cam_messages`) plus one child
  row per object its sensors perceived. Perceived-object `x_m`/`y_m`/`z_m`
  are relative offsets in metres from the reporting station, *not* absolute
  lat/lon -- converting them needs the parent row's position and heading,
  which isn't attempted here (see `its_decoder.extract_cpm_fields`'
  docstring for why). A CPM-sending vehicle's trailer data, if present,
  lands in `trailers_json`.
- **`traffic_light_states`** -- current signal phase per
  (region, intersection, signal group) from SPATEM, upserted in place like
  `stations`. No position is stored -- that's in the corresponding MAPEM,
  which isn't cross-referenced here (matching by `intersection_id`/`region`
  is on you, or ask for that to be wired up too).
- **`devices` / `device_stats`** -- bridge (not vehicle) bookkeeping, from
  the `status`/`info`/`stats` topics. `device_stats` also carries the
  `sniffer_*` columns (uptime, sent/dropped packet counts, queue depth,
  RSSI, age) relayed from the esp32-c5-sniffer's own stats, when the bridge
  has received any -- these are link/hardware health, not map data.

### Map viewer queries

Current vehicle positions:

```sql
SELECT station_id, longitude_deg, latitude_deg, heading_deg, speed_m_s
FROM stations
WHERE last_seen > NOW() - INTERVAL 30 SECOND;
```

Active hazards:

```sql
SELECT originating_station_id, sequence_number, longitude_deg, latitude_deg,
       cause_code, sub_cause_code
FROM denm_events
WHERE is_active AND (expires_at IS NULL OR expires_at > NOW());
```

Viewport bounding-box query using the spatial index (`stations`, `cam_messages`
and `denm_events` all store `POINT(longitude, latitude)`, i.e. (X, Y) = (lon, lat)):

```sql
SELECT station_id, longitude_deg, latitude_deg
FROM stations
WHERE MBRContains(
    ST_GeomFromText('POLYGON((minlon minlat, maxlon minlat, maxlon maxlat, minlon maxlat, minlon minlat))'),
    position
);
```

## Coverage / known limitations

- **Fully ASN.1-decoded**: CAM, DENM (v1 and v2), SPATEM, MAPEM, IVIM (v1
  shape), SREM, SSEM, CPM (v1 and v2), POIM (Point of Interest Message,
  messageID 3 -- renamed from the legacy "POI" in the current registry),
  EV-RSR (EV charging spot reservation), TISTPG, EVCSN (EV charging spot
  notification), RTCMEM (RTCM correction data), VAM (Vulnerable Road User
  Awareness Message) and SAEM (Service Announcement Message). That's 15 of
  the 21 registered message types. For anything else, the fixed 6-byte
  `ItsPduHeader` (protocol version, message type, station ID) is still
  decoded and stored in `its_messages`, with `decode_error` explaining why
  the body wasn't.
- **Not decoded** -- no usable public ASN.1 module found for these anywhere
  in ETSI's own `ITS/asn1/` repository namespace, confirmed by browsing its
  full contents, not just keyword search (see `its_decoder.py`'s module
  docstring for exactly what was tried): IMZM (needs geometry types that
  were dropped from a since-removed "temp imports" module and still
  haven't been merged into the CDD, checked against the latest release
  too), and DSM/PCIM/PCVM/MCM/PAM (no public ASN.1 module exists for these
  at all -- not even a placeholder repo -- and no evidence of real-world
  deployment to date).
- IVIM v2 (`ivim_2_2_1.asn`) uses the ASN.1 `RELATIVE-OID` type, which
  `asn1tools` doesn't support; only the IVIM v1 (ISO 19321-based) schema is
  wired up. If a receiver only ever emits IVIM v2, those messages will fail
  to decode and fall back to header-only.
- DENM v2, CPM v2, POIM and VAM headers constrain `protocolVersion`/
  `messageId` to a single legal value, which strict PER/UPER technically
  allows encoding in zero bits (shrinking the header to 4 bytes). Empirically
  `asn1tools` does not apply that optimization -- it always emits/expects
  the full 6-byte header, which is also what the header-sniffing code
  assumes before it even knows which ASN.1 schema to use. This has been
  fine in testing; if VAM/POIM decoding specifically starts failing against
  real traffic, this is the first thing to check.
- A GeoNetworking "secured packet" (IEEE 1609.2 envelope) is unwrapped via
  `its_1609dot2.py`, a small hand-written Canonical OER (COER) reader --
  not `asn1tools`, whose ASN.1 grammar can't parse IEEE 1609.2's real
  schema (its multi-field `CLASS` constructs for certificate/header
  extensions aren't supported; verified empirically). It walks just far
  enough into the structure (`SignedData.tbsData.payload.data.content`)
  to recover the plaintext GeoNetworking Common Header onward when the
  envelope is a `SignedData` carrying an embedded `unsecuredData` payload
  -- "secured" here almost always means *signed*, not encrypted, so this
  covers the common case. It does not (and does not need to) parse the
  signer/certificate or verify the signature. A genuinely `encryptedData`
  envelope, or one where only an external hash was referenced (no embedded
  payload), can't be recovered and falls back to keeping the raw envelope
  bytes as hex (`gn_json.secured_header_hex`), with whatever was cheaply
  learned along the way in `gn_json.secured_info`.
- Trailing bytes beyond the end of the actual GeoNetworking payload (a trend
  noted, for a *different* upstream firmware than this repo's own, in
  cits-to-json's `packetv1.rs`) aren't assumed or blindly stripped. The GN
  Common Header's own `payload_length` field is trusted instead: the
  BTP+facility payload is trimmed to exactly that many bytes, and whatever
  is left over (0 bytes, 8, or any other amount) is reported as-is in
  `gn_json.trailing_bytes_hex` rather than guessed at.
