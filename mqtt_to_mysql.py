#!/usr/bin/env python3
"""
Subscribe to the MQTT topics published by the esp32-c3-bridge
(its/<device_id>/packet|status|info|stats), fully decode the ITS-G5 C-ITS
packets (IEEE 802.11p -> LLC/SNAP -> GeoNetworking -> BTP -> ASN.1 UPER
facility layer message) and persist everything into MySQL.

See schema.sql for the table layout and README.md for setup instructions.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import ssl
import sys
from typing import Any, Optional

import paho.mqtt.client as mqtt
import pymysql
import pymysql.cursors

import its_decoder
import its_layers

try:
    from dotenv import load_dotenv
    load_dotenv()  # loads mqtt-bridge/.env if present; never overrides real env vars
except ImportError:
    pass

log = logging.getLogger("mqtt_to_mysql")


# ---------------------------------------------------------------------------
# JSON helpers -- asn1tools decode results contain bytes (OCTET/BIT STRING)
# and tuples (CHOICE alternatives, sometimes bitstrings), neither of which
# json.dumps understands natively.
# ---------------------------------------------------------------------------

def to_jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, tuple):
        if len(obj) == 2 and isinstance(obj[0], str):
            # asn1tools CHOICE result: (alternative_name, value)
            return {"choice": obj[0], "value": to_jsonable(obj[1])}
        if len(obj) == 2 and isinstance(obj[0], bytes) and isinstance(obj[1], int):
            # asn1tools BIT STRING result: (bytes, bit_length)
            return {"bits": obj[1], "hex": obj[0].hex()}
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, list):
        return [to_jsonable(v) for v in obj]
    return obj


def dumps(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    return json.dumps(to_jsonable(obj), default=str)


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# MySQL
# ---------------------------------------------------------------------------

class Database:
    def __init__(self, host: str, port: int, user: str, password: str, database: str):
        self._args = dict(host=host, port=port, user=user, password=password,
                           database=database, charset="utf8mb4",
                           cursorclass=pymysql.cursors.Cursor, autocommit=True)
        self.conn: Optional[pymysql.connections.Connection] = None
        self.connect()

    def connect(self) -> None:
        self.conn = pymysql.connect(**self._args)
        log.info("Connected to MySQL %s:%s/%s", self._args["host"], self._args["port"], self._args["database"])

    def execute(self, sql: str, params: tuple = ()) -> int:
        for attempt in (1, 2):
            try:
                with self.conn.cursor() as cur:
                    cur.execute(sql, params)
                    return cur.lastrowid
            except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as exc:
                if attempt == 2:
                    raise
                log.warning("MySQL connection lost (%s), reconnecting...", exc)
                self.connect()
        raise AssertionError("unreachable")

    def execute_many(self, sql: str, params_seq: list) -> None:
        if not params_seq:
            return
        for attempt in (1, 2):
            try:
                with self.conn.cursor() as cur:
                    cur.executemany(sql, params_seq)
                    return
            except (pymysql.err.OperationalError, pymysql.err.InterfaceError) as exc:
                if attempt == 2:
                    raise
                log.warning("MySQL connection lost (%s), reconnecting...", exc)
                self.connect()


# ---------------------------------------------------------------------------
# Topic handlers
# ---------------------------------------------------------------------------

def upsert_device_seen(db: Database, device_id: str, now: datetime.datetime) -> None:
    db.execute(
        """
        INSERT INTO devices (device_id, first_seen, last_seen)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen)
        """,
        (device_id, now, now),
    )


def handle_status(db: Database, device_id: str, payload: bytes) -> None:
    now = utcnow()
    status = payload.decode("utf-8", errors="replace").strip()
    if status not in ("online", "offline"):
        log.warning("Unexpected status payload from %s: %r", device_id, payload)
        return
    db.execute(
        """
        INSERT INTO devices (device_id, last_status, last_status_at, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE last_status = VALUES(last_status),
                                 last_status_at = VALUES(last_status_at),
                                 last_seen = VALUES(last_seen)
        """,
        (device_id, status, now, now, now),
    )


def handle_info(db: Database, device_id: str, payload: bytes) -> None:
    now = utcnow()
    try:
        info = json.loads(payload)
    except json.JSONDecodeError:
        log.warning("Malformed info JSON from %s: %r", device_id, payload)
        return
    mac = info.get("emac")
    version = info.get("ver")
    hwv = info.get("hwv")
    db.execute(
        """
        INSERT INTO devices (device_id, mac, firmware_version, hardware_version, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE mac = VALUES(mac),
                                 firmware_version = VALUES(firmware_version),
                                 hardware_version = VALUES(hardware_version),
                                 last_seen = VALUES(last_seen)
        """,
        (device_id, mac, version, hwv, now, now),
    )


def handle_stats(db: Database, device_id: str, payload: bytes) -> None:
    now = utcnow()
    try:
        stats = json.loads(payload)
    except json.JSONDecodeError:
        log.warning("Malformed stats JSON from %s: %r", device_id, payload)
        return
    # "sniffer" is a nested object the bridge only includes once it has
    # received at least one stats frame from the esp32-c5-sniffer over its
    # UART link (see sniffer_stats_t in esp32-c3-bridge.ino); absent means
    # not yet received, not necessarily that the sniffer is unhealthy.
    sniffer = stats.get("sniffer") or {}
    db.execute(
        """
        INSERT INTO device_stats (device_id, received_at, temp_c, rssi_dbm,
                                   sniffer_uptime_ms, sniffer_sent_packets, sniffer_dropped_packets,
                                   sniffer_queued, sniffer_queue_size, sniffer_rssi_dbm, sniffer_age_ms)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (device_id, now, stats.get("temp"), stats.get("rssi"),
         sniffer.get("uptime_ms"), sniffer.get("sent"), sniffer.get("dropped"),
         sniffer.get("queued"), sniffer.get("queue_size"), sniffer.get("rssi"), sniffer.get("age_ms")),
    )
    upsert_device_seen(db, device_id, now)


def upsert_station(db: Database, device_id: str, station_id: int, station_type: Optional[int],
                    message_type: str, now: datetime.datetime, fields: dict) -> None:
    lat, lon = fields.get("latitude_deg"), fields.get("longitude_deg")
    if lat is None or lon is None:
        return
    # trailer_json only comes from CPM (fields["trailers"]); CAM/DENM upserts
    # pass no trailer data at all, so COALESCE keeps whatever was last known
    # instead of wiping it out on every non-CPM update for the same station.
    trailers = fields.get("trailers")
    db.execute(
        """
        INSERT INTO stations (station_id, device_id, station_type, last_message_type,
                               latitude_deg, longitude_deg, altitude_m, position,
                               heading_deg, speed_m_s, vehicle_length_m, vehicle_width_m,
                               trailer_json, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s, %s, POINT(%s, %s), %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE device_id = VALUES(device_id),
                                 station_type = VALUES(station_type),
                                 last_message_type = VALUES(last_message_type),
                                 latitude_deg = VALUES(latitude_deg),
                                 longitude_deg = VALUES(longitude_deg),
                                 altitude_m = VALUES(altitude_m),
                                 position = VALUES(position),
                                 heading_deg = VALUES(heading_deg),
                                 speed_m_s = VALUES(speed_m_s),
                                 vehicle_length_m = VALUES(vehicle_length_m),
                                 vehicle_width_m = VALUES(vehicle_width_m),
                                 trailer_json = COALESCE(VALUES(trailer_json), trailer_json),
                                 last_seen = VALUES(last_seen)
        """,
        (station_id, device_id, station_type, message_type,
         lat, lon, fields.get("altitude_m"), lon, lat,
         fields.get("heading_deg"), fields.get("speed_m_s"),
         fields.get("vehicle_length_m"), fields.get("vehicle_width_m"),
         dumps(trailers) if trailers else None,
         now, now),
    )


def store_cam(db: Database, device_id: str, station_id: int, now: datetime.datetime, decoded: dict) -> None:
    fields = its_decoder.extract_cam_fields(decoded)
    lat, lon = fields.get("latitude_deg"), fields.get("longitude_deg")
    if lat is not None and lon is not None:
        db.execute(
            """
            INSERT INTO cam_messages (device_id, station_id, received_at, generation_delta_time,
                                       station_type, latitude_deg, longitude_deg, altitude_m, position,
                                       heading_deg, speed_m_s, drive_direction,
                                       vehicle_length_m, vehicle_width_m, protected_zones_json, decoded_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, POINT(%s, %s), %s, %s, %s, %s, %s, %s, %s)
            """,
            (device_id, station_id, now, fields.get("generation_delta_time"),
             fields.get("station_type"), lat, lon, fields.get("altitude_m"), lon, lat,
             fields.get("heading_deg"), fields.get("speed_m_s"), fields.get("drive_direction"),
             fields.get("vehicle_length_m"), fields.get("vehicle_width_m"),
             dumps(fields.get("protected_zones")) if fields.get("protected_zones") else None,
             dumps(decoded)),
        )
    upsert_station(db, device_id, station_id, fields.get("station_type"), "cam", now, fields)


def store_denm(db: Database, device_id: str, station_id: int, now: datetime.datetime, decoded: dict) -> None:
    fields = its_decoder.extract_denm_fields(decoded)
    lat, lon = fields.get("latitude_deg"), fields.get("longitude_deg")
    if lat is None or lon is None:
        return

    originating_station_id = fields.get("originating_station_id")
    sequence_number = fields.get("sequence_number")
    if originating_station_id is None or sequence_number is None:
        log.warning("DENM from station %s missing actionID, cannot upsert denm_events", station_id)
        return

    termination = fields.get("termination")
    is_active = termination is None
    validity_duration_s = fields.get("validity_duration_s") or 600
    expires_at = now + datetime.timedelta(seconds=validity_duration_s)

    db.execute(
        """
        INSERT INTO denm_events (originating_station_id, sequence_number, device_id, station_id,
                                  station_type, cause_code, sub_cause_code, termination, is_active,
                                  detection_time, reference_time, validity_duration_s, expires_at,
                                  latitude_deg, longitude_deg, altitude_m, position, decoded_json,
                                  first_received_at, last_received_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, POINT(%s, %s), %s, %s, %s)
        ON DUPLICATE KEY UPDATE device_id = VALUES(device_id),
                                 station_id = VALUES(station_id),
                                 station_type = VALUES(station_type),
                                 cause_code = VALUES(cause_code),
                                 sub_cause_code = VALUES(sub_cause_code),
                                 termination = VALUES(termination),
                                 is_active = VALUES(is_active),
                                 detection_time = VALUES(detection_time),
                                 reference_time = VALUES(reference_time),
                                 validity_duration_s = VALUES(validity_duration_s),
                                 expires_at = VALUES(expires_at),
                                 latitude_deg = VALUES(latitude_deg),
                                 longitude_deg = VALUES(longitude_deg),
                                 altitude_m = VALUES(altitude_m),
                                 position = VALUES(position),
                                 decoded_json = VALUES(decoded_json),
                                 last_received_at = VALUES(last_received_at)
        """,
        (originating_station_id, sequence_number, device_id, station_id,
         fields.get("station_type"), fields.get("cause_code"), fields.get("sub_cause_code"),
         termination, is_active,
         fields.get("detection_time"), fields.get("reference_time"), validity_duration_s, expires_at,
         lat, lon, fields.get("altitude_m"), lon, lat, dumps(decoded), now, now),
    )


def store_cpm(db: Database, device_id: str, station_id: int, now: datetime.datetime,
               decoded: dict, variant: Optional[str]) -> None:
    fields = its_decoder.extract_cpm_fields(decoded, variant or "")
    lat, lon = fields.get("latitude_deg"), fields.get("longitude_deg")
    if lat is None or lon is None:
        return

    cpm_message_id = db.execute(
        """
        INSERT INTO cpm_messages (device_id, station_id, received_at, asn1_variant, origin_kind,
                                   station_type, latitude_deg, longitude_deg, altitude_m, position,
                                   num_perceived_objects, trailers_json, decoded_json)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, POINT(%s, %s), %s, %s, %s)
        """,
        (device_id, station_id, now, variant, fields.get("origin_kind"),
         fields.get("station_type"), lat, lon, fields.get("altitude_m"), lon, lat,
         len(fields.get("perceived_objects") or []),
         dumps(fields.get("trailers")) if fields.get("trailers") else None,
         dumps(decoded)),
    )

    objects = fields.get("perceived_objects") or []
    if objects:
        db.execute_many(
            """
            INSERT INTO cpm_perceived_objects (cpm_message_id, object_id, x_m, y_m, z_m,
                                                measurement_delta_time_ms, object_age_ms, classification)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            [
                (cpm_message_id, obj.get("object_id"), obj.get("x_m"), obj.get("y_m"), obj.get("z_m"),
                 obj.get("measurement_delta_time_ms"), obj.get("object_age_ms"), obj.get("classification"))
                for obj in objects
            ],
        )

    # The CPM sender itself is a real ITS station with a real position --
    # worth showing on a live map like any CAM-sending vehicle/RSU.
    upsert_station(db, device_id, station_id, fields.get("station_type"), "cpm", now, fields)


def store_spatem(db: Database, device_id: str, station_id: int, now: datetime.datetime, decoded: dict) -> None:
    for state in its_decoder.extract_spatem_fields(decoded):
        intersection_id = state.get("intersection_id")
        signal_group = state.get("signal_group")
        if intersection_id is None or signal_group is None:
            continue
        region = state.get("region") or 0
        db.execute(
            """
            INSERT INTO traffic_light_states (intersection_id, region, signal_group, device_id, station_id,
                                               event_state, min_end_time, max_end_time, likely_end_time,
                                               first_received_at, last_received_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE device_id = VALUES(device_id),
                                     station_id = VALUES(station_id),
                                     event_state = VALUES(event_state),
                                     min_end_time = VALUES(min_end_time),
                                     max_end_time = VALUES(max_end_time),
                                     likely_end_time = VALUES(likely_end_time),
                                     last_received_at = VALUES(last_received_at)
            """,
            (intersection_id, region, signal_group, device_id, station_id,
             state.get("event_state"), state.get("min_end_time"), state.get("max_end_time"),
             state.get("likely_end_time"), now, now),
        )


def store_mapem(db: Database, device_id: str, station_id: int, now: datetime.datetime, decoded: dict) -> None:
    for isec in its_decoder.extract_mapem_fields(decoded):
        lat, lon = isec.get("latitude_deg"), isec.get("longitude_deg")
        if lat is None or lon is None:
            continue
        lanes = isec.get("lanes") or []
        db.execute(
            """
            INSERT INTO intersections (intersection_id, region, device_id, station_id, name, revision,
                                        latitude_deg, longitude_deg, altitude_m, position,
                                        lanes_json, decoded_json, first_received_at, last_received_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, POINT(%s, %s), %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE device_id = VALUES(device_id),
                                     station_id = VALUES(station_id),
                                     name = VALUES(name),
                                     revision = VALUES(revision),
                                     latitude_deg = VALUES(latitude_deg),
                                     longitude_deg = VALUES(longitude_deg),
                                     altitude_m = VALUES(altitude_m),
                                     position = VALUES(position),
                                     lanes_json = VALUES(lanes_json),
                                     decoded_json = VALUES(decoded_json),
                                     last_received_at = VALUES(last_received_at)
            """,
            (isec.get("intersection_id"), isec.get("region") or 0, device_id, station_id,
             isec.get("name"), isec.get("revision"), lat, lon, isec.get("altitude_m"), lon, lat,
             dumps(lanes) if lanes else None, dumps(decoded), now, now),
        )


def handle_packet(db: Database, device_id: str, topic: str, payload: bytes) -> None:
    now = utcnow()

    packet_id = db.execute(
        """
        INSERT INTO packets (device_id, mqtt_topic, received_at, raw_len, raw_payload)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (device_id, topic, now, len(payload), payload),
    )
    upsert_device_seen(db, device_id, now)

    try:
        layers = its_layers.parse_lower_layers(payload)
    except its_layers.DecodeError as exc:
        db.execute("UPDATE packets SET lower_layer_error = %s WHERE id = %s", (str(exc), packet_id))
        log.warning("[%s] failed to parse lower layers: %s", device_id, exc)
        return

    if layers.error:
        log.debug("[%s] %s", device_id, layers.error)

    if layers.payload is None:
        db.execute("UPDATE packets SET lower_layer_error = %s WHERE id = %s", (layers.error, packet_id))
        db.execute(
            """
            INSERT INTO its_messages (packet_id, device_id, received_at, source_mac,
                                       ieee80211_json, llc_json, gn_json, btp_json, decode_error)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (packet_id, device_id, now, layers.ieee80211.get("sa"),
             dumps(layers.ieee80211), dumps(layers.llc), dumps(layers.gn), dumps(layers.btp),
             layers.error),
        )
        return

    try:
        result = its_decoder.decode_its_pdu(layers.payload)
    except Exception as exc:
        log.exception("[%s] unexpected error decoding ITS PDU", device_id)
        db.execute(
            """
            INSERT INTO its_messages (packet_id, device_id, received_at, source_mac,
                                       ieee80211_json, llc_json, gn_json, btp_json, decode_error)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (packet_id, device_id, now, layers.ieee80211.get("sa"),
             dumps(layers.ieee80211), dumps(layers.llc), dumps(layers.gn), dumps(layers.btp),
             f"unhandled exception: {exc}"),
        )
        return

    its_message_id = db.execute(
        """
        INSERT INTO its_messages (packet_id, device_id, received_at, protocol_version, message_id,
                                   message_type, station_id, asn1_variant, decode_error, source_mac,
                                   ieee80211_json, llc_json, gn_json, btp_json, decoded_json)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (packet_id, device_id, now, result.header.protocol_version, result.header.message_id,
         result.message_type, result.header.station_id, result.variant, result.error,
         layers.ieee80211.get("sa"),
         dumps(layers.ieee80211), dumps(layers.llc), dumps(layers.gn), dumps(layers.btp),
         dumps(result.decoded)),
    )

    if not result.ok:
        if result.error:
            log.debug("[%s] station %s: %s", device_id, result.header.station_id, result.error)
        return

    try:
        if result.message_type == "cam":
            store_cam(db, device_id, result.header.station_id, now, result.decoded)
        elif result.message_type == "denm":
            store_denm(db, device_id, result.header.station_id, now, result.decoded)
        elif result.message_type == "cpm":
            store_cpm(db, device_id, result.header.station_id, now, result.decoded, result.variant)
        elif result.message_type == "spatem":
            store_spatem(db, device_id, result.header.station_id, now, result.decoded)
        elif result.message_type == "mapem":
            store_mapem(db, device_id, result.header.station_id, now, result.decoded)
    except Exception:
        log.exception("[%s] failed to store %s fields for its_messages.id=%s",
                      device_id, result.message_type, its_message_id)


# ---------------------------------------------------------------------------
# MQTT plumbing
# ---------------------------------------------------------------------------

def make_mqtt_client(args: argparse.Namespace, db: Database) -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.mqtt_client_id, clean_session=True)

    if args.mqtt_user:
        client.username_pw_set(args.mqtt_user, args.mqtt_password)

    if args.mqtt_tls:
        client.tls_set(cert_reqs=ssl.CERT_NONE if args.mqtt_insecure else ssl.CERT_REQUIRED)
        if args.mqtt_insecure:
            client.tls_insecure_set(True)

    prefix = args.mqtt_topic_prefix

    def on_connect(client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            log.error("MQTT connect failed: %s", reason_code)
            return
        log.info("MQTT connected, subscribing to %s/+/{packet,status,info,stats}", prefix)
        for suffix in ("packet", "status", "info", "stats"):
            client.subscribe(f"{prefix}/+/{suffix}", qos=0)

    def on_disconnect(client, userdata, flags, reason_code, properties=None):
        log.warning("MQTT disconnected: %s", reason_code)

    def on_message(client, userdata, msg: mqtt.MQTTMessage):
        print(".", end="", flush=True)
        parts = msg.topic.split("/")
        if len(parts) != 3 or parts[0] != prefix:
            return
        _prefix, device_id, kind = parts
        try:
            if kind == "packet":
                handle_packet(db, device_id, msg.topic, msg.payload)
            elif kind == "status":
                handle_status(db, device_id, msg.payload)
            elif kind == "info":
                handle_info(db, device_id, msg.payload)
            elif kind == "stats":
                handle_stats(db, device_id, msg.payload)
        except Exception:
            log.exception("Error handling message on topic %s", msg.topic)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    return client


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def env(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(name, default)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)

    p.add_argument("--mqtt-host", default=env("MQTT_HOST", "cits1.opentrafficmap.org"))
    p.add_argument("--mqtt-port", type=int, default=int(env("MQTT_PORT", "8883")))
    p.add_argument("--mqtt-user", default=env("MQTT_USER"))
    p.add_argument("--mqtt-password", default=env("MQTT_PASSWORD"))
    p.add_argument("--mqtt-tls", dest="mqtt_tls", action="store_true", default=env("MQTT_TLS", "true") == "true")
    p.add_argument("--no-mqtt-tls", dest="mqtt_tls", action="store_false")
    p.add_argument("--mqtt-insecure", action="store_true", default=env("MQTT_INSECURE", "true") == "true",
                    help="Skip TLS certificate verification (matches the bridge firmware's default)")
    p.add_argument("--mqtt-topic-prefix", default=env("MQTT_TOPIC_PREFIX", "its"))
    p.add_argument("--mqtt-client-id", default=env("MQTT_CLIENT_ID", "its-mysql-bridge"))

    p.add_argument("--mysql-host", default=env("MYSQL_HOST", "127.0.0.1"))
    p.add_argument("--mysql-port", type=int, default=int(env("MYSQL_PORT", "3306")))
    p.add_argument("--mysql-user", default=env("MYSQL_USER", "its_bridge"))
    p.add_argument("--mysql-password", default=env("MYSQL_PASSWORD", ""))
    p.add_argument("--mysql-database", default=env("MYSQL_DATABASE", "its_bridge"))

    p.add_argument("--log-level", default=env("LOG_LEVEL", "INFO"))

    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    log.info("Compiling ASN.1 modules...")
    its_decoder.preload()

    db = Database(args.mysql_host, args.mysql_port, args.mysql_user, args.mysql_password, args.mysql_database)
    client = make_mqtt_client(args, db)

    log.info("Connecting to MQTT broker %s:%s (tls=%s insecure=%s)...",
             args.mqtt_host, args.mqtt_port, args.mqtt_tls, args.mqtt_insecure)
    client.connect(args.mqtt_host, args.mqtt_port, keepalive=60)
    client.loop_forever(retry_first_connection=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
