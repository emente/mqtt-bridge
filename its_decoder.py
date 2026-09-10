"""
ASN.1 UPER decoding of ETSI ITS facility layer messages: CAM, DENM (v1/v2),
SPATEM, MAPEM, IVIM (v1 shape), SREM, SSEM, CPM (v1/v2), POIM, EV-RSR,
TISTPG, EVCSN, RTCMEM, VAM and SAEM.

The CAM/DENM/CPM/IVIM/SPATEM/MAPEM/SREM/SSEM modules in asn1/ are taken
verbatim from the C-ITS-Parser project
(https://github.com/consider-it/C-ITS-Parser, autogen/asn.1/), which is what
https://codeberg.org/opentrafficmap/cits-to-json uses under the hood for the
exact same MQTT payload format produced by this bridge. The remaining
modules (POIM, EV-RSR, TISTPG, EVCSN, RTCMEM, VAM, SAEM) were fetched
directly from ETSI's own ASN.1 repository
(https://forge.etsi.org/rep/ITS/asn1/), since C-ITS-Parser doesn't bundle
them. Keeping the modules byte-for-byte identical to those references means
the UPER encoding rules line up with what real ITS-G5 stations transmit.

SAEM (asn1/saem/) pulls in an older (2016), fully self-contained dependency
chain -- ETSI's own newer standalone saem_ts104091 repo wasn't used here
since this older one already compiles cleanly and SAEM traffic is rare
enough that chasing the newest revision wasn't worth the extra risk of an
untested schema swap.

Not decoded (no usable public ASN.1 available anywhere in ETSI's own
`ITS/asn1/` namespace as of this writing -- see git history / PR
description for what was tried): IMZM (needs geometry types -- AreaCircular
etc. -- that were dropped from a "VAM-Temp-Imports" module and still
haven't been merged into the CDD release available, confirmed against the
latest release2 CDD too), and DSM, PCIM, PCVM, MCM, PAM (no public ASN.1
module for these exists at all -- not even a placeholder repo -- and no
evidence of real-world deployment to date).

A note on newer message headers (DENM v2, CPM v2, POIM, VAM): their
`ItsPduHeader` is used via a `WITH COMPONENTS {..., protocolVersion (n),
messageId(x)}` constraint that pins both fields to a single legal value.
Strict PER/UPER allows (arguably requires) a compliant encoder to emit
zero bits for a component with such a singleton effective constraint,
which would shrink that header to 4 bytes (stationID only) instead of the
usual 6. Empirically, `asn1tools` does NOT apply this optimization -- it
always encodes/decodes the full 6-byte header, matching the fixed-layout
`parse_header_only()` peek below used to pick a candidate schema before
any ASN.1 decoding happens. This has been fine in practice for DENM v2 /
CPM v2 so far; if a real VAM/POIM sender turns out to use the shrunk
encoding, decoding for that message type specifically would need a
special-cased header parse. Flagging here so a future "why is VAM/POIM
decode failing" investigation starts here instead of from scratch.
"""

from __future__ import annotations

import math
import re
import struct
from pathlib import Path
from typing import Any, Optional

import asn1tools

ASN1_DIR = Path(__file__).parent / "asn1"

# messageID -> human readable name (ETSI TS 102894-2 / ISO TS 17419 registry).
# messageID 3 was "poi" in the older (v1.3.1.1) CDD and was renamed "poim"
# (POI Message, TS 103916) in the current one; using the current name here.
MESSAGE_ID_NAMES = {
    1: "denm", 2: "cam", 3: "poim", 4: "spatem", 5: "mapem", 6: "ivim",
    7: "ev-rsr", 8: "tistpg", 9: "srem", 10: "ssem", 11: "evcsn",
    12: "saem", 13: "rtcmem", 14: "cpm", 15: "imzm", 16: "vam",
    17: "dsm", 18: "pcim", 19: "pcvm", 20: "mcm", 21: "pam",
}

_FILESETS = {
    "cam": ["cam_1_4_1.asn", "cdd_1_3_1_1.asn"],
    "denm_v1": ["denm_1_3_1.asn", "cdd_1_3_1_1.asn"],
    "denm_v2": ["denm_2_2_1.asn", "cdd_2_2_1.asn"],
    "cpm_v1": ["cpm_1.asn", "cam_1_4_1.asn", "cdd_1_3_1_1.asn", "dsrc_2_2_1.asn", "cdd_2_2_1.asn"],
    "cpm_v2": ["cpm_2_1_1.asn", "cdd_2_2_1.asn"],
    "ivim_v1": ["ivim_2_1_1.asn", "cdd_1_3_1_1.asn", "dsrc_2_2_1.asn", "cdd_2_2_1.asn"],
    "mapem": ["mapem_2_2_1.asn", "cdd_2_2_1.asn", "dsrc_2_2_1.asn"],
    "spatem": ["spatem_2_2_1.asn", "cdd_2_2_1.asn", "dsrc_2_2_1.asn"],
    "srem": ["srem_2_2_1.asn", "cdd_2_2_1.asn", "dsrc_2_2_1.asn"],
    "ssem": ["ssem_2_2_1.asn", "cdd_2_2_1.asn", "dsrc_2_2_1.asn"],
    "poim": ["poim-pdu-description.asn", "poim-commoncontainers.asn", "cdd_2_2_1.asn"],
    "evrsr": ["ev-rsr-pdu-descriptions.asn", "cdd_1_3_1_1.asn"],
    "tistpg": ["tis-tpg-transactions-descriptions.asn", "cdd_1_3_1_1.asn"],
    "evcsn": ["evcsn-pdu-descriptions.asn", "cdd_1_3_1_1.asn"],
    "rtcmem": ["rtcmem_2_2_1.asn", "cdd_1_3_1_1.asn", "dsrc_2_2_1.asn", "cdd_2_2_1.asn"],
    "vam": ["vam-pdu-descriptions.asn", "motorcyclist-special-container.asn", "cdd_2_2_1.asn"],
    "saem": [
        "saem/EN302890-1.asn",
        "saem/ETSI_TS_102894-2_CDD_1_3_1.asn",
        "saem/TS16460_2016_ITSsa.asn",
        "saem/TS16460_2016_ITSee.asn",
        "saem/TS16460_2016_ITSlm_Reduced.asn",
        "saem/ISO21218_2013A1_CALMllsap_Reduced.asn",
        "saem/ISO_TS_17419_Reduced.asn",
    ],
}

# messageID -> list of (fileset, top-level ASN.1 type, result label,
# required_protocol_version). UPER has no self-describing tags, so feeding
# the wrong schema version to asn1tools does not reliably raise an error --
# it can silently decode nonsense bits into a structurally plausible but
# wrong result (verified empirically: a v1 DENM decoded against the v2
# schema "succeeds" with garbage CHOICE fields). The DENM v2 and CPM v2
# ASN.1 modules both constrain their header to `protocolVersion (2)`, so
# that field -- which exists precisely "to select the appropriate protocol
# decoder at the receiving ITS-S" (IVIM spec comment) -- is used to pick
# the right schema first. The other version is kept as a fallback only for
# the rare case a station mislabels protocolVersion.
_CANDIDATES = {
    1: [("denm_v1", "DENM", "denm_v1", None), ("denm_v2", "DENM", "denm_v2", 2)],
    2: [("cam", "CAM", "cam", None)],
    3: [("poim", "POIM", "poim", 1)],
    4: [("spatem", "SPATEM", "spatem", None)],
    5: [("mapem", "MAPEM", "mapem", None)],
    6: [("ivim_v1", "IVIM", "ivim_v1", None)],
    7: [("evrsr", "EV-RSR", "evrsr", None)],
    8: [("tistpg", "TisTpgTransactionsPdu", "tistpg", None)],
    9: [("srem", "SREM", "srem", None)],
    10: [("ssem", "SSEM", "ssem", None)],
    11: [("evcsn", "EvcsnPdu", "evcsn", None)],
    12: [("saem", "SAEM", "saem", None)],
    13: [("rtcmem", "RTCMEM", "rtcmem", None)],
    14: [("cpm_v1", "CPM", "cpm_v1", None), ("cpm_v2", "CollectivePerceptionMessage", "cpm_v2", 2)],
    16: [("vam", "VAM", "vam", 3)],
}

_compiled: dict[str, Any] = {}


def _spec(fileset: str):
    if fileset not in _compiled:
        files = [str(ASN1_DIR / name) for name in _FILESETS[fileset]]
        _compiled[fileset] = asn1tools.compile_files(files, "uper")
    return _compiled[fileset]


def preload() -> None:
    """Compile every ASN.1 fileset up front so the first MQTT message
    doesn't pay the (multi-second) compilation cost."""
    for name in _FILESETS:
        _spec(name)


class ItsPduHeader:
    __slots__ = ("protocol_version", "message_id", "station_id")

    def __init__(self, protocol_version: int, message_id: int, station_id: int):
        self.protocol_version = protocol_version
        self.message_id = message_id
        self.station_id = station_id

    def to_dict(self) -> dict:
        return {
            "protocol_version": self.protocol_version,
            "message_id": self.message_id,
            "message_type": MESSAGE_ID_NAMES.get(self.message_id, "unknown"),
            "station_id": self.station_id,
        }


def parse_header_only(data: bytes) -> ItsPduHeader:
    """Hand-decode the fixed 6-byte ItsPduHeader without asn1tools.

    ItsPduHeader is a plain, non-extensible SEQUENCE of three unsigned
    integers (1 + 1 + 4 bytes) with no optional fields, so in UPER it has
    no preamble bits and is always byte-aligned from offset 0.
    """
    if len(data) < 6:
        raise ValueError(f"Payload too short for ItsPduHeader: {len(data)} bytes")
    protocol_version, message_id = data[0], data[1]
    station_id = struct.unpack(">I", data[2:6])[0]
    return ItsPduHeader(protocol_version, message_id, station_id)


class DecodeResult:
    def __init__(self, header: ItsPduHeader, message_type: str, variant: Optional[str],
                 decoded: Optional[dict], error: Optional[str]):
        self.header = header
        self.message_type = message_type
        self.variant = variant
        self.decoded = decoded
        self.error = error

    @property
    def ok(self) -> bool:
        return self.decoded is not None


def decode_its_pdu(data: bytes) -> DecodeResult:
    header = parse_header_only(data)
    message_type = MESSAGE_ID_NAMES.get(header.message_id, f"unknown-{header.message_id}")

    candidates = _CANDIDATES.get(header.message_id)
    if not candidates:
        return DecodeResult(header, message_type, None, None,
                             f"No ASN.1 definition bundled for message type '{message_type}' "
                             f"(messageID={header.message_id}); header decoded only")

    # Try the candidate whose required protocolVersion matches the header
    # first (stable sort keeps the declared fallback order otherwise).
    candidates = sorted(
        candidates,
        key=lambda c: 0 if c[3] is not None and c[3] == header.protocol_version else 1,
    )

    errors = []
    for fileset, type_name, label, _required_pv in candidates:
        try:
            spec = _spec(fileset)
            decoded = spec.decode(type_name, data)
            return DecodeResult(header, message_type, label, decoded, None)
        except Exception as exc:  # asn1tools raises plain Exception subclasses
            errors.append(f"{label}: {exc}")

    return DecodeResult(header, message_type, None, None,
                         "All ASN.1 decode attempts failed: " + " | ".join(errors))


# --------------------------------------------------------------------------
# Common facility-layer field extraction (for flattened, indexable columns)
# --------------------------------------------------------------------------

_LAT_UNAVAILABLE = 900000001
_LON_UNAVAILABLE = 1800000001
_ALT_UNAVAILABLE = 800001
_SPEED_UNAVAILABLE = 16383
_HEADING_UNAVAILABLE = 3601


def _deg(value: Optional[int], unavailable: int) -> Optional[float]:
    if value is None or value == unavailable:
        return None
    return value / 1e7


def extract_reference_position(ref_pos: Optional[dict]) -> dict:
    if not ref_pos:
        return {}
    lat = ref_pos.get("latitude")
    lon = ref_pos.get("longitude")
    alt = (ref_pos.get("altitude") or {}).get("altitudeValue")
    return {
        "latitude_deg": _deg(lat, _LAT_UNAVAILABLE),
        "longitude_deg": _deg(lon, _LON_UNAVAILABLE),
        "altitude_m": None if alt is None or alt == _ALT_UNAVAILABLE else alt / 100.0,
    }


def extract_cam_fields(decoded: dict) -> dict:
    """Pull out the fields a map viewer typically wants from a decoded CAM."""
    out: dict = {}
    cam = decoded.get("cam", {})
    out["generation_delta_time"] = cam.get("generationDeltaTime")

    params = cam.get("camParameters", {})
    basic = params.get("basicContainer", {})
    out["station_type"] = basic.get("stationType")
    out.update(extract_reference_position(basic.get("referencePosition")))

    hf_container = params.get("highFrequencyContainer")
    if isinstance(hf_container, tuple) and len(hf_container) == 2:
        hf_kind, hf = hf_container
        out["hf_container_kind"] = hf_kind
        if hf_kind == "basicVehicleContainerHighFrequency":
            heading = (hf.get("heading") or {}).get("headingValue")
            speed = (hf.get("speed") or {}).get("speedValue")
            out["heading_deg"] = None if heading is None or heading == _HEADING_UNAVAILABLE else heading / 10.0
            out["speed_m_s"] = None if speed is None or speed == _SPEED_UNAVAILABLE else speed / 100.0
            out["drive_direction"] = hf.get("driveDirection")
            vlen = (hf.get("vehicleLength") or {}).get("vehicleLengthValue")
            out["vehicle_length_m"] = None if vlen is None or vlen == 1023 else vlen / 10.0
            vwid = hf.get("vehicleWidth")
            out["vehicle_width_m"] = None if vwid is None or vwid == 62 else vwid / 10.0
        elif hf_kind == "rsuContainerHighFrequency":
            # RSUContainerHighFrequency ::= SEQUENCE { protectedCommunicationZonesRSU
            # ProtectedCommunicationZonesRSU OPTIONAL, ... } -- a list of
            # DSRC/tolling-style zones the RSU is announcing, each with its
            # own position. RSUs have no heading/speed/dimensions.
            zones = hf.get("protectedCommunicationZonesRSU") or []
            out["protected_zones"] = [
                {
                    "zone_type": z.get("protectedZoneType"),
                    "latitude_deg": _deg(z.get("protectedZoneLatitude"), _LAT_UNAVAILABLE),
                    "longitude_deg": _deg(z.get("protectedZoneLongitude"), _LON_UNAVAILABLE),
                    "radius_m": z.get("protectedZoneRadius"),
                    "zone_id": z.get("protectedZoneID"),
                }
                for z in zones
            ]
    return out


_CHOICE_NAME_CODE_RE = re.compile(r"(\d+)$")


def _cause_code_v1_or_v2(cause: Optional[dict]) -> tuple[Optional[int], Optional[int]]:
    """CauseCode (DENM v1, EN 302637-3 v1.2.2) is a plain
    {causeCode, subCauseCode} SEQUENCE. CauseCodeV2 (DENM v2, v2.2.1) wraps
    a big CHOICE (`ccAndScc`) whose alternative name embeds the cause code
    as a numeric suffix, e.g. ('accident2', <subCauseCode int>)."""
    if not cause:
        return None, None
    if "causeCode" in cause:
        return cause.get("causeCode"), cause.get("subCauseCode")
    cc_and_scc = cause.get("ccAndScc")
    if isinstance(cc_and_scc, tuple) and len(cc_and_scc) == 2:
        choice_name, sub_cause = cc_and_scc
        m = _CHOICE_NAME_CODE_RE.search(choice_name)
        cause_code = int(m.group(1)) if m else None
        sub_cause_code = sub_cause if isinstance(sub_cause, int) else None
        return cause_code, sub_cause_code
    return None, None


def extract_denm_fields(decoded: dict) -> dict:
    out: dict = {}
    denm = decoded.get("denm", {})
    mgmt = denm.get("management", {})

    # DENM v1 uses "actionID"/"originatingStationID", v2 uses "actionId"/"originatingStationId".
    action_id = mgmt.get("actionID") or mgmt.get("actionId") or {}
    out["originating_station_id"] = action_id.get("originatingStationID", action_id.get("originatingStationId"))
    out["sequence_number"] = action_id.get("sequenceNumber")
    out["detection_time"] = mgmt.get("detectionTime")
    out["reference_time"] = mgmt.get("referenceTime")
    out["termination"] = mgmt.get("termination")
    out["station_type"] = mgmt.get("stationType")
    out.update(extract_reference_position(mgmt.get("eventPosition")))

    situation = denm.get("situation")
    if situation:
        cause_code, sub_cause_code = _cause_code_v1_or_v2(situation.get("eventType"))
        out["cause_code"] = cause_code
        out["sub_cause_code"] = sub_cause_code
    return out


# --------------------------------------------------------------------------
# CPM (Collective Perception Message)
# --------------------------------------------------------------------------

# CPM v2's cpmContainers is an ASN.1 "open type" (CPM-CONTAINER-ID-AND-TYPE
# Information Object Class): asn1tools can't automatically resolve
# containerData to the concrete type identified by containerId, so it comes
# back as raw undecoded bytes that need a second spec.decode() pass with
# the right type name (verified empirically -- see its_decoder tests).
_CPM_V2_CONTAINER_TYPES = {
    1: "OriginatingVehicleContainer",
    2: "OriginatingRsuContainer",
    3: "SensorInformationContainer",
    4: "PerceptionRegionContainer",
    5: "PerceivedObjectContainer",
}


def _tenth_meter(value: Optional[int]) -> Optional[float]:
    return None if value is None else value / 10.0


def _centimeter(value: Optional[int]) -> Optional[float]:
    return None if value is None else value / 100.0


def _extract_trailer(trailer: dict) -> dict:
    """TrailerData: same field names/units (StandardLength1B / CartesianAngle,
    both 0.1-unit DEs per the CDD) in both CPM v1's locally-declared
    TrailerData and CPM v2's shared-CDD TrailerData, so one helper covers both."""
    hitch_angle = (trailer.get("hitchAngle") or {}).get("value")
    trailer_width = trailer.get("trailerWidth")
    return {
        "ref_point_id": trailer.get("refPointId"),
        "hitch_point_offset_m": _tenth_meter(trailer.get("hitchPointOffset")),
        "front_overhang_m": _tenth_meter(trailer.get("frontOverhang")),
        "rear_overhang_m": _tenth_meter(trailer.get("rearOverhang")),
        "trailer_width_m": None if trailer_width is None or trailer_width == 62 else trailer_width / 10.0,
        "hitch_angle_deg": None if hitch_angle is None or hitch_angle in (3600, 3601) else hitch_angle / 10.0,
    }


def _cpm_classification(class_list: Optional[list]) -> Optional[str]:
    """A perceived object can carry more than one candidate classification;
    only the first (highest-priority) one is summarized here as a compact
    'choiceName:value' string -- the full list is still in decoded_json.

    CPM v2's ObjectClassDescription entries are {objectClass, confidence}
    with objectClass a CHOICE of (mostly) plain enums. CPM v1's are
    {confidence, class} with class a CHOICE whose alternatives (vehicle/
    person/animal/other) are themselves SEQUENCEs like {type, confidence}
    rather than a bare value -- handled generically below rather than
    assuming either shape."""
    if not class_list:
        return None
    first = class_list[0]
    if not isinstance(first, dict):
        return None
    choice = first.get("objectClass") if "objectClass" in first else first.get("class")
    if not (isinstance(choice, tuple) and len(choice) == 2):
        return None
    kind, value = choice
    if isinstance(value, str):
        return f"{kind}:{value}"
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        return f"{kind}:{value[0]}"
    if isinstance(value, dict):
        inner = value.get("type")
        return f"{kind}:{inner}" if inner is not None else kind
    return kind


def extract_cpm_fields(decoded: dict, variant: str) -> dict:
    """Pull out the CPM sender's own position/type plus what it perceived.
    `variant` is the its_decoder asn1_variant label ('cpm_v1' or 'cpm_v2'),
    since the two versions use structurally different payloads.

    Perceived object x/y/z are relative Cartesian offsets in metres from
    the reporting station (not absolute lat/lon) -- converting them to map
    coordinates needs the station's own position *and* heading, which
    isn't attempted here to avoid guessing at the exact rotation/axis
    convention and silently producing wrong-looking positions."""
    out: dict = {"perceived_objects": [], "trailers": [], "origin_kind": None}

    if variant == "cpm_v1":
        cpm = decoded.get("cpm", {})
        out["generation_delta_time"] = cpm.get("generationDeltaTime")
        params = cpm.get("cpmParameters", {})
        mgmt = params.get("managementContainer", {})
        out["station_type"] = mgmt.get("stationType")
        out.update(extract_reference_position(mgmt.get("referencePosition")))

        station_data = params.get("stationDataContainer")
        if isinstance(station_data, tuple) and len(station_data) == 2:
            kind, sd = station_data
            out["origin_kind"] = kind
            if kind == "originatingVehicleContainer":
                for trailer in sd.get("trailerDataContainer") or []:
                    out["trailers"].append(_extract_trailer(trailer))

        for obj in params.get("perceivedObjectContainer") or []:
            out["perceived_objects"].append({
                "object_id": obj.get("objectID"),
                "x_m": _centimeter((obj.get("xDistance") or {}).get("value")),
                "y_m": _centimeter((obj.get("yDistance") or {}).get("value")),
                "z_m": _centimeter((obj.get("zDistance") or {}).get("value")),
                "measurement_delta_time_ms": obj.get("timeOfMeasurement"),
                "object_age_ms": obj.get("objectAge"),
                "classification": _cpm_classification(obj.get("classification")),
            })

    elif variant == "cpm_v2":
        payload = decoded.get("payload", {})
        mgmt = payload.get("managementContainer", {})
        out["generation_delta_time"] = None
        out["reference_time"] = mgmt.get("referenceTime")
        out.update(extract_reference_position(mgmt.get("referencePosition")))

        spec = _spec("cpm_v2")
        for wrapped in payload.get("cpmContainers") or []:
            type_name = _CPM_V2_CONTAINER_TYPES.get(wrapped.get("containerId"))
            raw = wrapped.get("containerData")
            if not type_name or not isinstance(raw, (bytes, bytearray)):
                continue
            try:
                container = spec.decode(type_name, raw)
            except Exception:
                continue

            if type_name == "OriginatingVehicleContainer":
                out["origin_kind"] = "originatingVehicleContainer"
                for trailer in container.get("trailerDataSet") or []:
                    out["trailers"].append(_extract_trailer(trailer))
            elif type_name == "OriginatingRsuContainer":
                out["origin_kind"] = "originatingRsuContainer"
            elif type_name == "PerceivedObjectContainer":
                for obj in container.get("perceivedObjects") or []:
                    pos = obj.get("position") or {}
                    out["perceived_objects"].append({
                        "object_id": obj.get("objectId"),
                        "x_m": _centimeter((pos.get("xCoordinate") or {}).get("value")),
                        "y_m": _centimeter((pos.get("yCoordinate") or {}).get("value")),
                        "z_m": _centimeter((pos.get("zCoordinate") or {}).get("value")),
                        "measurement_delta_time_ms": obj.get("measurementDeltaTime"),
                        "object_age_ms": obj.get("objectAge"),
                        "classification": _cpm_classification(obj.get("classification")),
                    })
    return out


# --------------------------------------------------------------------------
# SPATEM (Signal Phase And Timing -- traffic lights)
# --------------------------------------------------------------------------

def extract_spatem_fields(decoded: dict) -> list:
    """One dict per (intersection, signal group) currently reported. SPATEM
    can list several MovementEvents per group (current phase plus
    predicted future ones); only the first -- the current one -- is
    extracted here, matching the spec's convention of listing the nearest-
    term state first. SPATEM carries no intersection position; that comes
    from the corresponding MAPEM, which isn't cross-referenced here."""
    out = []
    spat = decoded.get("spat", {})
    for intersection in spat.get("intersections") or []:
        ref = intersection.get("id", {})
        for state in intersection.get("states") or []:
            events = state.get("state-time-speed") or []
            if not events:
                continue
            current = events[0]
            timing = current.get("timing") or {}
            out.append({
                "intersection_id": ref.get("id"),
                "region": ref.get("region"),
                "signal_group": state.get("signalGroup"),
                "event_state": current.get("eventState"),
                "min_end_time": timing.get("minEndTime"),
                "max_end_time": timing.get("maxEndTime"),
                "likely_end_time": timing.get("likelyTime"),
            })
    return out


# --------------------------------------------------------------------------
# MAPEM (intersection / lane topology -- the geometry SPATEM's signal states
# apply to)
# --------------------------------------------------------------------------

_ELEVATION_UNAVAILABLE = -4096
_METRES_PER_DEGREE = 111320.0  # good enough for intersection-scale offsets


def _elevation_m(value: Optional[int]) -> Optional[float]:
    return None if value is None or value == _ELEVATION_UNAVAILABLE else value / 10.0


def _decode_node_list(node_list: Optional[tuple], start_lat: float, start_lon: float) -> list:
    """NodeListXY is a CHOICE; only the common 'nodes' (NodeSetXY) alternative
    is handled here -- 'computed' (ComputedLane: a reference to another
    lane's path plus a transform) and 'regional' extensions are rare in
    practice and are skipped rather than guessed at.

    Each NodeXY is normally an X/Y offset in centimetres from the previous
    point (DSRC Node-XY-*b types; the first node offsets from the
    intersection's refPoint), except the 'node-LatLon' alternative which
    gives an absolute lat/lon and becomes the new anchor for subsequent
    offsets. Offsets are converted to lat/lon with a flat-earth
    (equirectangular) approximation centred on the current anchor --
    inaccurate over long distances, but lane node spacing is metres, so this
    is well under GPS accuracy at the scale a live map needs."""
    if not (isinstance(node_list, tuple) and len(node_list) == 2 and node_list[0] == "nodes"):
        return []
    points = []
    lat, lon = start_lat, start_lon
    for node in node_list[1] or []:
        delta = node.get("delta")
        if not (isinstance(delta, tuple) and len(delta) == 2):
            continue
        kind, value = delta
        if kind == "node-LatLon":
            new_lat = _deg(value.get("lat"), _LAT_UNAVAILABLE)
            new_lon = _deg(value.get("lon"), _LON_UNAVAILABLE)
            if new_lat is None or new_lon is None:
                continue
            lat, lon = new_lat, new_lon
        elif kind.startswith("node-XY"):
            x_cm, y_cm = value.get("x"), value.get("y")
            if x_cm is None or y_cm is None:
                continue
            lat += (y_cm / 100.0) / _METRES_PER_DEGREE
            cos_lat = math.cos(math.radians(lat)) or 1e-9
            lon += (x_cm / 100.0) / (_METRES_PER_DEGREE * cos_lat)
        else:
            continue
        points.append([round(lon, 7), round(lat, 7)])
    return points


def extract_mapem_fields(decoded: dict) -> list:
    """One dict per intersection described in the MapData. Lane geometry is
    resolved into absolute lon/lat polylines (see `_decode_node_list`) so
    downstream consumers (the map viewer) don't need to redo the offset
    accumulation themselves."""
    out = []
    map_data = decoded.get("map", {})
    for isec in map_data.get("intersections") or []:
        ref = isec.get("id", {})
        ref_point = isec.get("refPoint") or {}
        lat = _deg(ref_point.get("lat"), _LAT_UNAVAILABLE)
        lon = _deg(ref_point.get("long"), _LON_UNAVAILABLE)
        if lat is None or lon is None:
            continue
        lanes = []
        for lane in isec.get("laneSet") or []:
            lanes.append({
                "lane_id": lane.get("laneID"),
                "name": lane.get("name"),
                "ingress_approach": lane.get("ingressApproach"),
                "egress_approach": lane.get("egressApproach"),
                "points": _decode_node_list(lane.get("nodeList"), lat, lon),
            })
        out.append({
            "intersection_id": ref.get("id"),
            "region": ref.get("region"),
            "name": isec.get("name"),
            "revision": isec.get("revision"),
            "latitude_deg": lat,
            "longitude_deg": lon,
            "altitude_m": _elevation_m(ref_point.get("elevation")),
            "lanes": lanes,
        })
    return out
