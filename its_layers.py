"""
Byte-level decoding of the lower protocol layers carried in the MQTT
`its/<device>/packet` payload published by the ESP32-C3 bridge:

    IEEE 802.11p (OCB) MAC header
      -> LLC/SNAP
        -> GeoNetworking (ETSI EN 302 636-4-1)
          -> BTP-A / BTP-B (ETSI EN 302 636-5-1)
            -> ITS facility layer PDU (ASN.1 UPER, see its_decoder.py)

Field names and byte layouts are cross-checked against the dissector in
https://codeberg.org/opentrafficmap/cits-to-json (src/dissect/*.rs), which
is the reference implementation for this same MQTT payload format.

cits-to-json's src/dissect/packetv1.rs unconditionally strips 8 trailing
bytes from every frame, citing a bug in a *different* upstream firmware
("its-g5-receiver-firmware", the RF sniffer this bridge's Serial1 is wired
to -- not this repo's own esp32-c3-bridge.ino, which forwards whatever
bytes it receives over MQTT verbatim, unmodified). That number was never
independently verified against this project's own captures, so instead of
blindly repeating it, the GeoNetworking Common Header's self-describing
`payload_length` field (see parse_geonetworking()) is used to trim the
BTP+facility payload to its declared size -- whatever trailing bytes
remain (0, 8, or anything else) are simply left over and reported
(GnResult.trailing_bytes_hex), not assumed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Optional

import its_1609dot2

LT_BASE_MS = {0: 50, 1: 1000, 2: 10000, 3: 100000}

GN_BH_NEXT_HEADER = {0: "any", 1: "common_header", 2: "secured_packet"}
GN_CH_NEXT_HEADER = {0: "any", 1: "btp_a", 2: "btp_b", 3: "ipv6"}


class DecodeError(Exception):
    pass


def _mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


# --------------------------------------------------------------------------
# IEEE 802.11
# --------------------------------------------------------------------------

@dataclass
class Ieee80211Header:
    frame_type: int
    frame_subtype: int
    to_ds: bool
    from_ds: bool
    more_frag: bool
    retry: bool
    pwr_mgt: bool
    more_data: bool
    protected: bool
    order: bool
    duration: int
    addr1: str
    addr2: str
    addr3: str
    addr4: Optional[str]
    bssid: Optional[str]
    ra: str
    ta: str
    da: str
    sa: str
    fragment_number: int
    sequence_number: int
    qos_control: Optional[int]
    header_len: int

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d.pop("header_len")
        return d


def parse_ieee80211(data: bytes) -> tuple[Ieee80211Header, bytes]:
    if len(data) < 24:
        raise DecodeError(f"Frame too short for 802.11 header: {len(data)} bytes")

    fc0, fc1 = data[0], data[1]
    frame_type = (fc0 >> 2) & 0x3
    frame_subtype = (fc0 >> 4) & 0xF
    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    more_frag = bool(fc1 & 0x04)
    retry = bool(fc1 & 0x08)
    pwr_mgt = bool(fc1 & 0x10)
    more_data = bool(fc1 & 0x20)
    protected = bool(fc1 & 0x40)
    order = bool(fc1 & 0x80)

    if frame_type != 2:
        raise DecodeError(f"Unsupported frame type {frame_type} (only Data frames are handled)")

    duration = struct.unpack("<H", data[2:4])[0]
    addr1 = data[4:10]
    addr2 = data[10:16]
    addr3 = data[16:22]
    sc = struct.unpack("<H", data[22:24])[0]
    fragment_number = sc & 0xF
    sequence_number = (sc >> 4) & 0xFFF

    header_len = 24
    addr4 = None
    if to_ds and from_ds:
        if len(data) < header_len + 6:
            raise DecodeError("Frame too short for 4-address 802.11 header")
        addr4 = data[header_len:header_len + 6]
        header_len += 6

    qos_control = None
    if frame_subtype & 0x8:
        if len(data) < header_len + 2:
            raise DecodeError("Frame too short for QoS control field")
        qos_control = struct.unpack("<H", data[header_len:header_len + 2])[0]
        header_len += 2

    # Address semantics per 802.11 (matches libwifi, used by cits-to-json):
    if not to_ds and not from_ds:
        ra, ta, da, sa, bssid = addr1, addr2, addr1, addr2, addr3
    elif to_ds and not from_ds:
        ra, ta, da, sa, bssid = addr1, addr2, addr3, addr2, addr1
    elif not to_ds and from_ds:
        ra, ta, da, sa, bssid = addr1, addr2, addr1, addr3, addr2
    else:
        ra, ta, da, sa, bssid = addr1, addr2, addr3, addr4, None

    header = Ieee80211Header(
        frame_type=frame_type,
        frame_subtype=frame_subtype,
        to_ds=to_ds, from_ds=from_ds, more_frag=more_frag, retry=retry,
        pwr_mgt=pwr_mgt, more_data=more_data, protected=protected, order=order,
        duration=duration,
        addr1=_mac_str(addr1), addr2=_mac_str(addr2), addr3=_mac_str(addr3),
        addr4=_mac_str(addr4) if addr4 else None,
        bssid=_mac_str(bssid) if bssid else None,
        ra=_mac_str(ra), ta=_mac_str(ta), da=_mac_str(da), sa=_mac_str(sa),
        fragment_number=fragment_number, sequence_number=sequence_number,
        qos_control=qos_control, header_len=header_len,
    )
    return header, data[header_len:]


# --------------------------------------------------------------------------
# LLC / SNAP
# --------------------------------------------------------------------------

GEONETWORKING_ETHERTYPE = 0x8947


@dataclass
class LlcHeader:
    dsap: int
    ssap: int
    control: int
    oui: Optional[str]
    ethertype: Optional[int]


def parse_llc(data: bytes) -> tuple[LlcHeader, bytes, bool]:
    if len(data) < 3:
        raise DecodeError("Frame too short for LLC header")
    dsap, ssap, control = data[0], data[1], data[2]
    rest = data[3:]
    oui = None
    ethertype = None
    if (dsap & 0xFE) == 0xAA and (ssap & 0xFE) == 0xAA:
        if len(rest) < 5:
            raise DecodeError("Frame too short for SNAP extension")
        oui_bytes = rest[0:3]
        ethertype = struct.unpack(">H", rest[3:5])[0]
        oui = _mac_str(oui_bytes).replace(":", ":").upper()
        rest = rest[5:]

    is_gn = (oui == "00:00:00" and ethertype == GEONETWORKING_ETHERTYPE)
    header = LlcHeader(dsap=dsap, ssap=ssap, control=control, oui=oui, ethertype=ethertype)
    return header, rest, is_gn


# --------------------------------------------------------------------------
# GeoNetworking (ETSI EN 302 636-4-1)
# --------------------------------------------------------------------------

def _sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


@dataclass
class GnAddr:
    manual: bool
    station_type: int
    mid: str


def _parse_gn_addr(data: bytes) -> GnAddr:
    b0, b1 = data[0], data[1]
    manual = bool(b0 & 0x80)
    station_type = (b0 >> 2) & 0x1F
    mid = _mac_str(data[2:8])
    return GnAddr(manual=manual, station_type=station_type, mid=mid)


@dataclass
class ShortPositionVector:
    gn_addr: GnAddr
    timestamp: int
    latitude: int
    longitude: int


def _parse_spv(data: bytes) -> ShortPositionVector:
    gn_addr = _parse_gn_addr(data[0:8])
    tst, lat, lon = struct.unpack(">Iii", data[8:20])
    return ShortPositionVector(gn_addr=gn_addr, timestamp=tst, latitude=lat, longitude=lon)


@dataclass
class LongPositionVector:
    spv: ShortPositionVector
    position_accuracy: bool
    speed_cm_s: int
    heading_decideg: int


def _parse_lpv(data: bytes) -> LongPositionVector:
    spv = _parse_spv(data[0:20])
    b0, b1, b2, b3 = data[20], data[21], data[22], data[23]
    pai = bool(b0 & 0x80)
    speed_raw = ((b0 & 0x7F) << 8) | b1
    speed = _sign_extend(speed_raw, 15)
    heading = (b2 << 8) | b3
    return LongPositionVector(spv=spv, position_accuracy=pai, speed_cm_s=speed, heading_decideg=heading)


def _lpv_dict(lpv: LongPositionVector) -> dict:
    return {
        "gn_addr": {"manual": lpv.spv.gn_addr.manual, "station_type": lpv.spv.gn_addr.station_type,
                    "mid": lpv.spv.gn_addr.mid},
        "timestamp": lpv.spv.timestamp,
        "latitude": lpv.spv.latitude, "longitude": lpv.spv.longitude,
        "latitude_deg": lpv.spv.latitude / 1e7, "longitude_deg": lpv.spv.longitude / 1e7,
        "position_accuracy": lpv.position_accuracy,
        "speed_cm_s": lpv.speed_cm_s, "speed_m_s": lpv.speed_cm_s / 100.0,
        "heading_decideg": lpv.heading_decideg, "heading_deg": lpv.heading_decideg / 10.0,
    }


def _spv_dict(spv: ShortPositionVector) -> dict:
    return {
        "gn_addr": {"manual": spv.gn_addr.manual, "station_type": spv.gn_addr.station_type,
                    "mid": spv.gn_addr.mid},
        "timestamp": spv.timestamp,
        "latitude": spv.latitude, "longitude": spv.longitude,
        "latitude_deg": spv.latitude / 1e7, "longitude_deg": spv.longitude / 1e7,
    }


_EXTENDED_HEADER_LEN = {
    (0, 0): 0,     # any / none
    (1, 0): 24,    # beacon
    (2, 0): 48,    # geo unicast (GUC)
    (3, 0): 44, (3, 1): 44, (3, 2): 44,  # geo broadcast (GBC)
    (4, 0): 44, (4, 1): 44, (4, 2): 44,  # geo anycast (GAC)
    (5, 0): 28,    # single hop broadcast (SHB)
    (5, 1): 28,    # topologically-scoped broadcast (TSB)
    (6, 0): 36,    # location service request
    (6, 1): 48,    # location service reply
}


def _parse_extended_header(ht: int, hst: int, data: bytes) -> tuple[str, dict, int]:
    length = _EXTENDED_HEADER_LEN.get((ht, hst))
    if length is None:
        raise DecodeError(f"Unknown GeoNetworking extended header type/subtype {ht}/{hst}")
    if len(data) < length:
        raise DecodeError(f"Frame too short for GeoNetworking extended header ({length} bytes needed)")
    body = data[:length]

    if (ht, hst) == (0, 0):
        return "none", {}, 0
    if (ht, hst) == (1, 0):
        return "beacon", {"source_pv": _lpv_dict(_parse_lpv(body))}, length
    if (ht, hst) == (2, 0):
        sn, _res = struct.unpack(">HH", body[0:4])
        src_pv = _parse_lpv(body[4:28])
        dst_pv = _parse_spv(body[28:48])
        return "geo_unicast", {"sequence_number": sn, "source_pv": _lpv_dict(src_pv),
                                "destination_pv": _spv_dict(dst_pv)}, length
    if ht in (3, 4):
        sn, _res = struct.unpack(">HH", body[0:4])
        src_pv = _parse_lpv(body[4:28])
        lat, lon, a, b, angle, _res1 = struct.unpack(">iiHHHH", body[28:44])
        kind = "geo_broadcast" if ht == 3 else "geo_anycast"
        shape = {0: "circle", 1: "rectangle", 2: "ellipse"}.get(hst, "unknown")
        return kind, {"sequence_number": sn, "source_pv": _lpv_dict(src_pv), "shape": shape,
                      "latitude": lat, "longitude": lon,
                      "latitude_deg": lat / 1e7, "longitude_deg": lon / 1e7,
                      "distance_a_m": a, "distance_b_m": b, "angle_deg": angle}, length
    if (ht, hst) == (5, 0):
        src_pv = _parse_lpv(body[0:24])
        cbr0, cbr1, txpr, mco = body[24], body[25], body[26], body[27]
        return "single_hop_broadcast", {
            "source_pv": _lpv_dict(src_pv),
            "dcc": {"cbr0": cbr0, "cbr1": cbr1, "tx_power_dbm": (txpr >> 4) & 0xF, "mco": mco},
        }, length
    if (ht, hst) == (5, 1):
        sn, _res = struct.unpack(">HH", body[0:4])
        src_pv = _parse_lpv(body[4:28])
        return "topo_broadcast", {"sequence_number": sn, "source_pv": _lpv_dict(src_pv)}, length
    if (ht, hst) == (6, 0):
        sn, _res = struct.unpack(">HH", body[0:4])
        src_pv = _parse_lpv(body[4:28])
        req_addr = _parse_gn_addr(body[28:36])
        return "ls_request", {"sequence_number": sn, "source_pv": _lpv_dict(src_pv),
                               "request_addr": {"manual": req_addr.manual,
                                                 "station_type": req_addr.station_type,
                                                 "mid": req_addr.mid}}, length
    if (ht, hst) == (6, 1):
        sn, _res = struct.unpack(">HH", body[0:4])
        src_pv = _parse_lpv(body[4:28])
        dst_pv = _parse_spv(body[28:48])
        return "ls_reply", {"sequence_number": sn, "source_pv": _lpv_dict(src_pv),
                             "destination_pv": _spv_dict(dst_pv)}, length

    raise DecodeError(f"Unhandled GeoNetworking extended header {ht}/{hst}")


@dataclass
class GnResult:
    basic_header: dict
    secured: bool
    secured_header_hex: Optional[str]
    secured_info: Optional[dict]
    common_header: Optional[dict]
    extended_header_kind: Optional[str]
    extended_header: Optional[dict]
    next_header: Optional[str]
    trailing_bytes_hex: Optional[str] = None


def parse_geonetworking(data: bytes) -> tuple[GnResult, Optional[bytes]]:
    if len(data) < 4:
        raise DecodeError("Frame too short for GeoNetworking basic header")

    b0, reserved, lt_byte, rhl = data[0], data[1], data[2], data[3]
    version = (b0 >> 4) & 0xF
    bh_next = b0 & 0xF
    lt_base = lt_byte & 0x3
    lt_mult = (lt_byte >> 2) & 0x3F
    basic_header = {
        "version": version,
        "next_header": GN_BH_NEXT_HEADER.get(bh_next, bh_next),
        "reserved": reserved,
        "lifetime_base": lt_base,
        "lifetime_multiplier": lt_mult,
        "lifetime_ms": lt_mult * LT_BASE_MS.get(lt_base, 0),
        "remaining_hop_limit": rhl,
    }
    rest = data[4:]

    secured = False
    secured_header_hex = None
    secured_info = None

    if bh_next == 2:
        # Secured packet: an IEEE 1609.2 Ieee1609Dot2Data (COER-encoded)
        # wraps everything that follows. its_1609dot2 walks just far enough
        # into it (SignedData.tbsData.payload.data.content.unsecuredData)
        # to recover the plaintext GN Common Header onward -- "secured"
        # here means signed, not encrypted, so the payload is recoverable
        # without any key material in the common case. If that fails (a
        # genuinely encrypted envelope, or a malformed/unsupported one),
        # the raw envelope bytes are kept as hex so nothing is lost.
        secured = True
        plaintext, secured_info = its_1609dot2.decode_secured_gn_payload(rest)
        if plaintext is None:
            secured_header_hex = rest.hex()
            result = GnResult(basic_header=basic_header, secured=True,
                               secured_header_hex=secured_header_hex,
                               secured_info=secured_info,
                               common_header=None, extended_header_kind=None,
                               extended_header=None, next_header=None)
            return result, None
        rest = plaintext

    if len(rest) < 8:
        raise DecodeError("Frame too short for GeoNetworking common header")
    ch = rest[0:8]
    nh_res0 = ch[0]
    ht_hst = ch[1]
    next_header = (nh_res0 >> 4) & 0xF
    reserved0 = nh_res0 & 0xF
    header_type = (ht_hst >> 4) & 0xF
    header_subtype = ht_hst & 0xF
    traffic_class = ch[2]
    flags = ch[3]
    mobile = bool(flags & 0x80)
    payload_length = struct.unpack(">H", ch[4:6])[0]
    max_hop_limit = ch[6]
    reserved1 = ch[7]

    common_header = {
        "next_header": GN_CH_NEXT_HEADER.get(next_header, next_header),
        "reserved0": reserved0,
        "header_type": header_type,
        "header_subtype": header_subtype,
        "traffic_class": traffic_class,
        "mobile": mobile,
        "flags_reserved": flags & 0x7F,
        "payload_length": payload_length,
        "maximum_hop_limit": max_hop_limit,
        "reserved1": reserved1,
    }

    after_ch = rest[8:]
    kind, ext, ext_len = _parse_extended_header(header_type, header_subtype, after_ch)
    candidate_payload = after_ch[ext_len:]

    # payload_length (above) is the GN Common Header's own declared size for
    # everything after the extended header (BTP + facility message), per
    # ETSI EN 302636-4-1. Trusting it -- rather than assuming a fixed
    # trailer size -- means any leftover bytes (0, 8, or otherwise) are
    # simply whatever's left over, not a guess baked into the parser.
    if len(candidate_payload) < payload_length:
        raise DecodeError(
            f"GeoNetworking payload_length declares {payload_length} bytes but only "
            f"{len(candidate_payload)} remain after the extended header (truncated packet?)")
    payload = candidate_payload[:payload_length]
    trailing = candidate_payload[payload_length:]
    trailing_bytes_hex = trailing.hex() if trailing else None

    result = GnResult(basic_header=basic_header, secured=secured, secured_header_hex=secured_header_hex,
                       secured_info=secured_info,
                       common_header=common_header, extended_header_kind=kind,
                       extended_header=ext, next_header=GN_CH_NEXT_HEADER.get(next_header, next_header),
                       trailing_bytes_hex=trailing_bytes_hex)
    return result, payload


# --------------------------------------------------------------------------
# BTP (ETSI EN 302 636-5-1)
# --------------------------------------------------------------------------

def parse_btp(kind: str, data: bytes) -> tuple[dict, bytes]:
    if len(data) < 4:
        raise DecodeError("Frame too short for BTP header")
    a, b = struct.unpack(">HH", data[0:4])
    if kind == "btp_a":
        header = {"type": "A", "destination_port": a, "source_port": b}
    elif kind == "btp_b":
        header = {"type": "B", "destination_port": a, "destination_port_info": b}
    else:
        raise DecodeError(f"Unsupported BTP variant '{kind}'")
    return header, data[4:]


# --------------------------------------------------------------------------
# Top level
# --------------------------------------------------------------------------

@dataclass
class LowerLayers:
    ieee80211: dict
    llc: dict
    gn: dict
    btp: Optional[dict]
    payload: Optional[bytes]
    error: Optional[str] = None


def parse_lower_layers(raw: bytes) -> LowerLayers:
    ieee_hdr, rest = parse_ieee80211(raw)
    llc_hdr, rest, is_gn = parse_llc(rest)
    if not is_gn:
        return LowerLayers(ieee80211=ieee_hdr.to_dict(), llc=llc_hdr.__dict__, gn={},
                            btp=None, payload=None,
                            error="LLC payload is not GeoNetworking (OUI/Ethertype mismatch)")

    gn, gn_payload = parse_geonetworking(rest)
    gn_dict = {
        "basic_header": gn.basic_header,
        "secured": gn.secured,
        "secured_header_hex": gn.secured_header_hex,
        "secured_info": gn.secured_info,
        "common_header": gn.common_header,
        "extended_header_kind": gn.extended_header_kind,
        "extended_header": gn.extended_header,
        "trailing_bytes_hex": gn.trailing_bytes_hex,
    }

    if gn_payload is None:
        # Only reachable when bh_next was "secured_packet" and
        # its_1609dot2 couldn't recover a plaintext payload from it (see
        # gn_dict["secured_info"] for what was learned along the way,
        # e.g. a genuinely encrypted content type).
        return LowerLayers(ieee80211=ieee_hdr.to_dict(), llc=llc_hdr.__dict__, gn=gn_dict,
                            btp=None, payload=None,
                            error="GeoNetworking secured packet (IEEE 1609.2) could not be decoded")

    if gn.next_header not in ("btp_a", "btp_b"):
        return LowerLayers(ieee80211=ieee_hdr.to_dict(), llc=llc_hdr.__dict__, gn=gn_dict,
                            btp=None, payload=gn_payload,
                            error=f"Unsupported GeoNetworking next header '{gn.next_header}'")

    btp_hdr, its_payload = parse_btp(gn.next_header, gn_payload)

    return LowerLayers(ieee80211=ieee_hdr.to_dict(), llc=llc_hdr.__dict__, gn=gn_dict,
                        btp=btp_hdr, payload=its_payload)
