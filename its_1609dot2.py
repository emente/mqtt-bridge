"""
Minimal, targeted Canonical OER (COER) reader for IEEE 1609.2 secured
GeoNetworking packets.

Why hand-rolled instead of using asn1tools like everything else in this
project: asn1tools's ASN.1 grammar only supports single-field CLASS
definitions (verified empirically -- a bare two-field CLASS already fails
to parse), and IEEE 1609.2's real ASN.1
(https://forge.etsi.org/rep/ITS/asn1/ieee1609.2) uses multi-field CLASS
constructs extensively for its certificate-extension and header-extension
mechanisms. Fully compiling it would mean manually flattening every use of
that Information Object Class system across ~135KB of standard text, with
no way to test the result against real traffic here.

What's actually needed is much narrower: given the bytes following a
GeoNetworking Basic Header whose next_header says "secured packet", walk

    Ieee1609Dot2Data
      .content (CHOICE) == signedData
        .tbsData.payload.data (Ieee1609Dot2Data, recursive)
          .content (CHOICE) == unsecuredData (OCTET STRING)

and return those bytes -- which are the plaintext GeoNetworking Common
Header onward, ready to feed back into the normal unsecured decode path
(see gnw.rs's own get_content_from_secured_header() in cits-to-json/
C-ITS-Parser, which does exactly this). `signer` and `signature` (the
fields after `tbsData` in SignedData) are never touched: SEQUENCE fields
are COER-encoded in declaration order, `tbsData` comes first, and nothing
past it is needed once its `payload.data` has been read out.

"Secured" here means signed (IEEE 1609.2 SignedData: certificate +
signature over plaintext), not encrypted -- the payload is recoverable
without any key material. A genuinely `encryptedData` content type is
detected and reported as such, not guessed at.

Byte layout decisions below (constrained INTEGER still takes a full octet
in COER, small extensible CHOICE/ENUMERATED tags are one octet with the
top bit marking root(1)/extension(0) and the low 7 bits a 0-based index,
SEQUENCEs with no OPTIONAL fields and no extension marker have no preamble
at all) are cross-checked against real captured traffic, not just the
ITU-T X.696 spec text -- an initial reading of X.696 suggested the
opposite root/extension bit polarity, which round-tripped fine against
this module's own encoder in testing but produced "unknown(ext:1)" against
a real signed CAM (bytes `03 81 ...`: protocolVersion=3, then a tag byte
that turned out to mean root index 1 = signedData, not extension index 1).
Also cross-checked against the field lists in asn1/ieee1609dot2/
Ieee1609Dot2.asn (see IEEE1609Dot2Data, Ieee1609Dot2Content, SignedData,
ToBeSignedData, SignedDataPayload, HashAlgorithm).
"""

from __future__ import annotations

from typing import Optional


class Coer1609Dot2Error(Exception):
    pass


class _Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise Coer1609Dot2Error(
                f"buffer underrun: need {n} bytes at offset {self.pos}, "
                f"have {len(self.data) - self.pos}")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def read_u8(self) -> int:
        return self.read(1)[0]


def _read_length_determinant(cur: _Cursor) -> int:
    """General COER length determinant (X.696 8.6): short form (0..127) is
    a single octet; long form has the top bit set, remaining 7 bits give
    the number of subsequent big-endian octets holding the real length."""
    first = cur.read_u8()
    if (first & 0x80) == 0:
        return first
    n = first & 0x7F
    if n == 0 or n > 8:
        raise Coer1609Dot2Error(f"unsupported length-of-length {n}")
    return int.from_bytes(cur.read(n), "big")


def _read_octet_string(cur: _Cursor) -> bytes:
    length = _read_length_determinant(cur)
    return cur.read(length)


def _read_small_tag(cur: _Cursor) -> tuple[bool, int]:
    """Reads a one-octet extensible CHOICE/ENUMERATED tag: top bit 1 = root
    alternative, 0 = extension alternative; low 7 bits = 0-based index.
    (Verified against real captured traffic: Ieee1609Dot2Content's
    unsecuredData, root index 0, encodes as 0x80; signedData, root index 1,
    as 0x81 -- i.e. bit7 set means root, not extension as an initial
    from-the-spec-text reading suggested.) Only valid where the type has
    <=127 alternatives on each side, true for everything this module
    touches."""
    b = cur.read_u8()
    is_extension = not bool(b & 0x80)
    return is_extension, b & 0x7F


# Ieee1609Dot2Content ::= CHOICE { unsecuredData, signedData, encryptedData,
#   signedCertificateRequest, ..., signedX509CertificateRequest }
_CONTENT_ALTERNATIVES = {
    (False, 0): "unsecuredData",
    (False, 1): "signedData",
    (False, 2): "encryptedData",
    (False, 3): "signedCertificateRequest",
    (True, 0): "signedX509CertificateRequest",
}

_MAX_RECURSION = 4


def _decode_ieee1609dot2_data(cur: _Cursor, depth: int = 0) -> tuple[Optional[bytes], dict]:
    if depth > _MAX_RECURSION:
        raise Coer1609Dot2Error("Ieee1609Dot2Data nesting too deep")

    # Ieee1609Dot2Data ::= SEQUENCE { protocolVersion Uint8(3), content ... }
    # No OPTIONAL fields, not extensible -> no preamble; protocolVersion is
    # constrained to a single value but COER (unlike PER/UPER) does not
    # elide constrained-to-one-value integers, so it's still one octet.
    protocol_version = cur.read_u8()
    is_ext, idx = _read_small_tag(cur)
    content_type = _CONTENT_ALTERNATIVES.get((is_ext, idx), f"unknown({'ext' if is_ext else 'root'}:{idx})")
    info: dict = {"protocol_version": protocol_version, "content_type": content_type}

    if content_type == "unsecuredData":
        return _read_octet_string(cur), info

    if content_type != "signedData":
        # encryptedData: genuinely encrypted, no key material available here.
        # signedCertificateRequest / signedX509CertificateRequest: not a GN
        # payload envelope, shouldn't appear here in practice.
        return None, info

    # SignedData ::= SEQUENCE { hashId HashAlgorithm, tbsData ToBeSignedData,
    #   signer SignerIdentifier, signature Signature }
    # All four fields mandatory, no extension marker -> no preamble.
    # HashAlgorithm ::= ENUMERATED { sha256, ..., sha384, sm3 }: one root
    # value + two extension values, still just one octet -- skip it, we
    # don't need to verify anything.
    info["hash_algorithm_raw"] = cur.read_u8()

    # ToBeSignedData ::= SEQUENCE { payload SignedDataPayload, headerInfo
    # HeaderInfo }. Two mandatory fields, no extension marker -> no
    # preamble. `payload` comes first, which is all we need; `headerInfo`
    # (and the SignedData fields after tbsData: signer, signature) are
    # never read.
    #
    # SignedDataPayload ::= SEQUENCE { data Ieee1609Dot2Data OPTIONAL,
    #   extDataHash HashedData OPTIONAL, ..., omitted NULL OPTIONAL }
    # Extensible with 2 root OPTIONALs -> 1 preamble octet: bit7 =
    # extension-additions-present, bit6 = data present, bit5 = extDataHash
    # present, remaining bits reserved/zero.
    preamble = cur.read_u8()
    data_present = bool(preamble & 0x40)
    info["payload_has_data"] = data_present
    info["payload_has_ext_data_hash"] = bool(preamble & 0x20)

    if not data_present:
        # The actual content isn't embedded (only a hash of externally-held
        # data, or nothing) -- genuinely nothing to recover here.
        return None, info

    inner_bytes, inner_info = _decode_ieee1609dot2_data(cur, depth + 1)
    info["inner"] = inner_info
    return inner_bytes, info


def decode_secured_gn_payload(data: bytes) -> tuple[Optional[bytes], dict]:
    """
    `data` is everything after a GeoNetworking Basic Header whose
    next_header says "secured packet" -- i.e. a COER-encoded
    IEEE 1609.2 Ieee1609Dot2Data.

    Returns (plaintext, info). `plaintext` is the recovered GeoNetworking
    Common Header onward (same shape the unsecured path expects) if this
    was a SignedData envelope with an embedded unsecuredData payload,
    otherwise None (e.g. genuinely encrypted, or only an external data
    hash was referenced). `info` carries whatever was cheaply decoded
    along the way (content type, hash algorithm) regardless of outcome,
    for logging/debugging -- plus `info["error"]` on a decode failure.
    """
    cur = _Cursor(data)
    try:
        return _decode_ieee1609dot2_data(cur)
    except Coer1609Dot2Error as exc:
        return None, {"error": str(exc)}
