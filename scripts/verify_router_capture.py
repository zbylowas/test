"""Verify TCP/443 Hop Limit evidence in an Ethernet/IPv6 PCAP from a controlled router."""

import argparse
import hashlib
import json
import struct
from ipaddress import IPv6Address
from pathlib import Path


def frames(stream):
    header = stream.read(24)
    formats = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}
    if len(header) != 24 or header[:4] not in formats:
        raise ValueError("microsecond classic PCAP required")
    order = formats[header[:4]]
    if struct.unpack_from(order + "I", header, 20)[0] != 1:
        raise ValueError("Ethernet link type required")
    while record := stream.read(16):
        if len(record) != 16:
            raise ValueError("truncated packet header")
        size = struct.unpack_from(order + "I", record, 8)[0]
        if size > 65535:
            raise ValueError("unexpected packet size")
        frame = stream.read(size)
        if len(frame) != size:
            raise ValueError("truncated capture")
        if frame[12:14] == b"\x86\xdd":
            yield frame[14:]


def probe_key(packet, target, syn=False):
    # This fixture uses plain IPv6. The first eight TCP bytes include both ports and sequence.
    if len(packet) < 48 or packet[0] >> 4 != 6 or packet[6] != 6 or packet[24:40] != target:
        return None
    if packet[42:44] != b"\x01\xbb":
        return None
    if syn and (packet[7] != 1 or len(packet) < 54 or packet[53] & 0x12 != 0x02):
        return None
    return packet[8:48]


def verify(path, target):
    probes, quoted, routers = set(), set(), set()
    with path.open("rb") as stream:
        for packet in frames(stream):
            key = probe_key(packet, target.packed, syn=True)
            if key:
                probes.add(key)
            if len(packet) < 96 or packet[6] != 58 or packet[40:42] != b"\x03\x00":
                continue
            key = probe_key(packet[48:], target.packed)
            if key in probes and packet[24:40] == key[:16] and packet[8:24] not in (target.packed, key[:16]):
                quoted.add(key)
                routers.add(packet[8:24])
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "capture_sha256": digest,
        "unique_tcp443_syn_hop_limit_1": len(probes),
        "unique_syn_matched_to_time_exceeded": len(quoted),
        "responding_router_count": len(routers),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("target", type=IPv6Address)
    args = parser.parse_args()
    result = verify(args.pcap, args.target)
    print(json.dumps(result))
    raise SystemExit(0 if result["unique_syn_matched_to_time_exceeded"] else 1)
