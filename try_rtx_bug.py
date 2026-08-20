#!/usr/bin/env python3

import ctypes
import ctypes.util
import subprocess


def load_opus():
    lib = ctypes.CDLL(
        ctypes.util.find_library("opus") or "libopus.so.0"
    )

    lib.opus_decoder_create.argtypes = [
        ctypes.c_int32,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.opus_decoder_create.restype = ctypes.c_void_p

    lib.opus_decoder_destroy.argtypes = [
        ctypes.c_void_p
    ]

    lib.opus_decode.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_int32,
        ctypes.POINTER(ctypes.c_int16),
        ctypes.c_int,
        ctypes.c_int,
    ]

    lib.opus_decode.restype = ctypes.c_int

    return lib


def parse_red(payload):
    """
    Returns:
        redundant blocks
        primary PT
        primary payload

    Returns None if the bytes cannot form a valid RFC2198 packet.
    """

    if not payload:
        return None

    headers = []
    pos = 0

    try:
        while True:
            if pos >= len(payload):
                return None

            b0 = payload[pos]

            follow = bool(b0 & 0x80)
            pt = b0 & 0x7F

            if not follow:
                primary_pt = pt
                pos += 1
                break

            if pos + 4 > len(payload):
                return None

            b1 = payload[pos + 1]
            b2 = payload[pos + 2]
            b3 = payload[pos + 3]

            timestamp_offset = (
                (b1 << 6)
                | (b2 >> 2)
            )

            length = (
                ((b2 & 0x03) << 8)
                | b3
            )

            headers.append(
                {
                    "pt": pt,
                    "offset": timestamp_offset,
                    "length": length,
                }
            )

            pos += 4

    except IndexError:
        return None

    data_pos = pos
    redundant = []

    for h in headers:

        end = data_pos + h["length"]

        if end > len(payload):
            return None

        redundant.append(
            (
                h["pt"],
                h["offset"],
                payload[data_pos:end],
            )
        )

        data_pos = end

    primary = payload[data_pos:]

    if not primary:
        return None

    return redundant, primary_pt, primary


def opus_decode_test(lib, decoder, payload):

    if not payload:
        return -999

    buf = (
        ctypes.c_ubyte * len(payload)
    ).from_buffer_copy(payload)

    pcm = (
        ctypes.c_int16 * 5760
    )()

    return lib.opus_decode(
        decoder,
        buf,
        len(payload),
        pcm,
        5760,
        0,
    )


def packets(pcap, ssrc, pt=99):

    cmd = [
        "tshark",
        "-n",
        "-r", pcap,

        "-Y",
        f"rtp.ssrc == {ssrc} && "
        f"rtp.p_type == {pt}",

        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",

        "-e", "frame.number",
        "-e", "rtp.seq",
        "-e", "rtp.timestamp",
        "-e", "rtp.payload",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        text=True,
    )

    for line in proc.stdout:

        p = line.rstrip().split("|")

        if len(p) != 4:
            continue

        try:
            yield (
                int(p[0]),
                int(p[1]),
                int(p[2]),
                bytes.fromhex(
                    p[3].replace(":", "")
                ),
            )
        except ValueError:
            continue


PCAP = "call_000001.pcap"
SSRC = "0x12345678"


opus = load_opus()

err = ctypes.c_int()

decoder = opus.opus_decoder_create(
    48000,
    1,
    ctypes.byref(err),
)


raw_ok = 0
raw_bad = 0

red_valid = 0
red_primary_opus_ok = 0
red_primary_opus_bad = 0

inner_pts = {}


for frame, seq, timestamp, payload in packets(
    PCAP,
    SSRC,
):

    #
    # Test complete RTP payload as Opus.
    #
    result = opus_decode_test(
        opus,
        decoder,
        payload,
    )

    if result >= 0:
        raw_ok += 1
    else:
        raw_bad += 1

    #
    # Now test RFC2198 interpretation.
    #
    red = parse_red(payload)

    if red is None:
        continue

    redundant, primary_pt, primary = red

    red_valid += 1

    inner_pts[primary_pt] = (
        inner_pts.get(primary_pt, 0) + 1
    )

    result = opus_decode_test(
        opus,
        decoder,
        primary,
    )

    if result >= 0:
        red_primary_opus_ok += 1
    else:
        red_primary_opus_bad += 1


opus.opus_decoder_destroy(decoder)


print()
print("=== Raw PT99 as Opus ===")

print("OK: ", raw_ok)
print("BAD:", raw_bad)


print()
print("=== PT99 interpreted as RFC2198 ===")

print("Structurally valid RED:", red_valid)

print(
    "Primary block Opus OK:",
    red_primary_opus_ok
)

print(
    "Primary block Opus BAD:",
    red_primary_opus_bad
)

print()
print("Primary inner PT distribution:")

for pt, count in sorted(
    inner_pts.items(),
    key=lambda x: -x[1]
):
    print(
        f"  PT {pt:3}: {count}"
    )
