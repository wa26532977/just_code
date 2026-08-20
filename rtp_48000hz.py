#!/usr/bin/env python3

import argparse
import ctypes
import ctypes.util
import subprocess
import wave


OPUS_OK = 0


def load_opus():
    name = ctypes.util.find_library("opus")

    if not name:
        name = "libopus.so.0"

    lib = ctypes.CDLL(name)

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


def read_packets(pcap, ssrc, pt):
    cmd = [
        "tshark",
        "-n",
        "-r", pcap,

        "-Y",
        f"rtp.ssrc == {ssrc} && rtp.p_type == {pt}",

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
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )

    for line in proc.stdout:
        p = line.strip().split("|")

        if len(p) != 4:
            continue

        frame, seq, timestamp, payload_hex = p

        if not payload_hex:
            continue

        try:
            payload = bytes.fromhex(
                payload_hex.replace(":", "")
            )

            yield {
                "frame": int(frame),
                "seq": int(seq),
                "timestamp": int(timestamp),
                "payload": payload,
            }

        except ValueError:
            continue

    stderr = proc.stderr.read()

    if proc.wait() != 0:
        raise RuntimeError(stderr)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("pcap")

    parser.add_argument(
        "--ssrc",
        required=True,
        help="example: 0x12345678"
    )

    parser.add_argument(
        "--pt",
        type=int,
        default=99,
    )

    parser.add_argument(
        "-o",
        "--output",
        default="pt99-opus.wav",
    )

    args = parser.parse_args()

    opus = load_opus()

    error = ctypes.c_int()

    # Decode to mono at 48 kHz.
    #
    # Opus can downmix a stereo packet to mono.
    decoder = opus.opus_decoder_create(
        48000,
        1,
        ctypes.byref(error),
    )

    if not decoder or error.value != OPUS_OK:
        raise RuntimeError(
            f"opus_decoder_create failed: {error.value}"
        )

    # Maximum Opus packet duration = 120 ms.
    #
    # 48000 * 0.120 = 5760 samples
    max_samples = 5760

    pcm = (
        ctypes.c_int16 * max_samples
    )()

    good = 0
    bad = 0
    duplicate = 0
    packet_count = 0

    seen = set()

    previous_timestamp = None

    with wave.open(args.output, "wb") as wav:

        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(48000)

        try:

            for packet in read_packets(
                args.pcap,
                args.ssrc,
                args.pt,
            ):

                packet_count += 1

                key = (
                    packet["seq"],
                    packet["timestamp"],
                )

                # Important for merged captures.
                if key in seen:
                    duplicate += 1
                    continue

                seen.add(key)

                payload = packet["payload"]

                buf = (
                    ctypes.c_ubyte * len(payload)
                ).from_buffer_copy(payload)

                samples = opus.opus_decode(
                    decoder,
                    buf,
                    len(payload),
                    pcm,
                    max_samples,
                    0,
                )

                if samples < 0:
                    bad += 1

                    if bad <= 20:
                        print(
                            f"BAD "
                            f"frame={packet['frame']} "
                            f"seq={packet['seq']} "
                            f"ts={packet['timestamp']} "
                            f"len={len(payload)} "
                            f"opus_error={samples}"
                        )

                    continue

                good += 1

                if previous_timestamp is not None:

                    delta = (
                        packet["timestamp"]
                        - previous_timestamp
                    ) & 0xffffffff

                    if good <= 30:
                        print(
                            f"OK  "
                            f"seq={packet['seq']} "
                            f"ts={packet['timestamp']} "
                            f"dts={delta} "
                            f"bytes={len(payload)} "
                            f"decoded_samples={samples}"
                        )

                previous_timestamp = packet["timestamp"]

                raw_pcm = ctypes.string_at(
                    ctypes.addressof(pcm),
                    samples * 2,
                )

                wav.writeframes(raw_pcm)

        finally:
            opus.opus_decoder_destroy(
                decoder
            )

    print()
    print("Packets:", packet_count)
    print("Decoded OK:", good)
    print("Decode errors:", bad)
    print("Duplicates skipped:", duplicate)
    print("WAV:", args.output)

    if good + bad:
        print(
            "Success rate:",
            f"{100 * good / (good + bad):.1f}%"
        )


if __name__ == "__main__":
    main()
