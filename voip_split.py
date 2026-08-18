#!/usr/bin/env python3
"""
voip_split.py

Split a PCAP containing many VoIP/RTP media sessions into:
  voip_calls/call_000001.pcap
  voip_calls/call_000002.pcap
  ...
  voip_calls/calls.csv
  voip_calls/streams.csv

Requirements:
  - tshark
  - scapy

Output PCAPs contain RTP packets only.
"""

import argparse
import csv
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

try:
    from scapy.utils import PcapReader, PcapWriter
except ImportError:
    sys.exit("Scapy is missing. Install it with: python3 -m pip install scapy")


STATIC_PT = {
    0: "PCMU/G711u",
    8: "PCMA/G711a",
    18: "G729",
}

RTPMAP_RE = re.compile(r"(?:a=)?rtpmap:(\d+)\s+([^/\s^]+)", re.I)


@dataclass
class Stream:
    sid: int
    src: str
    sport: int
    dst: str
    dport: int
    ssrc: str
    first: float
    last: float
    packets: int = 0
    pts: Counter = field(default_factory=Counter)

    @property
    def pair(self):
        return tuple(sorted(((self.src, self.sport), (self.dst, self.dport))))


@dataclass
class Call:
    number: int
    streams: List[Stream]
    filename: str = ""

    @property
    def first(self):
        return min(s.first for s in self.streams)

    @property
    def last(self):
        return max(s.last for s in self.streams)

    @property
    def packets(self):
        return sum(s.packets for s in self.streams)

    @property
    def pts(self):
        out = Counter()
        for s in self.streams:
            out.update(s.pts)
        return out


def run_tshark(cmd):
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        bufsize=1,
    )
    assert p.stdout is not None
    for line in p.stdout:
        yield line.rstrip("\n")

    stderr = p.stderr.read() if p.stderr else ""
    if p.wait():
        raise RuntimeError(stderr.strip() or "tshark failed")


def scan_sdp_payload_types(pcap):
    """Capture-wide dynamic PT -> codec mapping from SDP."""
    found = defaultdict(set)

    cmd = [
        "tshark", "-n", "-r", str(pcap),
        "-Y", "sdp",
        "-T", "fields",
        "-E", "occurrence=a",
        "-E", "aggregator=^",
        "-e", "sdp.media_attr",
    ]

    try:
        for line in run_tshark(cmd):
            for match in RTPMAP_RE.finditer(line):
                found[int(match.group(1))].add(match.group(2))
    except RuntimeError as e:
        print("WARNING: could not scan SDP:", e, file=sys.stderr)

    return found


def codec_name(pt, dynamic_map):
    if pt in STATIC_PT:
        return STATIC_PT[pt]

    names = dynamic_map.get(pt, set())
    if len(names) == 1:
        return "%s/PT%d" % (next(iter(names)), pt)
    if len(names) > 1:
        return "PT%d(dynamic:%s)" % (pt, "/".join(sorted(names)))
    return "PT%d(dynamic)" % pt


def discover_rtp(pcap, outdir, heuristic=True):
    """
    Ask tshark to identify RTP packets.

    Stream summaries stay in RAM. Frame -> stream membership is stored in
    a temporary TSV file, so large captures don't need a huge Python dict.
    """
    index_file = outdir / ".rtp_index.tsv"
    streams = []
    stream_ids = {}

    cmd = ["tshark", "-n", "-r", str(pcap)]
    if heuristic:
        cmd += ["-o", "rtp.heuristic_rtp:TRUE"]

    cmd += [
        "-Y", "rtp",
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=f",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "udp.srcport",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "udp.dstport",
        "-e", "rtp.ssrc",
        "-e", "rtp.p_type",
    ]

    with index_file.open("w") as index:
        for line in run_tshark(cmd):
            f = line.split("\t")
            f += [""] * (10 - len(f))

            frame_s, time_s, ip4s, ip6s, sport_s, ip4d, ip6d, dport_s, ssrc, pt_s = f[:10]
            src = ip4s or ip6s
            dst = ip4d or ip6d

            if not all((frame_s, time_s, src, sport_s, dst, dport_s, ssrc, pt_s)):
                continue

            try:
                frame_no = int(frame_s)
                ts = float(time_s)
                sport = int(sport_s)
                dport = int(dport_s)
                pt = int(pt_s)
            except ValueError:
                continue

            key = (src, sport, dst, dport, ssrc)
            sid = stream_ids.get(key)

            if sid is None:
                sid = len(streams)
                stream_ids[key] = sid
                streams.append(
                    Stream(sid, src, sport, dst, dport, ssrc, ts, ts)
                )

            s = streams[sid]
            s.last = ts
            s.packets += 1
            s.pts[pt] += 1
            index.write("%d\t%d\n" % (frame_no, sid))

    return streams, index_file


def group_calls(streams, reuse_gap):
    """
    Pair A->B and B->A RTP streams using the unordered IP:port pair.
    Reused port pairs are split after reuse_gap seconds.
    """
    by_pair = defaultdict(list)
    for s in streams:
        by_pair[s.pair].append(s)

    groups = []

    for items in by_pair.values():
        items.sort(key=lambda x: x.first)
        current = []
        current_last = 0.0

        for s in items:
            if not current:
                current = [s]
                current_last = s.last
            elif s.first <= current_last + reuse_gap:
                current.append(s)
                current_last = max(current_last, s.last)
            else:
                groups.append(current)
                current = [s]
                current_last = s.last

        if current:
            groups.append(current)

    groups.sort(key=lambda g: min(s.first for s in g))

    calls = []
    for number, group in enumerate(groups, 1):
        calls.append(
            Call(number, group, "call_%06d.pcap" % number)
        )
    return calls


class WriterCache:
    """Avoid opening hundreds/thousands of output files at once."""
    def __init__(self, outdir, calls, max_open=64):
        self.max_open = max_open
        self.open = OrderedDict()
        self.paths = {c.number: outdir / c.filename for c in calls}

        for p in self.paths.values():
            if p.exists():
                p.unlink()

    def get(self, number):
        if number in self.open:
            w = self.open.pop(number)
            self.open[number] = w
            return w

        if len(self.open) >= self.max_open:
            _, old = self.open.popitem(last=False)
            old.close()

        path = self.paths[number]
        w = PcapWriter(str(path), append=path.exists(), sync=False)
        self.open[number] = w
        return w

    def close(self):
        for w in self.open.values():
            w.close()
        self.open.clear()


def split_pcap(pcap, calls, index_file, outdir, max_open):
    stream_to_call = {}
    for call in calls:
        for s in call.streams:
            stream_to_call[s.sid] = call.number

    def read_idx(f):
        line = f.readline()
        if not line:
            return None
        a, b = line.rstrip("\n").split("\t")
        return int(a), int(b)

    writers = WriterCache(outdir, calls, max_open)
    idx = index_file.open("r")
    next_item = read_idx(idx)
    reader = PcapReader(str(pcap))

    try:
        for frame_no, packet in enumerate(reader, 1):
            while next_item and next_item[0] < frame_no:
                next_item = read_idx(idx)

            while next_item and next_item[0] == frame_no:
                _, sid = next_item
                writers.get(stream_to_call[sid]).write(packet)
                next_item = read_idx(idx)

            if next_item is None:
                break
    finally:
        reader.close()
        idx.close()
        writers.close()


def write_reports(outdir, calls, streams, dynamic_map):
    with (outdir / "calls.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "call", "start_epoch", "duration_seconds", "streams",
            "packets", "payload_types", "codecs", "pcap"
        ])
        for c in calls:
            pts = sorted(c.pts)
            w.writerow([
                c.number,
                "%.6f" % c.first,
                "%.3f" % (c.last - c.first),
                len(c.streams),
                c.packets,
                ",".join(map(str, pts)),
                ";".join(codec_name(pt, dynamic_map) for pt in pts),
                c.filename,
            ])

    with (outdir / "streams.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "stream", "src_ip", "src_port", "dst_ip", "dst_port",
            "ssrc", "packets", "duration_seconds", "payload_types", "codecs"
        ])
        for s in streams:
            pts = sorted(s.pts)
            w.writerow([
                s.sid, s.src, s.sport, s.dst, s.dport, s.ssrc,
                s.packets,
                "%.3f" % (s.last - s.first),
                ",".join(map(str, pts)),
                ";".join(codec_name(pt, dynamic_map) for pt in pts),
            ])


def main():
    ap = argparse.ArgumentParser(
        description="Split a multi-call VoIP PCAP into per-call RTP PCAPs."
    )
    ap.add_argument("pcap", type=Path)
    ap.add_argument("-o", "--outdir", type=Path, default=Path("voip_calls"))
    ap.add_argument(
        "--reuse-gap", type=float, default=300.0,
        help="Split reused RTP port pairs after this idle time (default: 300 sec)"
    )
    ap.add_argument(
        "--no-heuristic", action="store_true",
        help="Disable Wireshark heuristic RTP detection"
    )
    ap.add_argument(
        "--max-open", type=int, default=64,
        help="Maximum output PCAP files open at once"
    )
    args = ap.parse_args()

    if shutil.which("tshark") is None:
        sys.exit("ERROR: tshark is not installed or not in PATH")
    if not args.pcap.is_file():
        sys.exit("ERROR: PCAP not found: %s" % args.pcap)

    args.outdir.mkdir(parents=True, exist_ok=True)

    print("[1/4] Reading SDP dynamic payload mappings...")
    dynamic_map = scan_sdp_payload_types(args.pcap)

    print("[2/4] Detecting RTP streams...")
    try:
        streams, index_file = discover_rtp(
            args.pcap, args.outdir, not args.no_heuristic
        )
    except RuntimeError as e:
        if not args.no_heuristic and "rtp.heuristic_rtp" in str(e):
            print("Heuristic RTP option unavailable; retrying without it.")
            streams, index_file = discover_rtp(
                args.pcap, args.outdir, False
            )
        else:
            raise

    if not streams:
        sys.exit(
            "No RTP detected. Open the PCAP in Wireshark and check "
            "Telephony -> RTP -> RTP Streams, or use tshark -d to force UDP ports as RTP."
        )

    calls = group_calls(streams, args.reuse_gap)

    print("      RTP streams :", len(streams))
    print("      Calls/media :", len(calls))

    print("[3/4] Writing per-call RTP PCAPs...")
    split_pcap(args.pcap, calls, index_file, args.outdir, args.max_open)

    print("[4/4] Writing CSV reports...")
    write_reports(args.outdir, calls, streams, dynamic_map)

    try:
        index_file.unlink()
    except OSError:
        pass

    print("\nDone:", args.outdir)
    print("  calls.csv")
    print("  streams.csv")
    print("  %d call_*.pcap files" % len(calls))

    if dynamic_map:
        print("\nDynamic RTP mappings found in SDP:")
        for pt in sorted(dynamic_map):
            print("  PT %-3d -> %s" % (pt, ", ".join(sorted(dynamic_map[pt]))))


if __name__ == "__main__":
    main()
