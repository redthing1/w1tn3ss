#!/usr/bin/env python3

import argparse
import sys
from typing import Tuple

import p1ll


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a file, buffer, or current process using p1ll patterns"
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="path to a binary/file to scan")
    source.add_argument("--data-hex", help="hex bytes to scan (e.g. '90 90 cc 90')")
    source.add_argument("--data-text", help="raw text to scan (utf-8)")
    source.add_argument(
        "--process", action="store_true", help="scan the current process"
    )

    pattern = parser.add_mutually_exclusive_group(required=True)
    pattern.add_argument("--pattern", help="hex signature pattern")
    pattern.add_argument("--pattern-text", help="ASCII text to convert to hex pattern")

    parser.add_argument("--single", dest="single", action="store_true")
    parser.add_argument("--no-single", dest="single", action="store_false")
    parser.set_defaults(single=False)

    parser.add_argument("--max-matches", type=int, default=0)

    parser.add_argument("--name-regex", default="")
    parser.add_argument("--only-executable", action="store_true")
    parser.add_argument("--exclude-system", action="store_true")
    parser.add_argument("--min-size", type=int, default=0)
    parser.add_argument("--min-address", type=lambda v: int(v, 0))
    parser.add_argument("--max-address", type=lambda v: int(v, 0))

    parser.add_argument(
        "--platform", help="platform override for buffer sessions (e.g. linux:x64)"
    )

    return parser.parse_args()


def build_pattern(args: argparse.Namespace) -> str:
    if args.pattern_text:
        return p1ll.utils.str2hex(args.pattern_text)
    return args.pattern


def decode_hex_data(value: str) -> bytes:
    normalized = p1ll.utils.normalize_hex_pattern(value)
    if "?" in normalized:
        raise ValueError("data hex cannot include wildcards ('??')")
    if not normalized:
        raise ValueError("data hex is empty")
    return bytes.fromhex(normalized)


def load_data(args: argparse.Namespace) -> Tuple[p1ll.Session, str]:
    if args.process:
        if args.platform:
            raise ValueError("--platform is only valid for buffer sessions")
        return p1ll.Session.for_process(), "process"

    if args.input:
        data = p1ll.utils.read_file(args.input)
        if data is None:
            raise ValueError("failed to read file: {}".format(args.input))
        label = args.input
    elif args.data_hex:
        data = decode_hex_data(args.data_hex)
        label = "hex-buffer"
    else:
        data = args.data_text.encode("utf-8")
        label = "text-buffer"

    if args.platform:
        return p1ll.Session.for_buffer(data, args.platform), label
    return p1ll.Session.for_buffer(data), label


def main() -> int:
    try:
        args = parse_args()
        sess, label = load_data(args)
    except ValueError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    options = p1ll.ScanOptions()
    options.single = args.single
    options.max_matches = args.max_matches

    scan_filter = p1ll.ScanFilter()
    scan_filter.name_regex = args.name_regex
    scan_filter.only_executable = args.only_executable
    scan_filter.exclude_system = args.exclude_system
    scan_filter.min_size = args.min_size
    if args.min_address is not None:
        scan_filter.min_address = args.min_address
    if args.max_address is not None:
        scan_filter.max_address = args.max_address
    options.filter = scan_filter

    pattern = build_pattern(args)
    results = sess.scan(pattern, options)

    print("source: {}".format(label))
    print("matches: {}".format(len(results)))
    for idx, result in enumerate(results):
        addr = p1ll.utils.format_address(result.address)
        name = result.region_name or "[anonymous]"
        print("{}: addr={} region={}".format(idx, addr, name))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
