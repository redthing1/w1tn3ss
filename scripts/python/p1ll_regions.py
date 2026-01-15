#!/usr/bin/env python3

import argparse

import p1ll


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List regions from the current process using p1ll"
    )
    parser.add_argument("--name-regex", default="")
    parser.add_argument("--only-executable", action="store_true")
    parser.add_argument("--exclude-system", action="store_true")
    parser.add_argument("--min-size", type=int, default=0)
    parser.add_argument("--min-address", type=lambda v: int(v, 0))
    parser.add_argument("--max-address", type=lambda v: int(v, 0))
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--all", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sess = p1ll.Session.for_process()

    scan_filter = p1ll.ScanFilter()
    scan_filter.name_regex = args.name_regex
    scan_filter.only_executable = args.only_executable
    scan_filter.exclude_system = args.exclude_system
    scan_filter.min_size = args.min_size
    if args.min_address is not None:
        scan_filter.min_address = args.min_address
    if args.max_address is not None:
        scan_filter.max_address = args.max_address

    regions = sess.regions(scan_filter)
    print("regions:", len(regions))

    limit = None if args.all else args.limit
    for idx, region in enumerate(regions):
        if limit is not None and idx >= limit:
            break
        base = p1ll.utils.format_address(region.base_address)
        name = region.name or "[anonymous]"
        print(
            "{}: base={} size={} perms={} name={}".format(
                idx, base, region.size, region.protection, name
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
