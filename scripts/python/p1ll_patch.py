#!/usr/bin/env python3

import argparse
import sys
from typing import Optional, Tuple

import p1ll


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Patch a file or buffer using p1ll signatures"
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="path to binary/file to patch")
    source.add_argument("--data-hex", help="hex bytes to patch (e.g. '90 90 cc 90')")
    source.add_argument("--data-text", help="raw text to patch (utf-8)")

    dest = parser.add_mutually_exclusive_group()
    dest.add_argument("--output", help="output path for patched file")
    dest.add_argument("--inplace", action="store_true", help="overwrite input file")

    pattern = parser.add_mutually_exclusive_group(required=True)
    pattern.add_argument("--pattern", help="hex signature pattern")
    pattern.add_argument("--pattern-text", help="ASCII text to convert to hex pattern")

    patch = parser.add_mutually_exclusive_group(required=True)
    patch.add_argument("--patch", help="hex patch bytes")
    patch.add_argument("--patch-text", help="ASCII text to convert to hex patch")

    parser.add_argument("--offset", type=int, default=0)

    parser.add_argument("--single", dest="single", action="store_true")
    parser.add_argument("--no-single", dest="single", action="store_false")
    parser.set_defaults(single=True)

    parser.add_argument("--max-matches", type=int, default=0)

    parser.add_argument(
        "--validate", action="append", default=[], help="hex validation pattern"
    )
    parser.add_argument(
        "--validate-text", action="append", default=[], help="text validation pattern"
    )

    parser.add_argument(
        "--platform", help="platform override for buffer sessions (e.g. linux:x64)"
    )
    parser.add_argument("--recipe-name", default="python-patch")

    parser.add_argument("--verify", dest="verify", action="store_true")
    parser.add_argument("--no-verify", dest="verify", action="store_false")
    parser.set_defaults(verify=True)

    parser.add_argument("--flush-icache", dest="flush_icache", action="store_true")
    parser.add_argument("--no-flush-icache", dest="flush_icache", action="store_false")
    parser.set_defaults(flush_icache=True)

    parser.add_argument("--rollback", dest="rollback", action="store_true")
    parser.add_argument("--no-rollback", dest="rollback", action="store_false")
    parser.set_defaults(rollback=True)

    parser.add_argument("--allow-wx", action="store_true")

    parser.add_argument("--show-bytes", action="store_true")
    parser.add_argument("--show-max", type=int, default=64)

    return parser.parse_args()


def decode_hex_data(value: str) -> bytes:
    normalized = p1ll.utils.normalize_hex_pattern(value)
    if "?" in normalized:
        raise ValueError("data hex cannot include wildcards ('??')")
    if not normalized:
        raise ValueError("data hex is empty")
    return bytes.fromhex(normalized)


def load_data(args: argparse.Namespace) -> Tuple[p1ll.Session, bytes, str]:
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
        return p1ll.Session.for_buffer(data, args.platform), data, label
    return p1ll.Session.for_buffer(data), data, label


def build_pattern(hex_value: Optional[str], text_value: Optional[str]) -> str:
    if text_value is not None:
        return p1ll.utils.str2hex(text_value)
    return hex_value or ""


def add_validations(recipe: p1ll.Recipe, args: argparse.Namespace) -> None:
    patterns = []
    patterns.extend(args.validate)
    patterns.extend(p1ll.utils.str2hex(text) for text in args.validate_text)

    for pattern in patterns:
        sig = p1ll.SignatureSpec()
        sig.pattern = pattern
        sig.options = p1ll.ScanOptions()
        sig.options.single = args.single
        sig.options.max_matches = args.max_matches
        sig.required = True
        recipe.validations.append(sig)


def summarize_bytes(data: bytes, max_bytes: int) -> str:
    if len(data) <= max_bytes:
        return data.hex()
    prefix = data[:max_bytes].hex()
    return "{}...(+{} bytes)".format(prefix, len(data) - max_bytes)


def main() -> int:
    try:
        args = parse_args()

        if args.inplace and not args.input:
            raise ValueError("--inplace is only valid with --input")
        if args.output and not args.input:
            raise ValueError("--output is only valid with --input")
        if args.input and not (args.output or args.inplace):
            raise ValueError("--output or --inplace is required when using --input")

        sess, original_data, label = load_data(args)
    except ValueError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    recipe = p1ll.Recipe()
    recipe.name = args.recipe_name

    sig = p1ll.SignatureSpec()
    sig.pattern = build_pattern(args.pattern, args.pattern_text)
    sig.options = p1ll.ScanOptions()
    sig.options.single = args.single
    sig.options.max_matches = args.max_matches
    sig.required = True

    patch = p1ll.PatchSpec()
    patch.signature = sig
    patch.offset = args.offset
    patch.patch = build_pattern(args.patch, args.patch_text)
    patch.required = True

    recipe.patches = [patch]
    add_validations(recipe, args)

    apply_options = p1ll.ApplyOptions()
    apply_options.verify = args.verify
    apply_options.flush_icache = args.flush_icache
    apply_options.rollback_on_failure = args.rollback
    apply_options.allow_wx = args.allow_wx

    if args.show_bytes:
        print("before:", summarize_bytes(original_data, args.show_max))

    plan = sess.plan(recipe)
    report = sess.apply(plan, apply_options)

    if args.show_bytes:
        print("after:", summarize_bytes(sess.buffer_bytes(), args.show_max))

    if args.input:
        output_path = args.output if args.output else args.input
        if not p1ll.utils.write_file(output_path, sess.buffer_bytes()):
            print(
                "error: failed to write file: {}".format(output_path), file=sys.stderr
            )
            return 1
        print("output: {}".format(output_path))

    print(
        "source: {} applied: {} failed: {} success: {}".format(
            label, report.applied, report.failed, report.success
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
