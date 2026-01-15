#!/usr/bin/env python3

import sys

import p1ll


def main() -> int:
    sess = p1ll.Session.for_buffer(b"\x90\x90\xcc\x90")
    options = p1ll.ScanOptions()
    options.single = True
    results = sess.scan("90 90", options)

    if not results:
        print("no matches found")
        return 1

    print("before:", sess.buffer_bytes().hex())

    sig = p1ll.SignatureSpec()
    sig.pattern = "90 90"
    sig.options = options
    sig.required = True

    patch = p1ll.PatchSpec()
    patch.signature = sig
    patch.offset = 0
    patch.patch = "CC CC"
    patch.required = True

    recipe = p1ll.Recipe()
    recipe.name = "test"
    recipe.patches = [patch]

    plan = sess.plan(recipe)
    report = sess.apply(plan)

    print("after:", sess.buffer_bytes().hex())
    print(
        f"applied: {report.applied} failed: {report.failed} success: {report.success}"
    )

    if not report.success:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
