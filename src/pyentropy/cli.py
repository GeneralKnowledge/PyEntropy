"""Command-line interface for PyEntropy.

Educational RNG — not a production CSPRNG.

Examples::

    python -m pyentropy 32
    python -m pyentropy --hex 32
    python -m pyentropy --base64 32
    python -m pyentropy --integer 1 100
    python -m pyentropy --status
"""

from __future__ import annotations

import argparse
import sys

from pyentropy.diagnostics import format_status
from pyentropy.encoding import to_base64, to_hex
from pyentropy.exceptions import PyEntropyError
from pyentropy.rng import RNG


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyentropy",
        description=(
            "PyEntropy — educational userspace RNG. "
            "NOT a replacement for /dev/urandom or secrets."
        ),
    )
    parser.add_argument(
        "nbytes",
        nargs="?",
        type=int,
        default=None,
        help="number of random bytes to emit (raw by default)",
    )
    parser.add_argument(
        "--hex",
        dest="as_hex",
        metavar="N",
        type=int,
        default=None,
        help="emit N bytes as hexadecimal",
    )
    parser.add_argument(
        "--base64",
        dest="as_base64",
        metavar="N",
        type=int,
        default=None,
        help="emit N bytes as Base64",
    )
    parser.add_argument(
        "--integer",
        nargs=2,
        metavar=("MIN", "MAX"),
        type=int,
        default=None,
        help="emit one uniform integer in [MIN, MAX]",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="print generator diagnostics (never includes secret state)",
    )
    parser.add_argument(
        "--reseed",
        action="store_true",
        help="force an explicit reseed before producing output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    modes = [
        args.nbytes is not None,
        args.as_hex is not None,
        args.as_base64 is not None,
        args.integer is not None,
        args.status,
    ]
    if sum(1 for m in modes if m) == 0 and not args.reseed:
        parser.print_help()
        return 2

    try:
        rng = RNG()
        if args.reseed:
            rng.reseed()

        if args.status:
            print(format_status(rng.status()))
            return 0

        if args.integer is not None:
            lo, hi = args.integer
            print(rng.integer(lo, hi))
            return 0

        if args.as_hex is not None:
            print(to_hex(rng.bytes(args.as_hex)))
            return 0

        if args.as_base64 is not None:
            print(to_base64(rng.bytes(args.as_base64)))
            return 0

        if args.nbytes is not None:
            data = rng.bytes(args.nbytes)
            # Raw bytes to stdout buffer.
            sys.stdout.buffer.write(data)
            if sys.stdout.isatty():
                sys.stdout.buffer.write(b"\n")
            return 0

        return 0
    except PyEntropyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
