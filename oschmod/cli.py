"""oschmod command line interface."""

from __future__ import annotations

import argparse
import errno
import os
import sys
from collections.abc import Sequence
from typing import Any

import oschmod

# pywintypes.error derives from Exception, not OSError, so include it explicitly.
_ERRORS: tuple[type[Exception], ...] = (
    OSError,
    ValueError,
    OverflowError,
    AttributeError,
    TypeError,
)
if sys.platform == "win32":
    # pywin32 is a required dependency on Windows (import oschmod fails without it).
    from pywintypes import error as _pywinerror

    _ERRORS += (_pywinerror,)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oschmod",
        usage=(
            "%(prog)s [options] MODE FILE...\n       %(prog)s [options] --reference=RFILE FILE..."
        ),
        description="Change the mode (permissions) of files and directories",
    )
    parser.add_argument(
        "-R", "--recursive", dest="R", action="store_true", help="apply mode recursively"
    )
    links = parser.add_mutually_exclusive_group()
    links.add_argument(
        "-H",
        dest="links",
        action="store_const",
        const="H",
        help="with -R, follow the object if it is a symlink, but no links below it (default)",
    )
    links.add_argument(
        "-L",
        dest="links",
        action="store_const",
        const="L",
        help="with -R, follow every symlink (changes link targets, even outside the tree)",
    )
    links.add_argument(
        "-P",
        dest="links",
        action="store_const",
        const="P",
        help="with -R, follow no symlinks",
    )
    parser.set_defaults(links="H")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        dest="verbose",
        help="verbose: show each object as its mode is set; "
        "repeat (-vv) to also show old and new modes",
    )
    parser.add_argument(
        "-c",
        "--changes",
        action="store_true",
        help="like -vv, but report only objects whose mode changed (overrides -v)",
    )
    parser.add_argument(
        "-f",
        "--silent",
        "--quiet",
        dest="silent",
        action="store_true",
        help="don't print errors for individual objects (the exit status is still 1)",
    )
    parser.add_argument(
        "--reference",
        metavar="RFILE",
        help="use RFILE's mode instead of a MODE argument (symlinks are followed)",
    )
    parser.add_argument(
        "--other-sid",
        metavar="SID",
        default=None,
        help='Windows only: SID that receives "other" permissions '
        "(default: S-1-5-32-545, the built-in Users group)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {oschmod.__version__}")
    parser.add_argument(
        "operands",
        nargs="*",
        metavar="MODE FILE",
        help="MODE is octal (e.g., 640) or symbolic (e.g., u=rw,g=r,o=, or a+rX); "
        "FILE is one or more files or directories (MODE is omitted with --reference)",
    )
    return parser


def _format_mode(mode: int) -> str:
    return f"{mode:#05o} ({oschmod.mode_to_symbolic(mode)})"


def _apply(obj: Any, args: argparse.Namespace) -> None:
    """Set mode on a single object, reporting according to -v, -vv, or -c."""
    compare = args.changes or args.verbose > 1
    old_mode = obj.get_full_mode(args.other_sid) if compare else 0
    obj.set_mode(args.mode, args.other_sid)
    if compare:
        new_mode = obj.get_full_mode(args.other_sid)
        if not args.changes or new_mode != old_mode:
            print(f"{obj.path}: {_format_mode(old_mode)} -> {_format_mode(new_mode)}")
    elif args.verbose:
        print(obj.path)


def _parse(parser: argparse.ArgumentParser, argv: list[str]) -> argparse.Namespace:
    """Parse with options allowed after MODE or FILE (e.g., `oschmod 600 -v FILE`).

    That matches GNU chmod and earlier versions. Everything after the first
    `--` is an operand. It's split off here because Python 3.11's
    parse_intermixed_args drops operands when `--` comes before all of them.
    """
    if "--" in argv:
        split = argv.index("--")
        argv, extra = argv[:split], argv[split + 1 :]
    else:
        extra = []
    args, rest = parser.parse_known_intermixed_args(argv)
    unknown = [arg for arg in rest if arg.startswith("-") and arg != "-"]
    if unknown:
        parser.error(f"unrecognized arguments: {' '.join(unknown)}")
    args.operands = [*(args.operands or []), *rest, *extra]
    if not args.operands:
        parser.error("a MODE and at least one FILE are required")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Provide main function for CLI."""
    parser = _build_parser()
    args = _parse(parser, sys.argv[1:] if argv is None else list(argv))

    if args.reference is None:
        if len(args.operands) < 2:
            parser.error("a MODE and at least one FILE are required")
        args.mode, *args.object = args.operands
    else:
        args.object = args.operands
        try:
            # Copy the full mode, including set-ID and sticky bits, like GNU chmod.
            args.mode = oschmod.get_full_mode(args.reference, args.other_sid)
        except _ERRORS as exc:
            print(f"oschmod: {args.reference}: {_reason(exc)}", file=sys.stderr)
            return 1

    try:
        # Check the mode once, before changing anything (it would fail for every object).
        oschmod._resolve_mode_with(args.mode, lambda: 0, lambda: False)
    except _ERRORS as exc:
        print(f"oschmod: {exc}", file=sys.stderr)
        return 1

    failed = False

    def report(path: str, exc: Exception) -> None:
        nonlocal failed
        failed = True
        if not args.silent:
            print(f"oschmod: {path}: {_reason(exc)}", file=sys.stderr)

    for obj in args.object:
        try:
            _process(obj, args, report)
        except _ERRORS as exc:
            report(obj, exc)
    return 1 if failed else 0


def _reason(exc: Exception) -> str:
    return getattr(exc, "strerror", None) or str(exc)


def _process(obj: str, args: argparse.Namespace, report: oschmod.ErrorHandler) -> None:
    """Apply the mode to one command-line object, recursively with -R."""
    if args.R and args.links == "P" and oschmod._is_link(obj):
        return  # like GNU chmod -R -P: a symlink operand is neither followed nor changed
    if not os.path.exists(obj):
        raise FileNotFoundError(errno.ENOENT, "No such file or directory", obj)
    if args.R and os.path.isdir(obj):
        # Same traversal as oschmod.set_mode_recursive: contents first, root last.
        oschmod._walk_apply(
            obj,
            lambda o: _apply(o, args),
            follow_symlinks=args.links == "L",
            on_error=report,
        )
    else:
        _apply(oschmod._PathObj(obj, oschmod.get_object_type(obj)), args)


if __name__ == "__main__":
    sys.exit(main())
