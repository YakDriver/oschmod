"""oschmod command line interface."""

from __future__ import annotations

import argparse
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
        description="Change the mode (permissions) of a file or directory",
    )
    parser.add_argument("-R", action="store_true", help="apply mode recursively")
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
        action="count",
        default=0,
        dest="verbose",
        help="verbose: show each object as its mode is set; "
        "repeat (-vv) to also show old and new modes",
    )
    parser.add_argument(
        "--other-sid",
        metavar="SID",
        default=None,
        help='Windows only: SID that receives "other" permissions '
        "(default: S-1-5-32-545, the built-in Users group)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {oschmod.__version__}")
    parser.add_argument("mode", help="octal or symbolic mode of the object")
    parser.add_argument("object", help="file or directory")
    return parser


def _format_mode(mode: int) -> str:
    return f"{mode:#05o} ({oschmod.mode_to_symbolic(mode)})"


def _apply(obj: Any, mode: str, verbose: int, other_sid: str | None) -> None:
    """Set mode on a single object, reporting according to verbosity."""
    old_mode = obj.get_full_mode() if verbose > 1 else 0
    obj.set_mode(mode, other_sid)
    if verbose > 1:
        new_mode = obj.get_full_mode()
        print(f"{obj.path}: {_format_mode(old_mode)} -> {_format_mode(new_mode)}")
    elif verbose:
        print(obj.path)


def main(argv: Sequence[str] | None = None) -> int:
    """Provide main function for CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    obj: str = args.object

    failed = False

    def report(path: str, exc: Exception) -> None:
        nonlocal failed
        failed = True
        print(f"oschmod: {path}: {getattr(exc, 'strerror', None) or exc}", file=sys.stderr)

    try:
        if args.R and args.links == "P" and oschmod._is_link(obj):
            return 0  # like GNU chmod -R -P: a symlink operand is neither followed nor changed
        if not os.path.exists(obj):
            raise FileNotFoundError(f"Path {obj} could not be found.")
        if args.R and os.path.isdir(obj):
            # Same traversal as oschmod.set_mode_recursive: contents first, root last.
            oschmod._walk_apply(
                obj,
                lambda o: _apply(o, args.mode, args.verbose, args.other_sid),
                follow_symlinks=args.links == "L",
                on_error=report,
            )
        else:
            _apply(
                oschmod._PathObj(obj, oschmod.get_object_type(obj)),
                args.mode,
                args.verbose,
                args.other_sid,
            )
    except _ERRORS as exc:
        print(f"oschmod: {exc}", file=sys.stderr)
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
