"""oschmod command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

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


def _apply(path: str, mode: str, verbose: int, other_sid: str | None) -> None:
    """Set mode on a single object, reporting according to verbosity."""
    old_mode = oschmod.get_full_mode(path) if verbose > 1 else 0
    oschmod.set_mode(path, mode, other_sid)
    if verbose > 1:
        new_mode = oschmod.get_full_mode(path)
        print(f"{path}: {_format_mode(old_mode)} -> {_format_mode(new_mode)}")
    elif verbose:
        print(path)


def main(argv: Sequence[str] | None = None) -> int:
    """Provide main function for CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    obj: str = args.object

    try:
        if not os.path.exists(obj):
            raise FileNotFoundError(f"Path {obj} could not be found.")
        if args.R and oschmod.get_object_type(obj) == oschmod.DIRECTORY:
            # Same traversal order as oschmod.set_mode_recursive (bottom-up, root last).
            for path, _ in oschmod._iter_tree(obj):
                _apply(path, args.mode, args.verbose, args.other_sid)
        else:
            _apply(obj, args.mode, args.verbose, args.other_sid)
    except _ERRORS as exc:
        print(f"oschmod: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
