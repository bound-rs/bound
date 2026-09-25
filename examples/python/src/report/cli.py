"""The `report` command line."""

from __future__ import annotations

import argparse
import io
import sys
from importlib import resources
from pathlib import Path

from jinja2 import Environment

from report.table import Table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="report", description="Render a CSV file as an HTML report.")
    parser.add_argument("csv", help="the CSV file to render, or - for standard input")
    parser.add_argument("--title", default="Report", help="the report's title (default: %(default)s)")
    parser.add_argument("--template", type=Path, help="a Jinja2 template to use instead of the built-in one")
    parser.add_argument("-o", "--output", type=Path, help="write the report to this file instead of standard output")
    return parser


def render(table: Table, title: str, template: str) -> str:
    """Renders `table` with a Jinja2 template, escaping every value."""
    environment = Environment(autoescape=True, keep_trailing_newline=True)
    return environment.from_string(template).render(title=title, table=table)


def builtin_template() -> str:
    return (resources.files("report") / "templates" / "report.html.j2").read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.csv == "-":
            table = Table.read(io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8-sig", newline=""))
        else:
            with open(args.csv, encoding="utf-8-sig", newline="") as source:
                table = Table.read(source)
        template = args.template.read_text(encoding="utf-8") if args.template else builtin_template()
    except (OSError, ValueError) as error:
        print(f"report: {error}", file=sys.stderr)
        return 1

    html = render(table, args.title, template)
    if args.output:
        args.output.write_text(html, encoding="utf-8")
    else:
        # HTML is UTF-8 whatever the console's code page.
        sys.stdout.buffer.write(html.encode("utf-8"))
        sys.stdout.flush()
    return 0
