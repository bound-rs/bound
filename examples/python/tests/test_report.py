import io
from decimal import Decimal
from pathlib import Path

import pytest

from report.cli import builtin_template, main, render
from report.table import Table, parse_number

SAMPLE = Path(__file__).parent.parent / "samples" / "sales.csv"


def test_numeric_columns_are_totalled() -> None:
    with open(SAMPLE, encoding="utf-8", newline="") as source:
        table = Table.read(source)
    assert table.columns == ["region", "product", "units", "revenue"]
    assert len(table.rows) == 4
    assert table.totals == {"units": Decimal("255"), "revenue": Decimal("5450.49")}
    assert table.total("region") == ""


def test_numbers() -> None:
    assert parse_number(" 1,200.50 ") == Decimal("1200.50")
    assert parse_number("abc") is None
    assert parse_number("NaN") is None


def test_ragged_rows_are_rejected() -> None:
    with pytest.raises(ValueError, match="line 3: expected 2 fields, found 1"):
        Table.read(io.StringIO("a,b\n1,2\n3\n"))


def test_values_are_escaped() -> None:
    table = Table.read(io.StringIO("name,count\n<b>&,2\n"))
    html = render(table, "Q3 <sales>", builtin_template())
    assert "<title>Q3 &lt;sales&gt;</title>" in html
    assert "&lt;b&gt;&amp;" in html
    assert ">2</td>" in html


def test_the_command_writes_a_file(tmp_path: Path) -> None:
    out = tmp_path / "report.html"
    assert main([str(SAMPLE), "--title", "Sales", "-o", str(out)]) == 0
    html = out.read_text(encoding="utf-8")
    assert "<h1>Sales</h1>" in html
    assert "5450.49" in html


def test_missing_files_are_reported(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["no-such-file.csv"]) == 1
    assert "report:" in capsys.readouterr().err
