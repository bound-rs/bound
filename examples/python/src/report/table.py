"""Reading a CSV file and totalling its numeric columns."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import TextIO


@dataclass(frozen=True)
class Table:
    """A CSV file: its header, its rows, and the totals of its numeric columns."""

    columns: list[str]
    rows: list[list[str]]
    totals: dict[str, Decimal]

    @classmethod
    def read(cls, source: TextIO) -> Table:
        """Reads a CSV file whose first line names the columns."""
        reader = csv.reader(source)
        columns = next(reader, None)
        if not columns:
            raise ValueError("the CSV file has no header line")
        rows = [row for row in reader if row]
        for line, row in enumerate(rows, start=2):
            if len(row) != len(columns):
                raise ValueError(f"line {line}: expected {len(columns)} fields, found {len(row)}")

        totals: dict[str, Decimal] = {}
        for index, column in enumerate(columns):
            numbers = [number for row in rows if (number := parse_number(row[index])) is not None]
            if rows and len(numbers) == len(rows):
                totals[column] = sum(numbers, Decimal(0))
        return cls(columns, rows, totals)

    def total(self, column: str) -> str:
        """The total of a column, or an empty string if it is not numeric."""
        value = self.totals.get(column)
        return "" if value is None else str(value)


def parse_number(text: str) -> Decimal | None:
    """A decimal number, or None if the text is not one."""
    try:
        value = Decimal(text.strip().replace(",", ""))
    except InvalidOperation:
        return None
    return value if value.is_finite() else None
