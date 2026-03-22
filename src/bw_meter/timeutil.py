"""Flexible date/time parsing for bw-meter CLI arguments."""

import datetime
import re

import dateparser

_RELATIVE_RE = re.compile(r"^([+-])(\d+(?:\.\d+)?)([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
# Matches strings that explicitly specify a time-of-day (HH:MM, am/pm, "ago", or time units).
_HAS_TIME_RE = re.compile(r"\d:\d|[aApP][mM]\b|\bago\b|\b(?:hour|minute|second)s?\b", re.IGNORECASE)


def parse_dt(s: str) -> datetime.datetime:
    """Parse a flexible date/time string into a timezone-aware datetime.

    Accepted formats:
    - ISO 8601: ``2026-03-21``, ``2026-03-21T14:00``, ``2026-03-21 14:00``
    - Natural language (via dateparser): ``yesterday``, ``Friday``, ``3 hours ago``
    - Relative offsets: ``+2h``, ``-1d``, ``+30m``, ``+1w``

    Returns a timezone-aware datetime (local timezone when none is specified).
    Raises ValueError if the string cannot be parsed.
    """
    m = _RELATIVE_RE.match(s.strip())
    if m:
        sign = 1 if m.group(1) == "+" else -1
        amount = float(m.group(2))
        unit = m.group(3)
        delta = datetime.timedelta(seconds=sign * amount * _UNITS[unit])
        return datetime.datetime.now().astimezone() + delta

    settings: dict = {
        "RETURN_AS_TIMEZONE_AWARE": True,
        "PREFER_DATES_FROM": "current_period",
    }
    result = dateparser.parse(s, settings=settings)
    if result is None:
        raise ValueError(f"Cannot parse datetime: {s!r}")
    # Day-level inputs (e.g. "today", "yesterday", "Friday") should resolve to
    # midnight, not the current clock time that dateparser injects by default.
    if not _HAS_TIME_RE.search(s):
        result = result.replace(hour=0, minute=0, second=0, microsecond=0)
    return result
