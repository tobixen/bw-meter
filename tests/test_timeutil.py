"""Tests for bw_meter.timeutil.parse_dt."""

import datetime

import pytest

from bw_meter.timeutil import parse_dt


class TestIsoParsing:
    def test_iso_date(self):
        result = parse_dt("2026-03-21")
        assert result.date() == datetime.date(2026, 3, 21)
        assert result.tzinfo is not None

    def test_iso_datetime_T(self):
        result = parse_dt("2026-03-21T14:30")
        assert result.date() == datetime.date(2026, 3, 21)
        assert result.hour == 14
        assert result.minute == 30
        assert result.tzinfo is not None

    def test_iso_datetime_space(self):
        result = parse_dt("2026-03-21 14:30")
        assert result.date() == datetime.date(2026, 3, 21)
        assert result.hour == 14
        assert result.tzinfo is not None


class TestRelativeOffsets:
    def test_plus_hours(self):
        before = datetime.datetime.now().astimezone()
        result = parse_dt("+2h")
        after = datetime.datetime.now().astimezone()
        expected_low = before + datetime.timedelta(hours=2)
        expected_high = after + datetime.timedelta(hours=2)
        assert expected_low <= result <= expected_high

    def test_minus_days(self):
        before = datetime.datetime.now().astimezone()
        result = parse_dt("-1d")
        after = datetime.datetime.now().astimezone()
        expected_low = before - datetime.timedelta(days=1)
        expected_high = after - datetime.timedelta(days=1)
        assert expected_low <= result <= expected_high

    def test_plus_minutes(self):
        result = parse_dt("+30m")
        expected = datetime.datetime.now().astimezone() + datetime.timedelta(minutes=30)
        assert abs((result - expected).total_seconds()) < 2

    def test_plus_weeks(self):
        result = parse_dt("+1w")
        expected = datetime.datetime.now().astimezone() + datetime.timedelta(weeks=1)
        assert abs((result - expected).total_seconds()) < 2


class TestNaturalLanguage:
    def test_yesterday(self):
        result = parse_dt("yesterday")
        expected = (datetime.datetime.now().astimezone() - datetime.timedelta(days=1)).date()
        assert result.date() == expected
        assert result.tzinfo is not None

    def test_today(self):
        result = parse_dt("today")
        assert result.date() == datetime.datetime.now().astimezone().date()
        assert result.tzinfo is not None

    def test_hours_ago(self):
        result = parse_dt("3 hours ago")
        expected = datetime.datetime.now().astimezone() - datetime.timedelta(hours=3)
        assert abs((result - expected).total_seconds()) < 5


class TestErrors:
    def test_garbage_raises(self):
        with pytest.raises(ValueError, match="Cannot parse datetime"):
            parse_dt("not a date at all !!!!")

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="Cannot parse datetime"):
            parse_dt("")
