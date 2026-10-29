#!/usr/bin/env python3
"""Exercise collector behavior without opening a browser or capturing packets."""

from pathlib import Path
import logging
import sys
import threading
from unittest.mock import MagicMock, patch


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wikipedia_traffic_collector as collector  # noqa: E402

logging.disable(logging.CRITICAL)


def test_click_limit() -> None:
    driver = MagicMock()
    behavior = collector.Behavior(
        page_load_wait_s=(0.0, 0.0),
        read_time_s=(0.0, 0.0),
        scrolls_per_page=(0, 0),
        click_probability=1.0,
        max_clicks_per_page=3,
        idle_probability=0.0,
    )

    with (
        patch.object(collector, "build_driver", return_value=driver),
        patch.object(collector, "click_random_internal_link", return_value=True) as click,
        patch.object(collector.time, "sleep"),
    ):
        collector.simulate_wikipedia(1, behavior, headless=True, chromedriver_path=None)

    assert click.call_count == 3, "The configured click limit was not honored."
    driver.quit.assert_called_once()


def test_capture_error_propagation() -> None:
    stop_event = threading.Event()
    errors: list[Exception] = []

    with patch.object(collector, "sniff", side_effect=RuntimeError("capture failed")):
        collector.capture_packets(
            "test0",
            Path("unused.pcap"),
            "udp",
            stop_event,
            errors,
        )

    assert stop_event.is_set()
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)


if __name__ == "__main__":
    test_click_limit()
    test_capture_error_propagation()
    print("Wikipedia collector logic tests passed.")
