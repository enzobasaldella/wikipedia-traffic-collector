#!/usr/bin/env python3
"""Capture VPN traffic while Selenium browses random Wikipedia articles."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
import logging
import os
from pathlib import Path
import random
import threading
import time

from scapy.all import sniff, wrpcap
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("wikipedia_traffic_collector")


@dataclass(frozen=True)
class Behavior:
    """Timing and navigation parameters for one browsing session."""

    page_load_wait_s: tuple[float, float] = (2.5, 5.5)
    read_time_s: tuple[float, float] = (2.0, 6.0)
    scrolls_per_page: tuple[int, int] = (2, 4)
    scroll_px: tuple[int, int] = (400, 900)
    scroll_pause_s: tuple[float, float] = (1.5, 3.0)
    click_probability: float = 0.25
    max_clicks_per_page: int = 1
    idle_probability: float = 0.15
    idle_time_s: tuple[float, float] = (2.0, 6.0)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def probability(value: str) -> float:
    parsed = float(value)
    if not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be between 0.0 and 1.0")
    return parsed


def random_float(bounds: tuple[float, float]) -> float:
    return random.uniform(*bounds)


def random_int(bounds: tuple[int, int]) -> int:
    return random.randint(*bounds)


def build_driver(headless: bool, chromedriver_path: str | None) -> webdriver.Chrome:
    """Create the Chrome WebDriver used for the browsing workload."""

    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    service = Service(chromedriver_path) if chromedriver_path else Service()
    return webdriver.Chrome(service=service, options=options)


def capture_packets(
    interface: str,
    filename: Path,
    bpf_filter: str,
    stop_event: threading.Event,
    errors: list[Exception],
    poll_timeout_s: float = 1.0,
) -> None:
    """Capture packets until signaled and report failures to the main thread."""

    logger.info("Starting capture on interface=%s | filter='%s'", interface, bpf_filter)
    captured_packets: list = []

    try:
        # Repeated timeouts allow the thread to stop even when no packets arrive.
        while not stop_event.is_set():
            packets = sniff(iface=interface, filter=bpf_filter, timeout=poll_timeout_s)
            captured_packets.extend(packets)

        wrpcap(str(filename), captured_packets)
        logger.info(
            "Capture finished. Saved %d packets to %s",
            len(captured_packets),
            filename,
        )
    except Exception as error:  # Scapy exposes several backend-specific errors.
        errors.append(error)
        stop_event.set()
        logger.exception("Packet capture failed: %s", error)


def maybe_idle(behavior: Behavior) -> None:
    if random.random() < behavior.idle_probability:
        duration = random_float(behavior.idle_time_s)
        logger.info("  Idle for %.2f seconds", duration)
        time.sleep(duration)


def click_random_internal_link(driver: webdriver.Chrome, max_attempts: int = 2) -> bool:
    """Click one visible internal article link when available."""

    for _ in range(max_attempts):
        try:
            links = driver.find_elements(By.CSS_SELECTOR, "a[href^='/wiki/']")
            visible_links = [link for link in links if link.is_displayed()]
            if not visible_links:
                return False
            random.choice(visible_links).click()
            return True
        except WebDriverException:
            continue
    return False


def simulate_wikipedia(
    pages: int,
    behavior: Behavior,
    headless: bool,
    chromedriver_path: str | None,
) -> None:
    """Generate the configured Wikipedia browsing workload."""

    random_article_url = "https://pt.wikipedia.org/wiki/Especial:Aleatória"
    driver = build_driver(headless, chromedriver_path)

    try:
        for page_index in range(pages):
            logger.info("Page %d/%d: opening a random article", page_index + 1, pages)
            driver.get(random_article_url)
            time.sleep(random_float(behavior.page_load_wait_s))
            maybe_idle(behavior)

            for click_index in range(behavior.max_clicks_per_page):
                if random.random() >= behavior.click_probability:
                    break
                if not click_random_internal_link(driver):
                    logger.info("  No clickable internal link was found")
                    break
                logger.info(
                    "  Clicked an internal link (%d/%d)",
                    click_index + 1,
                    behavior.max_clicks_per_page,
                )
                time.sleep(random_float(behavior.page_load_wait_s))
                maybe_idle(behavior)

            read_duration = random_float(behavior.read_time_s)
            logger.info("  Reading for %.2f seconds", read_duration)
            time.sleep(read_duration)

            scroll_count = random_int(behavior.scrolls_per_page)
            for scroll_index in range(scroll_count):
                distance = random_int(behavior.scroll_px)
                logger.info(
                    "  Scroll %d/%d: down %d pixels",
                    scroll_index + 1,
                    scroll_count,
                    distance,
                )
                driver.execute_script("window.scrollBy(0, arguments[0]);", distance)
                time.sleep(random_float(behavior.scroll_pause_s))
                maybe_idle(behavior)
    finally:
        driver.quit()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture VPN traffic while browsing random Wikipedia articles."
    )
    parser.add_argument("-i", "--interface", default="enp0s8", help="Network interface to capture")
    parser.add_argument("--filter", default="udp port 1194", help="BPF capture filter")
    parser.add_argument("-c", "--cycles", type=positive_int, default=1, help="Capture cycles")
    parser.add_argument("-p", "--pages", type=positive_int, default=10, help="Pages per cycle")
    parser.add_argument("--outdir", default="captures", help="PCAP output directory")
    parser.add_argument("--prefix", default="wiki_traffic", help="PCAP filename prefix")
    parser.add_argument("--headless", action="store_true", help="Run Chrome without a visible window")
    parser.add_argument("--chromedriver-path", help="Path to a ChromeDriver executable")
    parser.add_argument("--read-min", type=float, default=2.0, help="Minimum reading time in seconds")
    parser.add_argument("--read-max", type=float, default=6.0, help="Maximum reading time in seconds")
    parser.add_argument("--scrolls-min", type=nonnegative_int, default=2, help="Minimum scrolls per page")
    parser.add_argument("--scrolls-max", type=nonnegative_int, default=4, help="Maximum scrolls per page")
    parser.add_argument("--scroll-px-min", type=nonnegative_int, default=400, help="Minimum scroll distance")
    parser.add_argument("--scroll-px-max", type=nonnegative_int, default=900, help="Maximum scroll distance")
    parser.add_argument("--click-prob", type=probability, default=0.25, help="Internal-link click probability")
    parser.add_argument("--max-clicks", type=nonnegative_int, default=1, help="Maximum clicks per page")
    parser.add_argument("--seed", type=int, help="Seed for repeatable random decisions")
    args = parser.parse_args(argv)

    if args.read_min < 0 or args.read_min > args.read_max:
        parser.error("--read-min must be nonnegative and no greater than --read-max")
    if args.scrolls_min > args.scrolls_max:
        parser.error("--scrolls-min cannot exceed --scrolls-max")
    if args.scroll_px_min > args.scroll_px_max:
        parser.error("--scroll-px-min cannot exceed --scroll-px-max")
    if not args.prefix:
        parser.error("--prefix cannot be empty")
    return args


def run_cycle(
    args: argparse.Namespace,
    behavior: Behavior,
    cycle_number: int,
) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = Path(args.outdir) / (
        f"{args.prefix}_{timestamp}_c{cycle_number:03d}.pcap"
    )
    stop_event = threading.Event()
    capture_errors: list[Exception] = []
    capture_thread = threading.Thread(
        target=capture_packets,
        args=(args.interface, output_path, args.filter, stop_event, capture_errors),
    )

    capture_thread.start()
    try:
        time.sleep(2.0)
        simulate_wikipedia(
            pages=args.pages,
            behavior=behavior,
            headless=args.headless,
            chromedriver_path=args.chromedriver_path,
        )
    finally:
        stop_event.set()
        logger.info("Waiting for the capture thread to finish")
        capture_thread.join()

    if capture_errors:
        raise RuntimeError("The packet capture did not complete successfully") from capture_errors[0]


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if os.geteuid() != 0:
        logger.error("Packet capture requires root privileges; run this command with sudo")
        return 1

    random.seed(args.seed)
    Path(args.outdir).mkdir(parents=True, exist_ok=True)
    behavior = Behavior(
        read_time_s=(args.read_min, args.read_max),
        scrolls_per_page=(args.scrolls_min, args.scrolls_max),
        scroll_px=(args.scroll_px_min, args.scroll_px_max),
        click_probability=args.click_prob,
        max_clicks_per_page=args.max_clicks,
    )

    try:
        for cycle_index in range(args.cycles):
            logger.info("Cycle %d/%d", cycle_index + 1, args.cycles)
            run_cycle(args, behavior, cycle_index + 1)
            logger.info("Cycle %d completed successfully", cycle_index + 1)
            if cycle_index + 1 < args.cycles:
                time.sleep(3.0)
    except KeyboardInterrupt:
        logger.warning("Interrupted by the user")
        return 130
    except Exception as error:
        logger.exception("Collection failed: %s", error)
        return 1

    logger.info("All capture cycles completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
