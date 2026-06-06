#!/usr/bin/env python3

import argparse
import logging
import os
import random
import signal
import sys
import time
from pathlib import Path


DEFAULT_SOURCE_FILE = "demo-web-attack.log"
DEFAULT_TARGET_FILE = "/var/log/demo-web-access.log"

stop_requested = False


def setup_logging(verbose: bool) -> None:
    """
    Configure application logging.
    """
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def handle_signal(signum, frame) -> None:
    """
    Handle termination signals gracefully.
    """
    global stop_requested
    stop_requested = True
    logging.warning("Stop signal received. Finishing gracefully...")


def validate_source_file(source_path: Path) -> None:
    """
    Validate source log file.
    """
    if not source_path.exists():
        raise FileNotFoundError(f"Source file does not exist: {source_path}")

    if not source_path.is_file():
        raise ValueError(f"Source path is not a regular file: {source_path}")

    if not os.access(source_path, os.R_OK):
        raise PermissionError(f"Source file is not readable: {source_path}")


def validate_target_file(target_path: Path) -> None:
    """
    Validate target log file and its parent directory.
    """
    parent_dir = target_path.parent

    if not parent_dir.exists():
        raise FileNotFoundError(f"Target directory does not exist: {parent_dir}")

    if not parent_dir.is_dir():
        raise ValueError(f"Target parent path is not a directory: {parent_dir}")

    if target_path.exists():
        if not target_path.is_file():
            raise ValueError(f"Target path is not a regular file: {target_path}")

        if not os.access(target_path, os.W_OK):
            raise PermissionError(f"Target file is not writable: {target_path}")
    else:
        if not os.access(parent_dir, os.W_OK):
            raise PermissionError(f"Target directory is not writable: {parent_dir}")


def get_delay(min_delay: float, max_delay: float) -> float:
    """
    Return a delay value. If min and max are equal, fixed delay is used.
    Otherwise, a random delay in the given range is used.
    """
    if min_delay < 0 or max_delay < 0:
        raise ValueError("Delay values cannot be negative.")

    if min_delay > max_delay:
        raise ValueError("min-delay cannot be greater than max-delay.")

    if min_delay == max_delay:
        return min_delay

    return random.uniform(min_delay, max_delay)


def replay_logs(
    source_path: Path,
    target_path: Path,
    min_delay: float,
    max_delay: float,
    loop: bool,
    skip_empty: bool,
    fsync_enabled: bool,
) -> None:
    """
    Read log lines from source file and append them to target file one by one.
    """
    total_written = 0
    round_number = 0

    logging.info("Starting log replay")
    logging.info("Source file: %s", source_path)
    logging.info("Target file: %s", target_path)
    logging.info("Delay range: %.4f - %.4f seconds", min_delay, max_delay)
    logging.info("Loop mode: %s", "enabled" if loop else "disabled")

    while True:
        round_number += 1
        logging.info("Replay round #%d started", round_number)

        lines_written_this_round = 0

        try:
            with source_path.open("r", encoding="utf-8", errors="replace") as src, \
                 target_path.open("a", encoding="utf-8", buffering=1) as dst:

                for line_number, line in enumerate(src, start=1):
                    if stop_requested:
                        logging.warning("Replay stopped by user.")
                        logging.info("Total lines written: %d", total_written)
                        return

                    if skip_empty and not line.strip():
                        logging.debug("Skipping empty line at source line %d", line_number)
                        continue

                    if not line.endswith("\n"):
                        line += "\n"

                    dst.write(line)
                    dst.flush()

                    if fsync_enabled:
                        os.fsync(dst.fileno())

                    total_written += 1
                    lines_written_this_round += 1

                    logging.debug(
                        "Injected line %d from source. Total written: %d",
                        line_number,
                        total_written,
                    )

                    delay = get_delay(min_delay, max_delay)
                    time.sleep(delay)

        except PermissionError as exc:
            logging.error("Permission error while writing logs: %s", exc)
            raise
        except OSError as exc:
            logging.error("OS error during log replay: %s", exc)
            raise

        logging.info(
            "Replay round #%d completed. Lines written this round: %d",
            round_number,
            lines_written_this_round,
        )

        if not loop:
            break

        if lines_written_this_round == 0:
            logging.warning(
                "No lines were written in this round. Source file may be empty."
            )

    logging.info("Log replay completed successfully.")
    logging.info("Total lines written: %d", total_written)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Replay web attack logs into a Wazuh-monitored access log file "
            "to simulate live web server logs."
        )
    )

    parser.add_argument(
        "-s",
        "--source",
        default=DEFAULT_SOURCE_FILE,
        help=f"Source log file. Default: {DEFAULT_SOURCE_FILE}",
    )

    parser.add_argument(
        "-t",
        "--target",
        default=DEFAULT_TARGET_FILE,
        help=f"Target log file monitored by Wazuh. Default: {DEFAULT_TARGET_FILE}",
    )

    parser.add_argument(
        "--min-delay",
        type=float,
        default=0.05,
        help="Minimum delay between log injections in seconds. Default: 0.05",
    )

    parser.add_argument(
        "--max-delay",
        type=float,
        default=0.20,
        help="Maximum delay between log injections in seconds. Default: 0.20",
    )

    parser.add_argument(
        "--loop",
        action="store_true",
        help="Replay the source file repeatedly until stopped.",
    )

    parser.add_argument(
        "--skip-empty",
        action="store_true",
        help="Skip empty lines from source file.",
    )

    parser.add_argument(
        "--fsync",
        action="store_true",
        help=(
            "Force syncing each written line to disk. "
            "Slower, but useful if you want immediate persistence."
        ),
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    script_dir = Path(__file__).resolve().parent

    source_path = Path(args.source)
    if not source_path.is_absolute():
        source_path = script_dir / source_path

    target_path = Path(args.target)

    try:
        validate_source_file(source_path)
        validate_target_file(target_path)

        replay_logs(
            source_path=source_path,
            target_path=target_path,
            min_delay=args.min_delay,
            max_delay=args.max_delay,
            loop=args.loop,
            skip_empty=args.skip_empty,
            fsync_enabled=args.fsync,
        )

    except KeyboardInterrupt:
        logging.warning("Interrupted by user.")
        return 130
    except Exception as exc:
        logging.error("Execution failed: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

