from __future__ import annotations

import logging
import os
import sys
from typing import Optional


RESET  = "" if os.getenv("NO_COLOR") else "\033[0m"
BOLD   = "" if os.getenv("NO_COLOR") else "\033[1m"
DIM    = "" if os.getenv("NO_COLOR") else "\033[2m"
CYAN   = "" if os.getenv("NO_COLOR") else "\033[96m"
YELLOW = "" if os.getenv("NO_COLOR") else "\033[93m"
RED    = "" if os.getenv("NO_COLOR") else "\033[91m"
GREEN  = "" if os.getenv("NO_COLOR") else "\033[92m"


class ColourFormatter(logging.Formatter):
    LEVEL_STYLES = {
        "DEBUG":    DIM,
        "INFO":     CYAN,
        "WARNING":  YELLOW,
        "ERROR":    RED,
        "CRITICAL": BOLD + RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self.LEVEL_STYLES.get(record.levelname, "")
        prefix = f"{colour}[{record.levelname[0]}]{RESET}"
        return f"{prefix} {record.getMessage()}"


def get_logger(name: str = "phishing_detector", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColourFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def step(message: str) -> None:
    """Print a top-level pipeline step to stdout."""
    print(f"{CYAN}[*]{RESET} {message}")


def success(message: str) -> None:
    print(f"{GREEN}[+]{RESET} {message}")


def warn(message: str) -> None:
    print(f"{YELLOW}[!]{RESET} {message}")


def error(message: str) -> None:
    print(f"{RED}[✗]{RESET} {message}", file=sys.stderr)
