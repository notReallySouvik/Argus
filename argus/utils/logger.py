import logging
from typing import Optional


def get_logger(name: str = "argus", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(level)
    logger.propagate = False
    return logger


def set_log_level(level: int) -> None:
    root_logger = logging.getLogger("argus")
    root_logger.setLevel(level)

    for handler in root_logger.handlers:
        handler.setLevel(level)