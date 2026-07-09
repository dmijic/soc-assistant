from  logging.handlers import RotatingFileHandler
from pathlib import Path
import logging

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    # Add console handler to logger
    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        file_handler = RotatingFileHandler(log_dir / "app.log", maxBytes=1_000_000, backupCount=3)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.setLevel(logging.INFO)
    return logger