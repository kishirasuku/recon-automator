#!/usr/bin/env python3
"""
Recon Automator - Web Reconnaissance Automation Tool

A GUI application for Kali Linux that automates web reconnaissance
with a single button click.

Usage:
    python main.py [--config CONFIG_PATH]
"""

import argparse
import sys
from pathlib import Path

from loguru import logger


def setup_logging(log_file: str = "recon_automator.log"):
    """Configure loguru for application logging.

    Args:
        log_file: Path to log file.
    """
    # Remove default handler
    logger.remove()

    # Add console handler (for debugging)
    logger.add(
        sys.stderr,
        level="WARNING",
        format="<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    )

    # Add file handler
    logger.add(
        log_file,
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="10 MB",
        retention="7 days",
    )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Recon Automator - Web Reconnaissance Automation Tool"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="config/settings.yaml",
        help="Path to configuration file (default: config/settings.yaml)",
    )
    parser.add_argument(
        "--log",
        "-l",
        type=str,
        default="recon_automator.log",
        help="Path to log file (default: recon_automator.log)",
    )
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log)
    logger.info("Starting Recon Automator")

    # Verify config exists
    config_path = Path(args.config)
    if not config_path.exists():
        logger.warning(f"Config file not found: {config_path}")
        print(f"Warning: Config file not found at {config_path}")
        print("Using default configuration.")

    # Import and run the app
    try:
        from gui.app import run_app
        run_app(str(config_path))
    except ImportError as e:
        logger.error(f"Import error: {e}")
        print(f"Error: Failed to import required modules: {e}")
        print("\nPlease install dependencies:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logger.exception("Application error")
        print(f"Error: {e}")
        sys.exit(1)

    logger.info("Recon Automator closed")


if __name__ == "__main__":
    main()
