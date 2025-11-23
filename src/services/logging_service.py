"""
Logging service for recording authentication results.
"""

import datetime
from pathlib import Path

from src.domain import AuthenticationResult
from src.infrastructure import FileRepository


class LoggingService:
    """Service for logging authentication results."""

    def __init__(self, file_repo: FileRepository, log_dir: Path):
        self.file_repo = file_repo
        self.log_dir = log_dir
        self.log_file = log_dir / "log.csv"

    def initialize(self) -> None:
        """Initialize log file with headers if it doesn't exist."""
        headers = [
            "Time",
            "realm",
            "pap_stat",
            "mschapv2_stat",
            "dns",
            "cert_pap",
            "cert_mschapv2",
        ]
        self.file_repo.ensure_directory(self.log_dir)
        self.file_repo.initialize_csv(self.log_file, headers)

    def log_result(self, result: AuthenticationResult) -> None:
        """
        Log authentication result to CSV file.

        Args:
            result: Authentication result to log
        """
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        pap_cert_str = "Yes" if result.pap_cert else "No"
        mschapv2_cert_str = "Yes" if result.mschapv2_cert else "No"

        row = [
            current_time,
            str(result.realm),
            str(result.pap_success),
            str(result.mschapv2_success),
            result.dns or "",
            pap_cert_str,
            mschapv2_cert_str,
        ]

        self.file_repo.append_csv_row(self.log_file, row)
