"""
Repository for file operations.
"""

import csv
import json
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional


class FileRepository(ABC):
    """Abstract base class for file operations."""

    @abstractmethod
    def read_text(self, path: Path) -> str:
        """Read text from file."""
        pass

    @abstractmethod
    def write_text(self, path: Path, content: str) -> None:
        """Write text to file."""
        pass

    @abstractmethod
    def read_bytes(self, path: Path) -> bytes:
        """Read bytes from file."""
        pass

    @abstractmethod
    def write_bytes(self, path: Path, content: bytes) -> None:
        """Write bytes to file."""
        pass

    @abstractmethod
    def exists(self, path: Path) -> bool:
        """Check if file exists."""
        pass

    @abstractmethod
    def copy(self, src: Path, dst: Path) -> None:
        """Copy file."""
        pass

    @abstractmethod
    def ensure_directory(self, path: Path) -> None:
        """Ensure directory exists."""
        pass


class LocalFileRepository(FileRepository):
    """File repository for local filesystem operations."""

    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """Read text from file."""
        with open(path, "r", encoding=encoding) as f:
            return f.read()

    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        """Write text to file."""
        with open(path, "w", encoding=encoding) as f:
            f.write(content)

    def read_bytes(self, path: Path) -> bytes:
        """Read bytes from file."""
        with open(path, "rb") as f:
            return f.read()

    def write_bytes(self, path: Path, content: bytes) -> None:
        """Write bytes to file."""
        with open(path, "wb") as f:
            f.write(content)

    def exists(self, path: Path) -> bool:
        """Check if file exists."""
        return path.exists()

    def copy(self, src: Path, dst: Path) -> None:
        """Copy file."""
        shutil.copy(src, dst)

    def ensure_directory(self, path: Path) -> None:
        """Ensure directory exists."""
        path.mkdir(parents=True, exist_ok=True)

    def read_json(self, path: Path) -> dict[str, Any]:
        """Read JSON from file."""
        content = self.read_text(path)
        return json.loads(content)

    def write_json(self, path: Path, data: dict[str, Any]) -> None:
        """Write JSON to file."""
        content = json.dumps(data, indent=4)
        self.write_text(path, content)

    def append_csv_row(self, path: Path, row: list[Any]) -> None:
        """Append a row to CSV file."""
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row)

    def initialize_csv(self, path: Path, headers: list[str]) -> None:
        """Initialize CSV file with headers if it doesn't exist."""
        if not self.exists(path):
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
