"""
Command executor for running shell commands safely.
"""

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class CommandResult:
    """Result of a command execution."""

    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        """Check if command executed successfully."""
        return self.returncode == 0


class CommandExecutor(ABC):
    """Abstract base class for command executors."""

    @abstractmethod
    def execute(self, command: list[str], cwd: Optional[str] = None) -> CommandResult:
        """Execute a command and return the result."""
        pass


class SubprocessExecutor(CommandExecutor):
    """Command executor using subprocess."""

    def execute(self, command: list[str], cwd: Optional[str] = None) -> CommandResult:
        """
        Execute a command using subprocess.

        Args:
            command: Command as list of strings
            cwd: Working directory

        Returns:
            CommandResult containing stdout, stderr, and return code
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                cwd=cwd,
            )
            return CommandResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
            )
        except Exception as e:
            return CommandResult(
                stdout="",
                stderr=str(e),
                returncode=-1,
            )
