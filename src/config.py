"""
Configuration for the eduroam profile generator.
"""

from pathlib import Path


class Config:
    """Application configuration."""

    # Paths
    TEMPLATE_DIR = Path("template")
    OUTPUT_DIR = Path("output")
    PROFILE_DIR = OUTPUT_DIR / "profile"
    CERT_DIR = OUTPUT_DIR / "cert"
    LOG_DIR = OUTPUT_DIR / "log"
    TEMP_DIR = OUTPUT_DIR / "temp"

    # Authentication credentials (for testing only)
    TEST_ACCOUNT = "anonymous"
    TEST_PASSWORD = "TestViaEduroamTWProfileProj"

    # Profile defaults
    DEFAULT_URL = "https://edur.isli.me/"
    DEFAULT_EMAIL = "eduroamtw@googlegroups.com"

    @classmethod
    def get_all_directories(cls) -> list[Path]:
        """Get all directories that need to be created."""
        return [
            cls.TEMPLATE_DIR,
            cls.OUTPUT_DIR,
            cls.PROFILE_DIR,
            cls.CERT_DIR,
            cls.LOG_DIR,
            cls.TEMP_DIR,
        ]
