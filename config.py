"""
Configuration module for the Cybersecurity Detection Framework
"""
from typing import List, Dict
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings"""
    
    def __init__(self):
        # Google Search API Configuration
        api_keys_str = os.getenv("GOOGLE_API_KEYS", "")
        search_ids_str = os.getenv("GOOGLE_SEARCH_ENGINE_IDS", "")
        
        self.google_api_keys: List[str] = [k.strip() for k in api_keys_str.split(",") if k.strip()]
        self.google_search_engine_ids: List[str] = [s.strip() for s in search_ids_str.split(",") if s.strip()]
        self.current_api_index: int = 0
        
        # Email Configuration
        self.smtp_server: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_email: str = os.getenv("SMTP_EMAIL", "")
        self.smtp_password: str = os.getenv("SMTP_PASSWORD", "")
        self.cert_in_email: str = os.getenv("CERT_IN_EMAIL", "vdisclose@cert-in.org.in")
        
        # Database Configuration
        self.database_url: str = os.getenv("DATABASE_URL", "sqlite:///./cybersecurity.db")
        
        # Application Settings
        self.debug: bool = os.getenv("DEBUG", "True").lower() == "true"
        self.host: str = os.getenv("HOST", "0.0.0.0")
        self.port: int = int(os.getenv("PORT", "8000"))
        
        # Sensitive Data Patterns
        self.patterns: Dict[str, str] = {
            "aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
            "pan": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            "bank_account": r"\b\d{9,18}\b",
            "voter_id": r"\b[A-Z]{3}[0-9]{7}\b",
            "passport": r"\b[A-Z]{1}[0-9]{7}\b"
        }
        
        # File Type Extensions
        self.supported_file_types: List[str] = ["pdf", "doc", "docx", "html", "log", "txt"]
        
        # Search Configuration
        self.max_results_per_query: int = 10
        self.max_retries: int = 3
        self.request_timeout: int = 30


# Global settings instance
settings = Settings()


def get_next_api_key():
    """Rotate through available API keys for rate limiting.
    
    Returns the current key pair, then advances the index for the next call.
    Handles mismatched key/ID counts safely by capping to the shorter list.
    """
    logger_instance = __import__('logging').getLogger(__name__)

    if not settings.google_api_keys or not settings.google_search_engine_ids:
        logger_instance.warning("⚠️ No Google API keys configured. Set GOOGLE_API_KEYS and GOOGLE_SEARCH_ENGINE_IDS in .env")
        return "", ""

    # Use the shorter list length so we never index out of bounds
    usable_count = min(len(settings.google_api_keys), len(settings.google_search_engine_ids))

    if len(settings.google_api_keys) != len(settings.google_search_engine_ids):
        logger_instance.warning(
            f"⚠️ Mismatched config: {len(settings.google_api_keys)} API key(s) vs "
            f"{len(settings.google_search_engine_ids)} Search Engine ID(s). "
            f"Using the first {usable_count} pair(s)."
        )

    # Read current index, then advance for next call
    idx = settings.current_api_index % usable_count
    settings.current_api_index = (idx + 1) % usable_count

    api_key = settings.google_api_keys[idx].strip()
    search_engine_id = settings.google_search_engine_ids[idx].strip()
    return api_key, search_engine_id


def validate_api_config() -> dict:
    """Return a summary of the current API configuration status."""
    keys_count = len(settings.google_api_keys)
    ids_count = len(settings.google_search_engine_ids)
    usable = min(keys_count, ids_count)
    configured = usable > 0

    return {
        "configured": configured,
        "api_keys_count": keys_count,
        "search_engine_ids_count": ids_count,
        "usable_pairs": usable,
        "mismatched": keys_count != ids_count and keys_count > 0 and ids_count > 0,
        "message": (
            f"{usable} API key pair(s) ready" if configured
            else "No API keys configured — copy .env.example to .env and add your keys"
        ),
    }
