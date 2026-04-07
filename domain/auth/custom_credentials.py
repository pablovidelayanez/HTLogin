from typing import List, Optional

from domain.auth.credential_provider import CredentialProvider
from utils.logging import get_logger

logger = get_logger()


class CustomCredentialProvider(CredentialProvider):
    def __init__(self, filepath: str):
        credentials = self._load_from_file(filepath)
        super().__init__(credentials)
        logger.info(f"Loaded {len(credentials)} custom credentials from {filepath}")

    def _load_from_file(self, filepath: str) -> List[str]:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                credentials = [line.strip() for line in f if line.strip()]
            return credentials
        except FileNotFoundError as e:
            logger.error(f"Credential file not found: {filepath}")
            raise FileNotFoundError(f"Credential file not found: {filepath}") from e
        except Exception as e:
            logger.error(f"Error reading credential file: {e}")
            raise RuntimeError(f"Error reading credential file: {e}") from e

