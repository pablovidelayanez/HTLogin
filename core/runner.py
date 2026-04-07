from typing import List, Optional
from config.settings import Config
from domain.auth import CredentialProviderProtocol
from core.scanner import LoginScanner
from core.results import ScanResult
from utils.logging import get_logger

logger = get_logger()


class ScanRunner:
    def __init__(self, scanner: LoginScanner, credential_provider: CredentialProviderProtocol):
        self.scanner = scanner
        self.credential_provider = credential_provider

    def run_single(self, url: str) -> ScanResult:
        result_dict = self.scanner.scan(url, self.credential_provider)
        return ScanResult.from_dict(result_dict)

    def run_multiple(self, urls: List[str], auto_test_discovered: bool = True) -> List[ScanResult]:
        results = []

        for url in urls:
            result = self.run_single(url)
            results.append(result)

            if auto_test_discovered and result.discovered_pages:
                logger.info(f"Auto-testing {len(result.discovered_pages)} discovered login page(s) for {url}")
                for discovered_url in result.discovered_pages:
                    discovered_result = self.run_single(discovered_url)
                    results.append(discovered_result)

        return results

