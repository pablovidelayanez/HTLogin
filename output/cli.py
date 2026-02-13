from typing import List, Optional
from core.results import ScanResult
from utils.colors import Colors


class CLIOutput:
    @staticmethod
    def print_banner(banner: str) -> None:
        print(banner)
    
    @staticmethod
    def print_target_header(url: str, index: int = None, total: int = None) -> None:
        if index is not None and total is not None:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}Target {index}/{total}:{Colors.RESET} {Colors.BRIGHT_CYAN}{url}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        else:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}Target:{Colors.RESET} {Colors.BRIGHT_CYAN}{url}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    @staticmethod
    def print_discovered_pages(discovered_urls: List[str]) -> None:
        print(f"\n{Colors.GREEN}✓ Found {len(discovered_urls)} login page(s):{Colors.RESET}")
        for discovered_url in discovered_urls:
            print(f"  {Colors.CYAN}→{Colors.RESET} {discovered_url}")
    
    @staticmethod
    def print_discovered_pages_header(count: int) -> None:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.YELLOW}Auto-testing {count} discovered login page(s)...{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.YELLOW}{'='*60}{Colors.RESET}\n")
    
    @staticmethod
    def print_discovered_page(url: str, index: int, total: int) -> None:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}Discovered Login Page {index}/{total}:{Colors.RESET} {Colors.BRIGHT_CYAN}{url}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    @staticmethod
    def print_summary(result: ScanResult) -> None:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}Summary of Results{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        if hasattr(result, 'baseline_login') and result.baseline_login:
            baseline = result.baseline_login
            if baseline.get("success"):
                print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.BOLD}Baseline Login Test{Colors.RESET}: {Colors.GREEN}Successful{Colors.RESET}")
                print(f"  {Colors.DIM}Confidence:{Colors.RESET} {baseline.get('confidence_level', 'N/A')} ({baseline.get('confidence_score', 0)})")
            else:
                print(f"{Colors.RED}✗{Colors.RESET} {Colors.BOLD}Baseline Login Test{Colors.RESET}: {Colors.RED}Failed{Colors.RESET}")
        
        if hasattr(result, 'username_enumeration') and result.username_enumeration:
            enum = result.username_enumeration
            if enum.get("vulnerable") is True:
                print(f"{Colors.YELLOW}⚠{Colors.RESET} {Colors.BOLD}Username Enumeration{Colors.RESET}: {Colors.YELLOW}Vulnerable{Colors.RESET}")
                if "details" in enum and enum["details"]:
                    details = enum["details"]
                    print(f"  {Colors.DIM}Test Username:{Colors.RESET} {details.get('test_username', 'N/A')}")
                    if "indicator_found" in details:
                        print(f"  {Colors.DIM}Indicator:{Colors.RESET} {', '.join(details['indicator_found'])}")
            elif enum.get("vulnerable") is False:
                print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.BOLD}Username Enumeration{Colors.RESET}: {Colors.GREEN}Not Vulnerable{Colors.RESET}")
            elif enum.get("skipped"):
                print(f"{Colors.DIM}⊘{Colors.RESET} {Colors.BOLD}Username Enumeration{Colors.RESET}: {Colors.DIM}Skipped ({enum.get('reason', 'N/A')}){Colors.RESET}")
        
        for test_type, test_result in result.tests.items():
            status = test_result.get("status", "Unknown")
            if status == "Successful":
                conf_level = test_result.get("confidence_level", "Unknown")
                conf_score = test_result.get("confidence_score", 0)
                
                conf_color = Colors.GREEN if conf_level == "High" else Colors.YELLOW if conf_level == "Medium" else Colors.RED
                print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.BOLD}{test_type}{Colors.RESET}: {Colors.GREEN}{status}{Colors.RESET} ({conf_color}{conf_level}{Colors.RESET} - {conf_score})")
                
                if "payload" in test_result:
                    print(f"  {Colors.DIM}Payload:{Colors.RESET} {Colors.BRIGHT_CYAN}{test_result['payload']}{Colors.RESET}")
                if "credential" in test_result:
                    print(f"  {Colors.DIM}Credential:{Colors.RESET} {Colors.BRIGHT_CYAN}{test_result['credential']}{Colors.RESET}")
                if test_result.get("manual_verification_recommended"):
                    print(f"  {Colors.YELLOW}⚠ Manual verification recommended{Colors.RESET}")
            else:
                print(f"{Colors.RED}✗{Colors.RESET} {Colors.BOLD}{test_type}{Colors.RESET}: {Colors.DIM}{status}{Colors.RESET}")
                if "rate_limited_at" in test_result and test_result["rate_limited_at"]:
                    print(f"  {Colors.DIM}Rate limited at:{Colors.RESET} Attempt #{test_result['rate_limited_at']}")
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.DIM}Target:{Colors.RESET} {Colors.BRIGHT_CYAN}{result.url}{Colors.RESET}")
        duration = result.duration_seconds
        print(f"{Colors.DIM}Total duration:{Colors.RESET} {Colors.BOLD}{duration:.2f} seconds{Colors.RESET}")
        if result.summary and "total_requests" in result.summary:
            total_requests = result.summary.get("total_requests", 0)
            print(f"{Colors.DIM}Total requests:{Colors.RESET} {Colors.BOLD}{total_requests}{Colors.RESET}")
    
    @staticmethod
    def print_error(message: str) -> None:
        print(f"Error: {message}")
    
    @staticmethod
    def print_info(message: str) -> None:
        print(message)
    
    @staticmethod
    def print_warning(message: str) -> None:
        print(f"{Colors.YELLOW}⚠{Colors.RESET} {message}")
    
    @staticmethod
    def print_form_info(username_field: str, password_field: str, csrf_found: bool = False, 
                       captcha_found: bool = False) -> None:
        print(f"{Colors.GREEN}✓{Colors.RESET} Username input: {Colors.BOLD}{username_field}{Colors.RESET}")
        print(f"{Colors.GREEN}✓{Colors.RESET} Password input: {Colors.BOLD}{password_field}{Colors.RESET}")
        if csrf_found:
            print(f"{Colors.GREEN}✓{Colors.RESET} CSRF token found")
        else:
            print(f"{Colors.YELLOW}⚠{Colors.RESET} CSRF token not found. The form might be vulnerable to CSRF attacks.")
        if captcha_found:
            print(f"{Colors.YELLOW}⚠{Colors.RESET} CAPTCHA detected! Automated testing may be limited.")
    
    @staticmethod
    def print_discovery_attempt() -> None:
        print(f"{Colors.YELLOW}⚠ Login form not found on this page.{Colors.RESET}")
        print(f"{Colors.CYAN}Attempting to discover login pages from this URL...{Colors.RESET}")
    
    @staticmethod
    def print_no_discovery() -> None:
        print("No login pages discovered.")
    
    @staticmethod
    def print_file_saved(filename: str, format_type: str) -> None:
        print(f"\n{format_type.upper()} output saved to {filename}")

