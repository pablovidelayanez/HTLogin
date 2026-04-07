import time
import concurrent.futures
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from statistics import mean, median

from domain.http import HTTPClient
from utils.logging import get_logger

logger = get_logger()


@dataclass
class RateLimitResult:
    rate_limited: bool
    detected_at: Optional[int] = None
    status_code: Optional[int] = None
    response_times: List[float] = field(default_factory=list)
    average_response_time: float = 0.0
    median_response_time: float = 0.0
    identical_responses: int = 0
    adaptive_delay_applied: bool = False
    total_duration: float = 0.0


class RateLimitDetector:
    def __init__(self, client: HTTPClient,
                 adaptive_delay: float = 1.0,
                 response_time_threshold: float = 2.0):
        self.client = client
        self.adaptive_delay = adaptive_delay
        self.response_time_threshold = response_time_threshold

        from domain.http.session_manager import SessionManager
        user_agent = None
        proxy = None
        if hasattr(client, 'session_manager'):
            if hasattr(client.session_manager, 'proxy'):
                proxy = client.session_manager.proxy
            if hasattr(client.session_manager, 'user_agent'):
                user_agent = client.session_manager.user_agent

        session_manager = SessionManager(
            timeout=client.timeout,
            proxy=proxy,
            use_cloudscraper=False,
            user_agent=user_agent
        )
        self.rate_limit_session = session_manager._create_requests_session(max_retries=0)

    def test(self, url: str, num_requests: int, verbose: bool = False,
             progress_bar=None) -> RateLimitResult:
        start_time = time.time()
        response_times: List[float] = []
        status_codes: List[int] = []
        response_bodies: List[str] = []
        rate_limited_at: Optional[int] = None
        rate_limit_status: Optional[int] = None
        test_terminated = False

        def make_request(i: int) -> Tuple[int, int, float, str]:
            try:
                req_start = time.time()
                response = self.rate_limit_session.get(url, timeout=self.client.timeout)
                elapsed = time.time() - req_start
                status_code = response.status_code if response else 0
                response_text = ""
                if response and hasattr(response, 'text') and response.text:
                    response_text = response.text[:100]
                return i, status_code, elapsed, response_text
            except Exception as e:
                error_str = str(e).lower()
                if '429' in error_str or 'too many' in error_str:
                    return i, 429, 0.0, ""
                if hasattr(e, 'response') and e.response and e.response.status_code == 429:
                    return i, 429, 0.0, ""
                if 'connection' in error_str and '429' in error_str:
                    return i, 429, 0.0, ""
                logger.debug(f"Request {i} failed: {e}")
                return i, 0, 0.0, ""

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]

            for future in concurrent.futures.as_completed(futures):
                if test_terminated:
                    for pending_future in futures:
                        if not pending_future.done():
                            pending_future.cancel()
                    break

                try:
                    i, status, elapsed, body = future.result()

                    response_times.append(elapsed)
                    status_codes.append(status)
                    response_bodies.append(body)

                    if progress_bar:
                        progress_bar.update(1)

                    if status == 429 and rate_limited_at is None:
                        rate_limited_at = i + 1
                        rate_limit_status = 429
                        test_terminated = True
                        logger.warning(f"Rate limit detected at request {rate_limited_at} (429). Terminating test immediately.")

                        cancelled_count = 0
                        for pending_future in futures:
                            if not pending_future.done():
                                pending_future.cancel()
                                cancelled_count += 1

                        if progress_bar:
                            progress_bar.update(cancelled_count)

                        break
                    elif status in [403] and rate_limited_at is None:
                        rate_limited_at = i + 1
                        rate_limit_status = status
                        logger.warning(f"Rate limit detected at request {rate_limited_at} with status code {status}")
                        if verbose:
                            logger.debug(f"Rate limit detected at request {rate_limited_at} with status code {status}")
                except concurrent.futures.CancelledError:
                    if progress_bar:
                        progress_bar.update(1)
                    continue
                except Exception as e:
                    error_str = str(e).lower()
                    if '429' in error_str or 'too many' in error_str:
                        if rate_limited_at is None:
                            rate_limited_at = len(response_times) + 1
                            rate_limit_status = 429
                            test_terminated = True
                            logger.warning(
                                f"Rate limit detected (429 error) at request {rate_limited_at}. "
                                "Terminating test immediately."
                            )

                            cancelled_count = 0
                            for pending_future in futures:
                                if not pending_future.done():
                                    pending_future.cancel()
                                    cancelled_count += 1

                            if progress_bar:
                                progress_bar.update(cancelled_count)

                            break
                    else:
                        logger.error(f"Error getting result from future: {e}")
                        if progress_bar:
                            progress_bar.update(1)

        total_duration = time.time() - start_time

        if test_terminated and rate_limited_at:
            logger.info(f"Rate limit test terminated after {rate_limited_at} request(s) due to 429 response")

        result = self._analyze_results(
            response_times, status_codes, response_bodies,
            rate_limited_at, rate_limit_status, verbose, total_duration
        )

        return result

    def _analyze_results(self, response_times: List[float], status_codes: List[int],
                        response_bodies: List[str], rate_limited_at: Optional[int],
                        rate_limit_status: Optional[int], verbose: bool,
                        total_duration: float = 0.0) -> RateLimitResult:
        avg_time = mean(response_times) if response_times else 0.0
        median_time = median(response_times) if response_times else 0.0

        time_spike_detected = False
        if len(response_times) > 5:
            early_avg = mean(response_times[:len(response_times)//2])
            late_avg = mean(response_times[len(response_times)//2:])
            if late_avg > early_avg * self.response_time_threshold:
                time_spike_detected = True
                logger.debug("Response time spike detected - possible rate limiting")

        identical_count = 0
        if len(response_bodies) > 1:
            first_body = response_bodies[0]
            identical_count = sum(1 for body in response_bodies[1:] if body == first_body)

        rate_limited = rate_limited_at is not None or time_spike_detected

        if rate_limited_at is None and 429 in status_codes:
            rate_limited = True
            for idx, code in enumerate(status_codes):
                if code == 429:
                    rate_limited_at = idx + 1
                    break
            rate_limit_status = 429
            logger.warning(
                f"Rate limit detected (429 found in responses) at request {rate_limited_at}"
            )

        if rate_limited and rate_limited_at is None:
            rate_limited_at = len(status_codes) if status_codes else 1
            logger.warning(f"Rate limit detected but request number unknown, using {rate_limited_at}")

        if rate_limited_at is None and not rate_limited:
            message = f"No rate limit after {len(response_times)} requests in {total_duration:.2f} seconds"
            logger.info(message)
            if verbose:
                logger.debug(message)

        return RateLimitResult(
            rate_limited=rate_limited,
            detected_at=rate_limited_at,
            status_code=rate_limit_status,
            response_times=response_times,
            average_response_time=avg_time,
            median_response_time=median_time,
            identical_responses=identical_count,
            adaptive_delay_applied=False,
            total_duration=total_duration
        )

    def apply_adaptive_delay(self, result: RateLimitResult) -> None:
        if result.rate_limited and not result.adaptive_delay_applied:
            logger.info(f"Applying adaptive delay of {self.adaptive_delay}s due to rate limiting")
            time.sleep(self.adaptive_delay)
            result.adaptive_delay_applied = True

