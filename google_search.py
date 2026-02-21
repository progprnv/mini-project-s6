"""
Google Search API integration module
"""
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from config import settings, get_next_api_key
import time
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urlparse, parse_qs
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GoogleSearchAPI:
    """Google Custom Search API wrapper"""
    
    def __init__(self):
        self.max_retries = settings.max_retries
        self.retry_count = 0
    
    def search(self, query: str, num_results: int = 10, file_type: str = None, max_pages: int = 10):
        """
        Execute Google search with pagination support.
        
        Tries the official Custom Search JSON API first.  If API keys are not
        configured *or* every API attempt fails, automatically falls back to a
        lightweight HTML-scraping approach so the tool still works universally.
        
        Args:
            query: Search query
            num_results: Number of results per page (max 10 per request)
            file_type: Optional file type filter (pdf, doc, docx, etc.)
            max_pages: Maximum number of pages to fetch (default 10 = 100 results)
        
        Returns:
            List of search results with URLs and metadata
        """
        # Check if API keys are configured
        if not settings.google_api_keys or not settings.google_search_engine_ids:
            logger.warning("⚠️ No Google API keys configured — falling back to web scraping")
            return self._fallback_search(query, file_type=file_type, max_pages=max_pages)
        
        all_results = []
        
        # Paginate through results
        for page in range(max_pages):
            attempts = 0
            page_success = False
            
            while attempts < self.max_retries and not page_success:
                try:
                    # Get next API key and search engine ID (rotate for rate limiting)
                    api_key, search_engine_id = get_next_api_key()
                    
                    if not api_key or not search_engine_id:
                        logger.error("❌ Invalid API key or search engine ID")
                        return all_results if all_results else []
                    
                    # Build search query
                    search_query = query
                    if file_type:
                        search_query += f" ext:{file_type}"
                    
                    # Calculate start index for pagination (1-based)
                    start_index = (page * 10) + 1
                    
                    logger.info(f"Executing search (page {page + 1}/{max_pages}): {search_query} [startIndex: {start_index}]")
                    
                    # Build the service
                    service = build("customsearch", "v1", developerKey=api_key)
                    
                    # Execute search with pagination
                    response = service.cse().list(
                        q=search_query,
                        cx=search_engine_id,
                        num=min(num_results, 10),  # Google allows max 10 per request
                        start=start_index
                    ).execute()
                    
                    # Extract results
                    if "items" in response:
                        for item in response["items"]:
                            url = item.get("link", "")
                            # Validate URL is not empty
                            if url:
                                all_results.append({
                                    "title": item.get("title", ""),
                                    "link": url,
                                    "snippet": item.get("snippet", ""),
                                    "file_format": item.get("fileFormat", ""),
                                    "mime": item.get("mime", "")
                                })
                        
                        logger.info(f"✅ Page {page + 1}: Found {len(response['items'])} results (Total: {len(all_results)})")
                        page_success = True
                    else:
                        # No more results available
                        logger.info(f"⚠️ Page {page + 1}: No more results available")
                        return all_results
                    
                except HttpError as e:
                    attempts += 1
                    logger.warning(f"⚠️ API Error on page {page + 1} (attempt {attempts}/{self.max_retries}): {str(e)}")
                    
                    if attempts < self.max_retries:
                        time.sleep(2 ** attempts)  # Exponential backoff
                    else:
                        logger.error(f"❌ Failed after {self.max_retries} attempts on page {page + 1}")
                        if all_results:
                            return all_results  # Return partial results collected so far
                        # No results yet — fall back to scraping
                        logger.info("🔄 Falling back to web scraping after API failures")
                        return self._fallback_search(query, file_type=file_type, max_pages=max_pages)
                        
                except Exception as e:
                    logger.error(f"❌ Unexpected error on page {page + 1}: {str(e)}")
                    if all_results:
                        return all_results  # Return partial results collected so far
                    logger.info("🔄 Falling back to web scraping after unexpected error")
                    return self._fallback_search(query, file_type=file_type, max_pages=max_pages)
        
        logger.info(f"✅ Search completed. Total results: {len(all_results)}")
        return all_results

    # ------------------------------------------------------------------
    # Fallback: scrape Google HTML results when the API is unavailable
    # ------------------------------------------------------------------

    _USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    def _fallback_search(self, query: str, file_type: str = None, max_pages: int = 3):
        """
        Scrape Google search results as a fallback when the Custom Search API
        is unavailable (no keys, quota exhausted, etc.).
        
        This is intentionally conservative: it fetches a small number of pages
        with polite delays to avoid being blocked.
        
        Args:
            query: Search query string
            file_type: Optional file-type filter
            max_pages: Pages to scrape (capped at 5 to stay polite)
        
        Returns:
            List of search result dicts (same shape as the API path)
        """
        search_query = query
        if file_type:
            search_query += f" ext:{file_type}"

        max_pages = min(max_pages, 5)  # cap to stay polite
        all_results = []
        session = requests.Session()

        for page in range(max_pages):
            try:
                start = page * 10
                url = f"https://www.google.com/search?q={quote_plus(search_query)}&start={start}&num=10"

                headers = {
                    "User-Agent": random.choice(self._USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                }

                resp = session.get(url, headers=headers, timeout=15)

                if resp.status_code == 429:
                    logger.warning("⚠️ Fallback scraper rate-limited (HTTP 429). Stopping.")
                    break
                if resp.status_code != 200:
                    logger.warning(f"⚠️ Fallback scraper got HTTP {resp.status_code}")
                    break

                soup = BeautifulSoup(resp.text, "html.parser")

                # Google wraps organic results in <div class="g"> blocks
                result_divs = soup.select("div.g")
                if not result_divs:
                    logger.info(f"⚠️ Fallback page {page + 1}: no result blocks found — possible CAPTCHA")
                    break

                for div in result_divs:
                    a_tag = div.find("a", href=True)
                    if not a_tag:
                        continue
                    link = a_tag["href"]
                    # Google sometimes wraps links – extract actual URL
                    if link.startswith("/url?"):
                        parsed = parse_qs(urlparse(link).query)
                        link = parsed.get("q", [link])[0]
                    if not link.startswith("http"):
                        continue

                    title_el = div.find("h3")
                    title = title_el.get_text(strip=True) if title_el else ""

                    snippet_el = div.select_one("div[data-sncf], div.VwiC3b, span.aCOpRe")
                    snippet = snippet_el.get_text(strip=True) if snippet_el else ""

                    all_results.append({
                        "title": title,
                        "link": link,
                        "snippet": snippet,
                        "file_format": "",
                        "mime": "",
                    })

                logger.info(f"🔄 Fallback page {page + 1}: scraped {len(result_divs)} blocks (total {len(all_results)} results)")

                # Polite delay between pages
                if page < max_pages - 1:
                    time.sleep(random.uniform(2, 4))

            except Exception as e:
                logger.error(f"❌ Fallback scraper error on page {page + 1}: {e}")
                break

        logger.info(f"🔄 Fallback search completed. Total results: {len(all_results)}")
        return all_results

    def generate_dork_queries(self, data_types: list, domain: str = "gov.in"):
        """
        Generate Google dorking queries for sensitive data detection
        
        Args:
            data_types: List of data types to search for (aadhaar, pan, etc.)
            domain: Target domain (default: gov.in)
        
        Returns:
            List of dorking queries
        """
        queries = []
        
        # Mapping of data types to specific dork queries
        dork_queries = {
            "aadhaar": [
                f'site:{domain} ext:pdf "Aadhaar Card No" -site:uidai.gov.in -site:styandptg.py.gov.in -site:mhc.tn.gov.in -site:goaprintingpress.gov.in  -inurl:gazette',
                f'site:{domain} ext:pdf "Aadhaar Number" -site:uidai.gov.in -site:styandptg.py.gov.in -site:mhc.tn.gov.in -site:goaprintingpress.gov.in  -inurl:gazette',
                f'site:{domain} ext:pdf "Aadhaar No" -site:uidai.gov.in -site:styandptg.py.gov.in -site:mhc.tn.gov.in -site:goaprintingpress.gov.in  -inurl:gazette'
                ],
            
            "pan": [
                f'site:{domain} ext:pdf "Pan Card"',
                f'site:{domain} ext:pdf "Permanent Account Number"'
            ],
            "bank_account": [
                f'site:{domain} ext:pdf "Account Number" "IFSC"',
                f'site:{domain} ext:pdf "Bank Account"'
            ],
            "voter_id": [
                f'site:{domain} ext:pdf "Voter ID"',
                f'site:{domain} ext:pdf "EPIC Number"'
            ],
            "passport": [
                f'site:{domain} ext:pdf "Passport Number"'
            ]
        }
        
        for data_type in data_types:
            if data_type in dork_queries:
                for dork in dork_queries[data_type]:
                    queries.append({
                        "query": dork,
                        "data_type": data_type,
                        "file_type": "pdf"
                    })
        
        logger.info(f"📋 Generated {len(queries)} dorking queries")
        return queries
