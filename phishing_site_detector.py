"""
Module 2 - Phishing Site Detector
Detects potential phishing/spoofed websites using Google Dorks and analysis
"""

import asyncio
import json
import logging
from typing import List, Dict
from google_search import GoogleSearchAPI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingSiteDetector:
    """Detect phishing sites using Google dorks"""
    
    def __init__(self):
        self.google_search = GoogleSearchAPI()
        self.phishing_keywords = {
            "betting_apps": {
                "dork": 'site:DOMAIN "betting" OR "sports betting" OR "casino" OR "bet"',
                "indicators": ["betting", "casino", "wager", "jackpot", "odds"],
                "risk_level": "HIGH"
            },
            "trading_apps": {
                "dork": 'site:DOMAIN "trading" OR "stocks" OR "crypto" OR "forex" OR "investment"',
                "indicators": ["trading", "stock", "forex", "crypto", "investment", "broker"],
                "risk_level": "MEDIUM"
            },
            "rummy_apps": {
                "dork": 'site:DOMAIN "rummy" OR "card games" OR "teen patti" OR "poker"',
                "indicators": ["rummy", "teen patti", "card game", "poker", "gamble"],
                "risk_level": "HIGH"
            }
        }
    
    async def scan_domain(self, site_domain: str, selected_types: List[str] = None) -> Dict:
        """
        Scan domain for phishing indicators using Google dorks
        
        Args:
            site_domain: Domain to scan (e.g., 'gov.in')
            selected_types: List of app types to check ['betting_apps', 'trading_apps', 'rummy_apps']
        
        Returns:
            Dictionary with scan results
        """
        if not selected_types:
            selected_types = list(self.phishing_keywords.keys())
        
        all_findings = []
        total_queries = 0
        
        for app_type in selected_types:
            if app_type not in self.phishing_keywords:
                logger.warning(f"Unknown app type: {app_type}")
                continue
            
            config = self.phishing_keywords[app_type]
            dork = config["dork"].replace("DOMAIN", site_domain)
            
            logger.info(f"Scanning {app_type} with dork: {dork}")
            
            try:
                # Execute Google search with dork (synchronous call)
                results = self.google_search.search(
                    query=dork,
                    num_results=10,
                    max_pages=3  # 30 results per app type
                )
                
                total_queries += 1
                
                for result in results:
                    finding = self._analyze_result(
                        result,
                        app_type,
                        config,
                        site_domain
                    )
                    if finding:
                        all_findings.append(finding)
            
            except Exception as e:
                logger.error(f"Error scanning {app_type}: {e}")
                continue
        
        # Calculate risk breakdown
        critical_count = len([f for f in all_findings if f["risk_level"] == "CRITICAL"])
        high_count = len([f for f in all_findings if f["risk_level"] == "HIGH"])
        medium_count = len([f for f in all_findings if f["risk_level"] == "MEDIUM"])
        
        return {
            "scan_id": None,  # Will be set by main.py
            "domain": site_domain,
            "total_findings": len(all_findings),
            "total_queries": total_queries,
            "risk_breakdown": {
                "CRITICAL": critical_count,
                "HIGH": high_count,
                "MEDIUM": medium_count,
                "LOW": len(all_findings) - critical_count - high_count - medium_count
            },
            "findings": all_findings
        }
    
    def _analyze_result(self, result: Dict, app_type: str, config: Dict, site_domain: str) -> Dict:
        """
        Analyze a search result for phishing indicators
        
        Args:
            result: Google search result
            app_type: Type of app being checked
            config: Configuration for this app type
            site_domain: Domain being scanned
        
        Returns:
            Finding dictionary or None
        """
        try:
            url = result.get("link", "")
            title = result.get("title", "")
            snippet = result.get("snippet", "")
            
            if not url:
                return None
            
            # Combine text to search
            combined_text = f"{title} {snippet}".lower()
            
            # Count indicators found
            indicators_found = []
            for indicator in config.get("indicators", []):
                if indicator.lower() in combined_text:
                    indicators_found.append(indicator)
            
            # If no indicators found, skip
            if not indicators_found:
                return None
            
            # Calculate confidence based on indicators and URL
            confidence = len(indicators_found) * 15  # 15% per indicator
            
            # Check if this is actually a gov.in subdomain
            is_gov_subdomain = site_domain.lower() in url.lower()
            
            # Determine risk level
            if is_gov_subdomain and len(indicators_found) >= 2:
                risk_level = "CRITICAL"
                confidence = min(100, confidence + 30)
            elif is_gov_subdomain:
                risk_level = "HIGH"
                confidence = min(100, confidence + 15)
            else:
                risk_level = config.get("risk_level", "MEDIUM")
            
            finding = {
                "url": url,
                "title": title.replace(site_domain, "***"),  # Anonymize domain
                "snippet": snippet[:100],
                "app_type": app_type.replace("_", " ").title(),
                "indicators": indicators_found,
                "risk_level": risk_level,
                "confidence": min(100, confidence),
                "is_gov_subdomain": is_gov_subdomain
            }
            
            return finding
        
        except Exception as e:
            logger.error(f"Error analyzing result: {e}")
            return None
    
    def get_dorks(self, site_domain: str) -> Dict[str, str]:
        """Get all dorks for a domain"""
        dorks = {}
        for app_type, config in self.phishing_keywords.items():
            dorks[app_type] = config["dork"].replace("DOMAIN", site_domain)
        return dorks
