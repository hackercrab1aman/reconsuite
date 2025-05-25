import requests
import logging
import re
from bs4 import BeautifulSoup
import json
from .utils import rate_limit, sanitize_url

class TechDetector:
    """Module for detecting technologies used by web applications"""
    
    def __init__(self, target, timeout=5):
        self.target = sanitize_url(target)
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
        
        # User agent to mimic a browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Define technology signatures
        self.tech_signatures = self._load_signatures()
    
    def _load_signatures(self):
        """Load technology signatures"""
        # Define basic signatures for common technologies
        # In a real implementation, this would load from a comprehensive database
        return {
            'wordpress': {
                'headers': [],
                'cookies': ['wp-settings', 'wordpress_test_cookie'],
                'html': [
                    '<link[^>]+wp-content', 
                    '<link[^>]+wp-includes',
                    'wp-embed.min.js'
                ],
                'meta': ['generator" content="WordPress']
            },
            'joomla': {
                'headers': [],
                'cookies': ['joomla_user_state'],
                'html': [
                    '/media/system/js/core.js',
                    '/media/jui/'
                ],
                'meta': ['generator" content="Joomla']
            },
            'drupal': {
                'headers': [],
                'cookies': ['Drupal.visitor'],
                'html': ['Drupal.settings', 'data-drupal'],
                'meta': ['generator" content="Drupal']
            },
            'bootstrap': {
                'headers': [],
                'cookies': [],
                'html': ['bootstrap.min.css', 'bootstrap.min.js', 'class="container"', 'class="row"'],
                'meta': []
            },
            'jquery': {
                'headers': [],
                'cookies': [],
                'html': ['jquery.min.js', 'jquery-'],
                'meta': []
            },
            'react': {
                'headers': [],
                'cookies': [],
                'html': ['react.min.js', 'react-dom', 'reactjs'],
                'meta': []
            },
            'angular': {
                'headers': [],
                'cookies': [],
                'html': ['ng-app', 'angular.min.js', 'ng-controller'],
                'meta': []
            },
            'vue': {
                'headers': [],
                'cookies': [],
                'html': ['vue.min.js', 'v-bind', 'v-for', 'v-if'],
                'meta': []
            },
            'php': {
                'headers': ['X-Powered-By: PHP'],
                'cookies': ['PHPSESSID'],
                'html': ['.php"', '.php\''],
                'meta': []
            },
            'aspnet': {
                'headers': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
                'cookies': ['ASP.NET_SessionId'],
                'html': ['__VIEWSTATE', '__EVENTVALIDATION'],
                'meta': []
            },
            'nodejs': {
                'headers': ['X-Powered-By: Express'],
                'cookies': ['connect.sid'],
                'html': [],
                'meta': []
            },
            'apache': {
                'headers': ['Server: Apache'],
                'cookies': [],
                'html': [],
                'meta': []
            },
            'nginx': {
                'headers': ['Server: nginx'],
                'cookies': [],
                'html': [],
                'meta': []
            },
            'iis': {
                'headers': ['Server: Microsoft-IIS'],
                'cookies': [],
                'html': [],
                'meta': []
            },
            'cloudflare': {
                'headers': ['Server: cloudflare', 'CF-RAY'],
                'cookies': ['__cfduid'],
                'html': [],
                'meta': []
            },
            'google analytics': {
                'headers': [],
                'cookies': ['_ga', '_gid'],
                'html': ['google-analytics.com/analytics.js', 'gtag'],
                'meta': []
            },
            'google tag manager': {
                'headers': [],
                'cookies': [],
                'html': ['googletagmanager.com/gtm.js', 'GTM-'],
                'meta': []
            }
        }
    
    @rate_limit(1)  # 1 second delay between requests
    def fetch_page(self, url):
        """Fetch the target page and return response details"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            return {
                'headers': response.headers,
                'cookies': response.cookies,
                'html': response.text,
                'status_code': response.status_code
            }
        except requests.RequestException as e:
            self.logger.error(f"Error fetching page {url}: {str(e)}")
            return None
    
    def _extract_meta_tags(self, html):
        """Extract meta tags from HTML"""
        meta_tags = {}
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    meta_tags[name] = content
        except Exception as e:
            self.logger.error(f"Error parsing HTML: {str(e)}")
        
        return meta_tags
    
    def _extract_js_libraries(self, html):
        """Extract JavaScript libraries from HTML"""
        js_libraries = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            scripts = soup.find_all('script', src=True)
            
            for script in scripts:
                src = script['src']
                # Extract library name from script src
                if '/' in src:
                    parts = src.split('/')
                    for part in parts:
                        if '.js' in part:
                            lib_name = part.split('.')[0]
                            if lib_name and lib_name not in ['', 'http:', 'https:']:
                                js_libraries.append(lib_name)
        except Exception as e:
            self.logger.error(f"Error extracting JS libraries: {str(e)}")
        
        return list(set(js_libraries))  # Remove duplicates
    
    def detect_technologies(self, page_data):
        """Detect technologies based on signatures"""
        if not page_data:
            return []
        
        detected_techs = {}
        
        # Extract meta tags
        meta_tags = self._extract_meta_tags(page_data['html'])
        meta_str = json.dumps(meta_tags)
        
        # Convert headers to string for easier matching
        headers_str = str(page_data['headers'])
        
        # Convert cookies to string
        cookies_str = str(page_data['cookies'])
        
        # Check each technology signature
        for tech, signatures in self.tech_signatures.items():
            confidence = 0
            matches = []
            
            # Check headers
            for signature in signatures['headers']:
                if signature in headers_str:
                    confidence += 30
                    matches.append(f"Header: {signature}")
            
            # Check cookies
            for signature in signatures['cookies']:
                if signature in cookies_str:
                    confidence += 30
                    matches.append(f"Cookie: {signature}")
            
            # Check HTML content
            for signature in signatures['html']:
                if re.search(signature, page_data['html'], re.IGNORECASE):
                    confidence += 20
                    matches.append(f"HTML: {signature}")
            
            # Check meta tags
            for signature in signatures['meta']:
                if signature in meta_str:
                    confidence += 30
                    matches.append(f"Meta: {signature}")
            
            # If we found any matches, add to detected technologies
            if confidence > 0:
                detected_techs[tech] = {
                    'confidence': min(confidence, 100),  # Cap at 100%
                    'matches': matches
                }
        
        # Additional detection: JavaScript libraries
        js_libraries = self._extract_js_libraries(page_data['html'])
        for lib in js_libraries:
            if lib.lower() not in detected_techs:
                detected_techs[lib.lower()] = {
                    'confidence': 70,
                    'matches': [f"Script src: {lib}"]
                }
        
        # Sort by confidence (descending)
        sorted_techs = dict(sorted(
            detected_techs.items(), 
            key=lambda item: item[1]['confidence'], 
            reverse=True
        ))
        
        return sorted_techs
    
    def run(self):
        """Run technology detection"""
        self.logger.info(f"Starting technology detection for {self.target}")
        
        page_data = self.fetch_page(self.target)
        if not page_data:
            return {
                'error': 'Failed to fetch page',
                'target': self.target
            }
        
        technologies = self.detect_technologies(page_data)
        
        self.logger.info(f"Technology detection completed. Found {len(technologies)} technologies")
        
        # Group technologies by category
        categories = {
            'cms': ['wordpress', 'joomla', 'drupal', 'magento', 'shopify'],
            'javascript': ['jquery', 'react', 'angular', 'vue', 'bootstrap'],
            'server': ['apache', 'nginx', 'iis', 'tomcat', 'nodejs'],
            'analytics': ['google analytics', 'google tag manager', 'hotjar', 'matomo'],
            'cdn': ['cloudflare', 'akamai', 'fastly', 'cloudfront']
        }
        
        categorized = {
            'cms': [],
            'javascript': [],
            'server': [],
            'analytics': [],
            'cdn': [],
            'other': []
        }
        
        for tech, data in technologies.items():
            categorized_tech = {
                'name': tech,
                'confidence': data['confidence'],
                'matches': data['matches']
            }
            
            # Assign to category
            assigned = False
            for category, tech_list in categories.items():
                if tech.lower() in tech_list:
                    categorized[category].append(categorized_tech)
                    assigned = True
                    break
            
            if not assigned:
                categorized['other'].append(categorized_tech)
        
        # Clean empty categories
        for category in list(categorized.keys()):
            if not categorized[category]:
                del categorized[category]
        
        return {
            'target': self.target,
            'total_technologies': len(technologies),
            'technologies': technologies,
            'categorized': categorized
        }
