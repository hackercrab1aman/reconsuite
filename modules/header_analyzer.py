import requests
import logging
from .utils import rate_limit, sanitize_url

class HeaderAnalyzer:
    """Module for analyzing HTTP headers for security issues"""
    
    def __init__(self, target, timeout=5):
        self.target = sanitize_url(target)
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
        
        # User agent to mimic a browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Define security headers to check
        self.security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Feature-Policy',
            'Permissions-Policy',
            'Access-Control-Allow-Origin',
            'Server',
            'X-Powered-By'
        ]
    
    @rate_limit(1)  # 1 second delay between requests
    def get_headers(self, url):
        """Get HTTP headers from the target URL"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            return response.headers
        except requests.RequestException as e:
            self.logger.error(f"Error getting headers from {url}: {str(e)}")
            return {}
    
    def analyze_headers(self, headers):
        """Analyze headers for security issues"""
        results = {
            'headers_found': {},
            'missing_headers': [],
            'issues': []
        }
        
        # Check which security headers are present
        for header in self.security_headers:
            if header in headers:
                results['headers_found'][header] = headers[header]
            else:
                results['missing_headers'].append(header)
        
        # Analyze HSTS header
        if 'Strict-Transport-Security' in headers:
            hsts = headers['Strict-Transport-Security']
            if 'max-age=' not in hsts or int(hsts.split('max-age=')[1].split(';')[0]) < 15768000:  # 6 months
                results['issues'].append({
                    'header': 'Strict-Transport-Security',
                    'value': hsts,
                    'severity': 'Medium',
                    'description': 'HSTS max-age is less than 6 months'
                })
        else:
            results['issues'].append({
                'header': 'Strict-Transport-Security',
                'value': 'Missing',
                'severity': 'High',
                'description': 'HSTS header is missing, which could lead to SSL stripping attacks'
            })
        
        # Analyze Content-Security-Policy
        if 'Content-Security-Policy' not in headers:
            results['issues'].append({
                'header': 'Content-Security-Policy',
                'value': 'Missing',
                'severity': 'Medium',
                'description': 'CSP header is missing, which increases the risk of XSS attacks'
            })
        
        # Analyze X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers:
            results['issues'].append({
                'header': 'X-Content-Type-Options',
                'value': 'Missing',
                'severity': 'Low',
                'description': 'X-Content-Type-Options header is missing, which could lead to MIME sniffing attacks'
            })
        
        # Analyze X-Frame-Options
        if 'X-Frame-Options' not in headers:
            results['issues'].append({
                'header': 'X-Frame-Options',
                'value': 'Missing',
                'severity': 'Medium',
                'description': 'X-Frame-Options header is missing, which could lead to clickjacking attacks'
            })
        
        # Check for server information disclosure
        if 'Server' in headers and headers['Server'] not in ['', 'cloudflare']:
            results['issues'].append({
                'header': 'Server',
                'value': headers['Server'],
                'severity': 'Low',
                'description': 'Server header discloses information about the server software'
            })
        
        # Check for technology information disclosure
        if 'X-Powered-By' in headers:
            results['issues'].append({
                'header': 'X-Powered-By',
                'value': headers['X-Powered-By'],
                'severity': 'Low',
                'description': 'X-Powered-By header discloses information about the technology stack'
            })
        
        return results
    
    def run(self):
        """Run HTTP header analysis"""
        self.logger.info(f"Starting HTTP header analysis for {self.target}")
        
        headers = self.get_headers(self.target)
        if not headers:
            return {
                'error': 'Failed to retrieve headers',
                'target': self.target
            }
        
        analysis = self.analyze_headers(headers)
        
        # Add overall security score based on issues
        security_score = 100
        for issue in analysis['issues']:
            if issue['severity'] == 'High':
                security_score -= 15
            elif issue['severity'] == 'Medium':
                security_score -= 10
            elif issue['severity'] == 'Low':
                security_score -= 5
        
        security_score = max(0, security_score)
        
        self.logger.info(f"HTTP header analysis completed with security score: {security_score}")
        
        return {
            'target': self.target,
            'headers_found': analysis['headers_found'],
            'missing_headers': analysis['missing_headers'],
            'issues': analysis['issues'],
            'security_score': security_score,
            'total_headers': len(headers),
            'total_issues': len(analysis['issues'])
        }
