import dns.resolver
import logging
import concurrent.futures
from .utils import rate_limit

class SubdomainEnumerator:
    """Module for subdomain enumeration"""
    
    def __init__(self, domain, wordlist=None, max_workers=5):
        self.domain = domain
        self.logger = logging.getLogger(__name__)
        self.max_workers = max_workers
        
        # Use default wordlist if none provided
        self.wordlist = wordlist or self._get_default_wordlist()
        
        # Initialize DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0
    
    def _get_default_wordlist(self):
        """Get a default wordlist of common subdomains"""
        # This is a small default list, in production you'd use a larger one
        return [
            'www', 'mail', 'smtp', 'webmail', 'pop', 'ftp', 'blog', 
            'dev', 'admin', 'test', 'portal', 'ns1', 'ns2', 'ns3', 'ns4',
            'mx', 'remote', 'shop', 'api', 'app', 'secure', 'vpn', 'cdn',
            'stage', 'staging', 'web', 'intranet', 'corp', 'internal',
            'cloud', 'git', 'gitlab', 'jenkins', 'jira', 'support', 'help',
            'wiki', 'docs', 'login', 'backend', 'frontend', 'auth', 'mobile',
            'beta', 'alpha', 'db', 'database', 'sql', 'mysql', 'postgres',
            'ldap', 'ads', 'ad', 'analytics', 'monitor', 'status', 'grafana',
            'prometheus', 'kibana', 'elasticsearch', 'logstash'
        ]
    
    @rate_limit(0.3)  # Rate limit to avoid detection
    def check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            self.resolver.resolve(full_domain, 'A')
            return full_domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
            return None
        except Exception as e:
            self.logger.debug(f"Error checking subdomain {full_domain}: {str(e)}")
            return None
    
    def run(self):
        """Run subdomain enumeration"""
        self.logger.info(f"Starting subdomain enumeration for {self.domain}")
        discovered_subdomains = []
        
        # Use ThreadPoolExecutor for parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.check_subdomain, subdomain) for subdomain in self.wordlist]
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.logger.info(f"Discovered subdomain: {result}")
                    discovered_subdomains.append(result)
        
        self.logger.info(f"Subdomain enumeration completed. Found {len(discovered_subdomains)} subdomains")
        
        # Extract just the subdomain part for each discovered full domain
        formatted_results = {
            'total_found': len(discovered_subdomains),
            'subdomains': discovered_subdomains,
            'domain': self.domain
        }
        
        return formatted_results
