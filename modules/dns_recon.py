import dns.resolver
import logging
from .utils import rate_limit

class DNSRecon:
    """Module for DNS reconnaissance and record lookups"""
    
    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0
        self.logger = logging.getLogger(__name__)
        
        # Common DNS record types to query
        self.record_types = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR'
        ]
    
    @rate_limit(1)  # 1 second delay between DNS queries
    def query_record(self, record_type):
        """Query a specific DNS record type"""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Domain {self.domain} does not exist")
            return []
        except dns.exception.Timeout:
            self.logger.warning(f"Timeout querying {record_type} records for {self.domain}")
            return []
        except Exception as e:
            self.logger.error(f"Error querying {record_type} records: {str(e)}")
            return []
    
    def run(self):
        """Run DNS reconnaissance on the target domain"""
        self.logger.info(f"Starting DNS reconnaissance for {self.domain}")
        
        results = {}
        for record_type in self.record_types:
            self.logger.debug(f"Querying {record_type} records")
            record_results = self.query_record(record_type)
            if record_results:
                results[record_type] = record_results
        
        # Additional info: Check if domain has DNSSEC
        try:
            has_dnssec = False
            dnskey_results = self.resolver.resolve(self.domain, 'DNSKEY')
            if dnskey_results:
                has_dnssec = True
        except Exception:
            has_dnssec = False
        
        results['has_dnssec'] = has_dnssec
        
        self.logger.info(f"DNS reconnaissance for {self.domain} completed")
        return results
