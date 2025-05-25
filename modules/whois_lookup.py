import whois
import logging
from datetime import datetime
from .utils import rate_limit

class WHOISLookup:
    """Module for WHOIS information gathering"""
    
    def __init__(self, domain):
        self.domain = domain
        self.logger = logging.getLogger(__name__)
    
    @rate_limit(2)  # 2 second delay between WHOIS lookups
    def lookup(self):
        """Perform WHOIS lookup for the domain"""
        try:
            self.logger.info(f"Performing WHOIS lookup for {self.domain}")
            w = whois.whois(self.domain)
            return w
        except Exception as e:
            self.logger.error(f"Error during WHOIS lookup: {str(e)}")
            return None
    
    def _format_date(self, date_obj):
        """Format date object to string"""
        if date_obj is None:
            return "Unknown"
        
        if isinstance(date_obj, list):
            if not date_obj:
                return "Unknown"
            date_obj = date_obj[0]
        
        if isinstance(date_obj, datetime):
            return date_obj.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return str(date_obj)
    
    def _extract_important_whois_info(self, whois_data):
        """Extract important information from WHOIS data"""
        if not whois_data:
            return {}
        
        # Format WHOIS data into a more usable structure
        formatted_data = {
            'domain_name': whois_data.domain_name,
            'registrar': whois_data.registrar,
            'creation_date': self._format_date(whois_data.creation_date),
            'expiration_date': self._format_date(whois_data.expiration_date),
            'updated_date': self._format_date(whois_data.updated_date),
            'name_servers': whois_data.name_servers if isinstance(whois_data.name_servers, list) else [whois_data.name_servers] if whois_data.name_servers else [],
            'status': whois_data.status if isinstance(whois_data.status, list) else [whois_data.status] if whois_data.status else [],
            'emails': whois_data.emails if isinstance(whois_data.emails, list) else [whois_data.emails] if whois_data.emails else [],
            'dnssec': whois_data.dnssec if hasattr(whois_data, 'dnssec') else "Unknown",
            'org': whois_data.org if hasattr(whois_data, 'org') else "Unknown",
            'country': whois_data.country if hasattr(whois_data, 'country') else "Unknown",
        }
        
        # Calculate domain age in days
        try:
            if isinstance(whois_data.creation_date, list):
                creation_date = whois_data.creation_date[0]
            else:
                creation_date = whois_data.creation_date
                
            if isinstance(creation_date, datetime):
                domain_age = (datetime.now() - creation_date).days
                formatted_data['domain_age_days'] = domain_age
        except (TypeError, AttributeError):
            formatted_data['domain_age_days'] = "Unknown"
        
        return formatted_data
    
    def run(self):
        """Run WHOIS lookup and extract important information"""
        whois_data = self.lookup()
        if whois_data:
            return self._extract_important_whois_info(whois_data)
        else:
            return {
                'error': 'WHOIS lookup failed',
                'domain_name': self.domain
            }
