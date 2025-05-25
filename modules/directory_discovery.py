import requests
import logging
import concurrent.futures
from urllib.parse import urljoin
from .utils import rate_limit, sanitize_url

class DirectoryDiscovery:
    """Module for directory and file discovery on web servers"""
    
    def __init__(self, target, wordlist=None, extensions=None, max_workers=5, timeout=5):
        self.target = sanitize_url(target)
        self.logger = logging.getLogger(__name__)
        self.max_workers = max_workers
        self.timeout = timeout
        
        # Use default wordlist if none provided
        self.wordlist = wordlist or self._get_default_wordlist()
        
        # Use default extensions if none provided
        self.extensions = extensions or ['.php', '.html', '.txt', '.xml', '.json', '.bak', '.old', '.backup']
        
        # User agent to mimic a browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def _get_default_wordlist(self):
        """Get a default wordlist of common directories and files"""
        return [
            'admin', 'administrator', 'backup', 'backups', 'config', 'conf', 'db',
            'database', 'login', 'wp-admin', 'cms', 'app', 'api', 'upload', 'uploads',
            'download', 'downloads', 'content', 'assets', 'img', 'images', 'css', 'js',
            'test', 'temp', 'tmp', 'dev', 'development', 'stage', 'staging', 'prod',
            'production', 'secret', 'secrets', 'private', 'public', 'src', 'source',
            'log', 'logs', 'admin.php', 'index.php', 'info.php', 'phpinfo.php',
            'robots.txt', 'sitemap.xml', '.git', '.env', '.htaccess', '.DS_Store',
            'wp-config.php', 'config.php', 'settings.php', 'home', 'default', 'about',
            'contact', 'login.php', 'register', 'signup', 'reset', 'password', 'cgi-bin',
            'server-status', 'server-info', 'status', 'forum', 'forums', 'blog', 'cart',
            'checkout', 'account', 'members', 'users', 'user', 'customer', 'customers',
            'web', 'portal', 'site', 'sites'
        ]
    
    @rate_limit(0.2)  # 200ms delay between requests to avoid detection
    def check_path(self, path):
        """Check if a path exists on the target server"""
        url = urljoin(self.target, path)
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            
            # Check the response status code
            if 200 <= response.status_code < 300:
                self.logger.info(f"Found: {url} ({response.status_code})")
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'type': response.headers.get('Content-Type', 'unknown')
                }
            elif response.status_code == 403:  # Forbidden but exists
                self.logger.info(f"Found (Forbidden): {url} ({response.status_code})")
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'type': response.headers.get('Content-Type', 'unknown')
                }
            
        except requests.RequestException as e:
            self.logger.debug(f"Error checking {url}: {str(e)}")
        
        return None
    
    def run(self):
        """Run directory discovery scan"""
        self.logger.info(f"Starting directory discovery for {self.target}")
        discovered_paths = []
        all_paths = []
        
        # Generate paths with extensions
        for word in self.wordlist:
            all_paths.append(word)  # Check the word itself (could be a directory)
            for ext in self.extensions:
                if not word.endswith(ext):  # Avoid duplicates
                    all_paths.append(f"{word}{ext}")
        
        self.logger.info(f"Generated {len(all_paths)} paths to check")
        
        # Use ThreadPoolExecutor for parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.check_path, path) for path in all_paths]
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered_paths.append(result)
        
        self.logger.info(f"Directory discovery completed. Found {len(discovered_paths)} paths")
        
        # Sort results by status code, then by URL
        discovered_paths.sort(key=lambda x: (x['status'], x['url']))
        
        return {
            'target': self.target,
            'total_found': len(discovered_paths),
            'paths': discovered_paths
        }
