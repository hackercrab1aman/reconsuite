import socket
import logging
import concurrent.futures
import nmap
from .utils import rate_limit, is_valid_ip

class PortScanner:
    """Module for port scanning"""
    
    def __init__(self, target, ports=None, timeout=1, use_nmap=True):
        self.target = target
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
        self.use_nmap = use_nmap
        
        # Resolve hostname to IP if target is a domain
        try:
            if not is_valid_ip(target):
                self.ip = socket.gethostbyname(target)
            else:
                self.ip = target
        except socket.gaierror:
            self.logger.error(f"Could not resolve hostname: {target}")
            self.ip = None
        
        # Default ports to scan if none provided
        self.ports = ports or [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
    
    @rate_limit(0.1)  # 100ms delay between port checks to avoid detection
    def check_port(self, port):
        """Check if a port is open using socket connection"""
        if not self.ip:
            return None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                service = self._get_service_name(port)
                self.logger.debug(f"Port {port} is open on {self.target}")
                return {
                    'port': port,
                    'status': 'open',
                    'service': service
                }
            sock.close()
        except Exception as e:
            self.logger.debug(f"Error checking port {port}: {str(e)}")
        
        return None
    
    def _get_service_name(self, port):
        """Get the service name for a given port"""
        try:
            return socket.getservbyport(port)
        except (socket.error, OSError):
            return 'unknown'
    
    def scan_with_nmap(self):
        """Perform port scanning using python-nmap with better timeout handling"""
        if not self.ip:
            return []
        
        try:
            scanner = nmap.PortScanner()
            port_range = ','.join(map(str, self.ports))
            self.logger.info(f"Starting Nmap scan on {self.ip} for ports {port_range}")
            
            # Run Nmap scan with faster timing and no version detection to avoid timeouts
            # Use -T4 for faster timing template and reduce timeout to 2s
            scanner.scan(self.ip, port_range, arguments='-T5 --host-timeout 10s --max-retries 1 --min-rate 1000')
            
            results = []
            if self.ip in scanner.all_hosts():
                for proto in scanner[self.ip].all_protocols():
                    ports = sorted(scanner[self.ip][proto].keys())
                    for port in ports:
                        port_info = scanner[self.ip][proto][port]
                        results.append({
                            'port': port,
                            'status': port_info['state'],
                            'service': port_info['name'] if 'name' in port_info else self._get_service_name(port),
                            'version': 'not detected' # Version detection disabled for speed
                        })
            
            return results
        except Exception as e:
            self.logger.error(f"Error during Nmap scan: {str(e)}")
            return []
    
    def scan_with_socket(self):
        """Perform port scanning using socket connections"""
        if not self.ip:
            return []
        
        open_ports = []
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.check_port, port) for port in self.ports]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports
    
    def run(self):
        """Run port scan using selected method"""
        if not self.ip:
            return {
                'error': 'Could not resolve hostname',
                'target': self.target
            }
        
        self.logger.info(f"Starting port scan for {self.target} ({self.ip})")
        
        if self.use_nmap:
            try:
                results = self.scan_with_nmap()
                if not results:  # Fallback to socket scan if nmap fails
                    self.logger.warning("Nmap scan failed, falling back to socket scan")
                    results = self.scan_with_socket()
            except ImportError:
                self.logger.warning("python-nmap not available, using socket scan")
                results = self.scan_with_socket()
        else:
            results = self.scan_with_socket()
        
        self.logger.info(f"Port scan completed. Found {len(results)} open ports")
        
        # Format the results
        return {
            'target': self.target,
            'ip': self.ip,
            'total_open_ports': len(results),
            'ports': results
        }
