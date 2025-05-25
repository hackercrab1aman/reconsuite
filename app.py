import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Import reconnaissance modules
from modules.dns_recon import DNSRecon
from modules.whois_lookup import WHOISLookup
from modules.subdomain_enum import SubdomainEnumerator
from modules.port_scanner import PortScanner
from modules.directory_discovery import DirectoryDiscovery
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.header_analyzer import HeaderAnalyzer
from modules.tech_detector import TechDetector
from modules.utils import validate_domain, sanitize_input

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///recon.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

with app.app_context():
    # Import models here to avoid circular imports
    import models
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target = sanitize_input(request.form.get('target', ''))
        scan_options = {
            'dns_recon': request.form.get('dns_recon') == 'on',
            'whois_lookup': request.form.get('whois_lookup') == 'on',
            'subdomain_enum': request.form.get('subdomain_enum') == 'on',
            'port_scan': request.form.get('port_scan') == 'on',
            'directory_discovery': request.form.get('directory_discovery') == 'on',
            'vulnerability_scan': request.form.get('vulnerability_scan') == 'on',
            'header_analysis': request.form.get('header_analysis') == 'on',
            'tech_detection': request.form.get('tech_detection') == 'on',
        }
        
        # Validate domain
        if not validate_domain(target):
            flash('Invalid domain name. Please enter a valid domain.', 'danger')
            return render_template('scan.html')
        
        # Store scan details in session
        scan_id = datetime.now().strftime('%Y%m%d%H%M%S')
        session['current_scan'] = {
            'id': scan_id,
            'target': target,
            'options': scan_options,
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return redirect(url_for('results', scan_id=scan_id))
    
    return render_template('scan.html')

@app.route('/results/<scan_id>')
def results(scan_id):
    scan_info = session.get('current_scan', {})
    if not scan_info or scan_info.get('id') != scan_id:
        flash('Invalid scan ID or session expired', 'danger')
        return redirect(url_for('scan'))
    
    return render_template('results.html', scan_info=scan_info)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint to run scans asynchronously with better timeout handling"""
    scan_info = session.get('current_scan', {})
    if not scan_info:
        return jsonify({'error': 'No active scan session'}), 400
    
    target = scan_info.get('target')
    options = scan_info.get('options', {})
    results = {}
    
    try:
        # Run selected scans based on options with individual error handling
        if options.get('dns_recon'):
            try:
                dns_recon = DNSRecon(target)
                results['dns_recon'] = dns_recon.run()
            except Exception as e:
                logger.error(f"DNS Recon error: {str(e)}")
                results['dns_recon'] = {'error': 'DNS reconnaissance failed', 'details': str(e)}
        
        if options.get('whois_lookup'):
            try:
                whois_lookup = WHOISLookup(target)
                results['whois_lookup'] = whois_lookup.run()
            except Exception as e:
                logger.error(f"WHOIS Lookup error: {str(e)}")
                results['whois_lookup'] = {'error': 'WHOIS lookup failed', 'details': str(e)}
        
        if options.get('subdomain_enum'):
            try:
                subdomain_enum = SubdomainEnumerator(target)
                results['subdomain_enum'] = subdomain_enum.run()
            except Exception as e:
                logger.error(f"Subdomain Enum error: {str(e)}")
                results['subdomain_enum'] = {'error': 'Subdomain enumeration failed', 'details': str(e)}
        
        if options.get('port_scan'):
            try:
                # Use socket scan instead of nmap for better reliability
                port_scan = PortScanner(target, use_nmap=False, timeout=1)
                results['port_scan'] = port_scan.run()
            except Exception as e:
                logger.error(f"Port Scan error: {str(e)}")
                results['port_scan'] = {'error': 'Port scanning failed', 'details': str(e)}
        
        if options.get('directory_discovery'):
            try:
                directory_discovery = DirectoryDiscovery(target, max_workers=3)  # Limit concurrency
                results['directory_discovery'] = directory_discovery.run()
            except Exception as e:
                logger.error(f"Directory Discovery error: {str(e)}")
                results['directory_discovery'] = {'error': 'Directory discovery failed', 'details': str(e)}
        
        if options.get('vulnerability_scan'):
            try:
                vulnerability_scan = VulnerabilityScanner(target, max_pages=5)  # Limit scan depth
                results['vulnerability_scan'] = vulnerability_scan.run()
            except Exception as e:
                logger.error(f"Vulnerability Scan error: {str(e)}")
                results['vulnerability_scan'] = {'error': 'Vulnerability scanning failed', 'details': str(e)}
        
        if options.get('header_analysis'):
            try:
                header_analyzer = HeaderAnalyzer(target)
                results['header_analysis'] = header_analyzer.run()
            except Exception as e:
                logger.error(f"Header Analysis error: {str(e)}")
                results['header_analysis'] = {'error': 'Header analysis failed', 'details': str(e)}
        
        if options.get('tech_detection'):
            try:
                tech_detector = TechDetector(target)
                results['tech_detection'] = tech_detector.run()
            except Exception as e:
                logger.error(f"Tech Detection error: {str(e)}")
                results['tech_detection'] = {'error': 'Technology detection failed', 'details': str(e)}
        
        # Store results in session
        scan_info['results'] = results
        scan_info['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        session['current_scan'] = scan_info
        
        # Save scan to database
        try:
            with app.app_context():
                from models import ScanResult
                
                new_scan = ScanResult(
                    scan_id=scan_info['id'],
                    target=target,
                    options=str(options),
                    results=str(results),
                    start_time=scan_info['start_time'],
                    end_time=scan_info['end_time']
                )
                db.session.add(new_scan)
                db.session.commit()
        except Exception as db_error:
            logger.error(f"Database error: {str(db_error)}")
            # Continue even if database save fails
        
        return jsonify({
            'status': 'success',
            'results': results
        })
    
    except Exception as e:
        logger.exception("Error during scan")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/export/<scan_id>', methods=['GET'])
def export_results(scan_id):
    """API endpoint to export scan results in JSON format"""
    scan_info = session.get('current_scan', {})
    if not scan_info or scan_info.get('id') != scan_id:
        return jsonify({'error': 'Invalid scan ID or session expired'}), 400
    
    return jsonify({
        'scan_id': scan_id,
        'target': scan_info.get('target'),
        'start_time': scan_info.get('start_time'),
        'end_time': scan_info.get('end_time'),
        'options': scan_info.get('options'),
        'results': scan_info.get('results')
    })

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

# Ethical usage notice route
@app.route('/ethics')
def ethics():
    return render_template('about.html', scroll_to='ethics')
