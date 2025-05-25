from app import db
from datetime import datetime

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(50), unique=True, nullable=False)
    target = db.Column(db.String(255), nullable=False)
    options = db.Column(db.Text, nullable=False)
    results = db.Column(db.Text, nullable=True)
    start_time = db.Column(db.String(50), nullable=False)
    end_time = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanResult {self.scan_id} - {self.target}>'

class DomainInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    dns_records = db.Column(db.Text, nullable=True)
    whois_info = db.Column(db.Text, nullable=True)
    subdomains = db.Column(db.Text, nullable=True)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<DomainInfo {self.domain}>'

class VulnerabilityRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    vulnerability_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    remediation = db.Column(db.Text, nullable=True)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<VulnerabilityRecord {self.vulnerability_type} - {self.target}>'
