import os
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc

db = SQLAlchemy()

class ScanRecord(db.Model):
    __tablename__ = 'scan_records'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False, unique=True)
    label = db.Column(db.String(20), nullable=False)  # 'malicious' or 'benign'
    confidence = db.Column(db.Float, nullable=False)
    algorithm = db.Column(db.String(20), nullable=False)
    entropy = db.Column(db.Float, nullable=True)
    strings_count = db.Column(db.Integer, nullable=True)
    strings_mean_len = db.Column(db.Float, nullable=True)
    strings_std_len = db.Column(db.Float, nullable=True)
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_ip = db.Column(db.String(45), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_size': self.file_size,
            'sha256': self.sha256,
            'label': self.label,
            'confidence': self.confidence,
            'algorithm': self.algorithm,
            'entropy': self.entropy,
            'strings_count': self.strings_count,
            'strings_mean_len': self.strings_mean_len,
            'strings_std_len': self.strings_std_len,
            'scan_timestamp': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'user_ip': self.user_ip
        }

class ModelPerformance(db.Model):
    __tablename__ = 'model_performance'
    
    id = db.Column(db.Integer, primary_key=True)
    algorithm = db.Column(db.String(20), nullable=False)
    accuracy = db.Column(db.Float, nullable=False)
    precision = db.Column(db.Float, nullable=False)
    recall = db.Column(db.Float, nullable=False)
    f1_score = db.Column(db.Float, nullable=False)
    training_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'algorithm': self.algorithm,
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'training_timestamp': self.training_timestamp.isoformat() if self.training_timestamp else None
        }

def init_database(app):
    """Initialize the database with the Flask app"""
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

def save_scan_record(filename, file_size, sha256, label, confidence, algorithm, 
                    entropy=None, strings_count=None, strings_mean_len=None, 
                    strings_std_len=None, user_ip=None):
    """Save a scan record to the database"""
    # Check if record already exists (same SHA256)
    existing = ScanRecord.query.filter_by(sha256=sha256).first()
    if existing:
        # Update existing record
        existing.scan_timestamp = datetime.utcnow()
        existing.user_ip = user_ip
        db.session.commit()
        return existing
    
    # Create new record
    record = ScanRecord(
        filename=filename,
        file_size=file_size,
        sha256=sha256,
        label=label,
        confidence=confidence,
        algorithm=algorithm,
        entropy=entropy,
        strings_count=strings_count,
        strings_mean_len=strings_mean_len,
        strings_std_len=strings_std_len,
        user_ip=user_ip
    )
    
    db.session.add(record)
    db.session.commit()
    return record

def get_recent_scans(limit=50):
    """Get recent scan records"""
    return ScanRecord.query.order_by(desc(ScanRecord.scan_timestamp)).limit(limit).all()

def get_scan_statistics():
    """Get overall scan statistics"""
    total_scans = ScanRecord.query.count()
    malicious_count = ScanRecord.query.filter_by(label='malicious').count()
    benign_count = ScanRecord.query.filter_by(label='benign').count()
    
    # Algorithm usage statistics
    algo_stats = db.session.query(
        ScanRecord.algorithm,
        db.func.count(ScanRecord.id).label('count')
    ).group_by(ScanRecord.algorithm).all()
    
    # Daily scan counts (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    daily_stats = (
        db.session.query(
            db.func.date(ScanRecord.scan_timestamp).label('date'),
            db.func.count(ScanRecord.id).label('count')
        )
        .filter(ScanRecord.scan_timestamp >= thirty_days_ago)
        .group_by(db.func.date(ScanRecord.scan_timestamp))
        .all()
    )
    
    return {
        'total_scans': total_scans,
        'malicious_count': malicious_count,
        'benign_count': benign_count,
        'malicious_percentage': (malicious_count / total_scans * 100) if total_scans > 0 else 0,
        'algorithm_usage': {algo: count for algo, count in algo_stats},
        'daily_scans': [{'date': str(date), 'count': count} for date, count in daily_stats]
    }
