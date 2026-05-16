"""
SQLAlchemy Database Models
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Text
from sqlalchemy.sql import func
from database import Base


class ScanResult(Base):
    """
    Store URL scan results
    """
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False, index=True)
    prediction = Column(String(50), nullable=False)  # 'phishing' or 'legitimate'
    confidence = Column(Float, nullable=False)
    risk_score = Column(Integer, nullable=False)  # 0-100
    ml_score = Column(Float, nullable=False)

    # Features
    features = Column(JSON, nullable=True)

    # Threat Intelligence
    virustotal_data = Column(JSON, nullable=True)
    urlhaus_data = Column(JSON, nullable=True)
    whois_data = Column(JSON, nullable=True)
    dns_data = Column(JSON, nullable=True)
    typosquatting_data = Column(JSON, nullable=True)

    # Metadata
    scan_timestamp = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)

    def __repr__(self):
        return f"<ScanResult(url='{self.url}', prediction='{self.prediction}', risk_score={self.risk_score})>"


class User(Base):
    """
    User model (for future authentication)
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<User(email='{self.email}')>"
