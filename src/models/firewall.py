from sqlalchemy import Column, Integer, String, Boolean, DateTime, BigInteger, JSON, ARRAY, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class Firewall(Base):
    __tablename__ = "firewalls"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    vendor = Column(String(50))  # 'cisco', 'paloalto'
    ip_address = Column(String(15), nullable=False)
    api_key_encrypted = Column(String(500))
    last_sync = Column(DateTime)
    created_at = Column(DateTime, default=datetime.now)
    
    rules = relationship("FirewallRule", back_populates="firewall")

class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    
    id = Column(Integer, primary_key=True)
    firewall_id = Column(Integer, ForeignKey("firewalls.id"), nullable=False)
    rule_id = Column(String(255), nullable=False)
    rule_name = Column(String(500), nullable=False)
    source_ip = Column(String(50))
    destination_ip = Column(String(50))
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(20))
    action = Column(String(20))
    enabled = Column(Boolean, default=True)
    hit_count = Column(BigInteger, default=0)
    last_hit = Column(DateTime)
    created_at = Column(DateTime)
    synced_at = Column(DateTime)
    raw_config = Column(JSON)
    
    firewall = relationship("Firewall", back_populates="rules")

class RuleAnalysis(Base):
    __tablename__ = "rule_analysis"
    
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("firewall_rules.id"))
    analysis_type = Column(String(50))  # redundant, unused, conflict
    confidence_score = Column(Integer)  # 0-100
    related_rules = Column(ARRAY(Integer))
    recommendation = Column(String(1000))
    status = Column(String(20), default='pending')
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime)

class AuditLog(Base):
    __tablename__ = "audit_log"
    
    id = Column(Integer, primary_key=True)
    action = Column(String(255))
    rule_id = Column(Integer)
    user_id = Column(String(255))
    details = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)
