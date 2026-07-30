from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import os
from dotenv import load_dotenv
from datetime import datetime

from src.database import get_db
from src.models.firewall import Firewall, FirewallRule, RuleAnalysis

load_dotenv()

app = FastAPI(
    title="Firewall Rule Manager API",
    description="Intelligent firewall rule analysis and optimization",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "service": "firewall-rule-manager"
    }

@app.get("/api/v1/firewalls")
async def get_firewalls(db: Session = Depends(get_db)):
    """List all managed firewalls"""
    firewalls = db.query(Firewall).all()
    return {
        "count": len(firewalls),
        "data": [
            {
                "id": f.id,
                "name": f.name,
                "vendor": f.vendor,
                "ip_address": f.ip_address,
                "last_sync": f.last_sync
            }
            for f in firewalls
        ]
    }

@app.post("/api/v1/firewalls")
async def create_firewall(
    name: str,
    vendor: str,
    ip_address: str,
    db: Session = Depends(get_db)
):
    """Add a new firewall"""
    new_firewall = Firewall(name=name, vendor=vendor, ip_address=ip_address)
    db.add(new_firewall)
    db.commit()
    db.refresh(new_firewall)
    
    return {
        "status": "created",
        "id": new_firewall.id,
        "name": new_firewall.name
    }

@app.get("/api/v1/rules")
async def get_rules(
    firewall_id: int = None,
    db: Session = Depends(get_db)
):
    """Retrieve firewall rules"""
    query = db.query(FirewallRule)
    
    if firewall_id:
        query = query.filter(FirewallRule.firewall_id == firewall_id)
    
    rules = query.limit(1000).all()
    
    return {
        "count": len(rules),
        "data": [
            {
                "id": r.id,
                "rule_name": r.rule_name,
                "action": r.action,
                "enabled": r.enabled,
                "hit_count": r.hit_count,
                "source_ip": r.source_ip,
                "destination_ip": r.destination_ip
            }
            for r in rules
        ]
    }

@app.get("/api/v1/analysis/summary")
async def get_analysis_summary(db: Session = Depends(get_db)):
    """Get summary of rule analysis"""
    total_rules = db.query(FirewallRule).count()
    unused = db.query(RuleAnalysis).filter(RuleAnalysis.analysis_type == 'unused').count()
    redundant = db.query(RuleAnalysis).filter(RuleAnalysis.analysis_type == 'redundant').count()
    conflicts = db.query(RuleAnalysis).filter(RuleAnalysis.analysis_type == 'conflict').count()
    
    return {
        "total_rules": total_rules,
        "unused_rules": unused,
        "redundant_rules": redundant,
        "conflicting_rules": conflicts,
        "potential_savings": f"Reduce by ~{(unused + redundant) * 5}% with optimization"
    }

@app.post("/api/v1/trigger-sync")
async def trigger_sync(firewall_id: int, db: Session = Depends(get_db)):
    """Trigger rule synchronization from a firewall"""
    firewall = db.query(Firewall).filter(Firewall.id == firewall_id).first()
    
    if not firewall:
        raise HTTPException(status_code=404, detail="Firewall not found")
    
    firewall.last_sync = datetime.now()
    db.commit()
    
    return {
        "status": "sync_initiated",
        "firewall_id": firewall_id,
        "firewall_name": firewall.name,
        "message": "Rule synchronization started in background"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
