
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel
from app.timeline import build_timeline
from app.detector import detect_suspicious_logins
from app.attack_graph import build_attack_graph

app = FastAPI(
    title="PHANTOMTRACE",
    description="Evidence-Driven Predictive SOC Intelligence",
    version="0.2.0",
)


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    source_ip: str
    username: Optional[str] = None


class DetectionRequest(BaseModel):
    events: list[SecurityEvent]


@app.get("/")
def home():
    return {
        "project": "PHANTOMTRACE",
        "status": "running",
        "message": "SOC intelligence engine is online",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/detect")
def detect(request: DetectionRequest):
    events = [
        event.model_dump()
        for event in request.events
    ]

    alerts = detect_suspicious_logins(events)

    return {
        "events_analyzed": len(events),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }
@app.post("/timeline")
def create_timeline(request: DetectionRequest):
    events = [
        event.model_dump()
        for event in request.events
    ]

    return build_timeline(events)
@app.post("/attack-graph")
def create_attack_graph(request: DetectionRequest):
    events = [
        event.model_dump()
        for event in request.events
    ]

    return build_attack_graph(events)

@app.post("/investigate")
def investigate(request: DetectionRequest):
    events = [
        event.model_dump()
        for event in request.events
    ]

    alerts = detect_suspicious_logins(events)
    timeline = build_timeline(events)
    attack_graph = build_attack_graph(events)

    return {
        "investigation_status": "completed",
        "events_analyzed": len(events),
        "alerts_generated": len(alerts),
        "alerts": alerts,
        "timeline": timeline,
        "attack_graph": attack_graph,
        "assessment": {
            "finding": (
                "Repeated failed logins detected"
                if alerts
                else "No configured detection rule matched"
            ),
            "confirmed_attack": False,
            "limitations": [
                "Only the configured repeated-login rule is evaluated",
                "Shared source IP is a candidate relationship, "
                "not proof of causation",
                "No predictive model is active yet"
            ]
        }
    }
