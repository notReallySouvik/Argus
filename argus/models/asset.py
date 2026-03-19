from typing import List, Optional
from pydantic import BaseModel, Field


class Service(BaseModel):
    port: int
    protocol: str
    name: Optional[str] = None

class ProbeResult(BaseModel):
    http_url: Optional[str] = None
    https_url: Optional[str] = None
    preferred_url: Optional[str] = None
    redirect_chain_detected: bool = False

class WebMetadata(BaseModel):
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    body_preview: Optional[str] = None

class Asset(BaseModel):
    host: str
    asset_type: str = "subdomain"
    ip_addresses: List[str] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)
    web: Optional[WebMetadata] = None
    probe: Optional[ProbeResult] = None
    risk_signals: List[str] = Field(default_factory=list)
    confidence: float = 0.0