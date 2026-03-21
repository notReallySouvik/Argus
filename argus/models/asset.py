from typing import List, Optional
from pydantic import BaseModel, Field


class DiscoverySource(BaseModel):
    name: str
    confidence: float = 0.5


class ProbeResult(BaseModel):
    http_url: Optional[str] = None
    https_url: Optional[str] = None
    preferred_url: Optional[str] = None
    redirect_chain_detected: bool = False


class ServiceExposure(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    classification: Optional[str] = None
    banner: Optional[str] = None


class Relationship(BaseModel):
    relationship_type: str
    source: str
    target: str


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
    services: List[ServiceExposure] = Field(default_factory=list)
    web: Optional[WebMetadata] = None
    probe: Optional[ProbeResult] = None
    risk_signals: List[str] = Field(default_factory=list)
    discovery_sources: List[DiscoverySource] = Field(default_factory=list)
    relationships: List[Relationship] = Field(default_factory=list)
    context_tags: List[str] = Field(default_factory=list)
    exposure_summary: Optional[str] = None
    live: bool = False
    confidence: float = 0.0