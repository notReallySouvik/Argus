from typing import List, Optional
from pydantic import BaseModel, Field


class Service(BaseModel):
    port: int
    protocol: str
    name: Optional[str] = None


class WebMetadata(BaseModel):
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)


class Asset(BaseModel):
    host: str
    asset_type: str = "subdomain"
    ip_addresses: List[str] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)
    web: Optional[WebMetadata] = None
    risk_signals: List[str] = Field(default_factory=list)
    confidence: float = 0.0