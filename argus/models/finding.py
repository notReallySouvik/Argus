from typing import Optional
from pydantic import BaseModel


class Finding(BaseModel):
    asset: str
    title: str
    severity: str = "info"
    description: str
    signal: str
    confidence: float = 0.5
    recommendation: Optional[str] = None