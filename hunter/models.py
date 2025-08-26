from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Literal

IOCType = Literal[
    "ipv4-addr", "ipv6-addr", "domain", "url", "file-sha256", "file-md5", "file-sha1"
]


class IOC(BaseModel):
    type: IOCType
    value: str
    source: str
    first_seen: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    context: dict = Field(default_factory=dict)  # enrichissements
    score: Optional[int] = None  # 0..100
