from pydantic import BaseModel
from typing import Any

class EventIn(BaseModel):
    data: dict[str, Any]

class StatusIn(BaseModel):
    status: str
