from datetime import datetime
from pydantic import BaseModel, Field

class MonitorScheduleCreate(BaseModel):
    asset_id: str
    frequency: str = Field(..., description="Monitoring interval: daily, weekly, monthly")
    enabled: bool = True


class AlertResponse(BaseModel):
    id: str
    schedule_id: str
    alert_type: str
    severity: str
    message: str
    acknowledged: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class MonitorScheduleResponse(BaseModel):
    id: str
    asset_id: str
    frequency: str
    enabled: bool
    last_run: datetime | None
    created_at: datetime
    updated_at: datetime
    alerts: list[AlertResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}
