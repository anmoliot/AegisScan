from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field, HttpUrl

class ApiDiscoveryRequest(BaseModel):
    target_url: HttpUrl
    asset_id: str | None = None


class ApiEndpointResponse(BaseModel):
    id: str
    inventory_id: str
    method: str
    path: str
    auth_required: bool
    parameters: list[dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ApiInventoryResponse(BaseModel):
    id: str
    asset_id: str | None
    url: str
    api_type: str
    schema_definition: str | None
    endpoints_count: int
    created_at: datetime
    updated_at: datetime
    endpoints: list[ApiEndpointResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ApiDiscoveryResponse(BaseModel):
    success: bool
    message: str
    inventory: ApiInventoryResponse | None = None
