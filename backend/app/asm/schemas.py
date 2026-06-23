from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import re

class AssetCreate(BaseModel):
    domain: str = Field(..., description="Root domain of the asset (e.g., example.com)")

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        # Simple domain validation
        v = v.strip().lower()
        if not re.match(r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}$", v):
            raise ValueError("Invalid domain name format")
        return v


class TechnologyResponse(BaseModel):
    id: str
    subdomain_id: str | None
    service_id: str | None
    name: str
    version: str | None
    category: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ServiceResponse(BaseModel):
    id: str
    subdomain_id: str
    port: int
    protocol: str
    banner: str | None
    technology: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SubdomainResponse(BaseModel):
    id: str
    asset_id: str
    hostname: str
    ip_addresses: list[str]
    status: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    services: list[ServiceResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class CertificateResponse(BaseModel):
    id: str
    asset_id: str
    subject: str
    issuer: str
    serial: str | None
    not_before: datetime
    not_after: datetime
    fingerprint: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssetResponse(BaseModel):
    id: str
    user_id: str
    domain: str
    status: str
    exposure_score: float
    last_scanned: datetime | None
    created_at: datetime
    updated_at: datetime
    subdomains: list[SubdomainResponse] = Field(default_factory=list)
    certificates: list[CertificateResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}
