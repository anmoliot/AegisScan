import uuid
from typing import Any
from sqlalchemy import Boolean, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

class ApiInventory(Base, TimestampMixin):
    __tablename__ = "api_inventories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=True)
    url: Mapped[str] = mapped_column(String(2048))
    api_type: Mapped[str] = mapped_column(String(50))  # e.g., REST, GraphQL
    schema_definition: Mapped[str | None] = mapped_column(Text, nullable=True)
    endpoints_count: Mapped[int] = mapped_column(Integer, default=0)

    endpoints = relationship("ApiEndpoint", back_populates="inventory", cascade="all, delete-orphan")


class ApiEndpoint(Base, TimestampMixin):
    __tablename__ = "api_endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    inventory_id: Mapped[str] = mapped_column(ForeignKey("api_inventories.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(10))  # GET, POST, etc.
    path: Mapped[str] = mapped_column(String(2048))
    auth_required: Mapped[bool] = mapped_column(Boolean, default=True)
    parameters: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    inventory = relationship("ApiInventory", back_populates="endpoints")
