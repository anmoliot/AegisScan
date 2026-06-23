import uuid
from datetime import datetime
from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(253), index=True)
    status: Mapped[str] = mapped_column(String(50))  # e.g., active, archived
    exposure_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    subdomains = relationship("Subdomain", back_populates="asset", cascade="all, delete-orphan")
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan")
    apis = relationship("AssetApi", back_populates="asset", cascade="all, delete-orphan")
    schedules = relationship("MonitorSchedule", back_populates="asset", cascade="all, delete-orphan")
    graph_nodes = relationship("GraphNode", back_populates="asset", cascade="all, delete-orphan")
    graph_edges = relationship("GraphEdge", back_populates="asset", cascade="all, delete-orphan")


class Subdomain(Base, TimestampMixin):
    __tablename__ = "subdomains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, default=list)  # list of IPs
    status: Mapped[str] = mapped_column(String(50))  # e.g., active, inactive
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    asset = relationship("Asset", back_populates="subdomains")
    services = relationship("Service", back_populates="subdomain", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="subdomain", cascade="all, delete-orphan")


class Certificate(Base, TimestampMixin):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    subject: Mapped[str] = mapped_column(String(253))
    issuer: Mapped[str] = mapped_column(String(253))
    serial: Mapped[str | None] = mapped_column(String(100), nullable=True)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    asset = relationship("Asset", back_populates="certificates")


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    subdomain_id: Mapped[str] = mapped_column(ForeignKey("subdomains.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20))  # TCP, UDP
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    technology: Mapped[str | None] = mapped_column(String(100), nullable=True)

    subdomain = relationship("Subdomain", back_populates="services")
    technologies = relationship("Technology", back_populates="service", cascade="all, delete-orphan")


class Technology(Base, TimestampMixin):
    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    subdomain_id: Mapped[str | None] = mapped_column(ForeignKey("subdomains.id", ondelete="CASCADE"), index=True, nullable=True)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    category: Mapped[str | None] = mapped_column(String(50), nullable=True)

    subdomain = relationship("Subdomain", back_populates="technologies")
    service = relationship("Service", back_populates="technologies")


class AssetApi(Base, TimestampMixin):
    __tablename__ = "asset_apis"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    api_inventory_id: Mapped[str] = mapped_column(ForeignKey("api_inventories.id", ondelete="CASCADE"), index=True)

    asset = relationship("Asset", back_populates="apis")
