import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

class MonitorSchedule(Base, TimestampMixin):
    __tablename__ = "monitor_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    frequency: Mapped[str] = mapped_column(String(50))  # daily, weekly, monthly
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset = relationship("Asset", back_populates="schedules")
    alerts = relationship("Alert", back_populates="schedule", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    schedule_id: Mapped[str] = mapped_column(ForeignKey("monitor_schedules.id", ondelete="CASCADE"), index=True)
    alert_type: Mapped[str] = mapped_column(String(80))  # e.g. subdomain_drift, cert_expiry
    severity: Mapped[str] = mapped_column(String(20))    # critical, high, medium, low
    message: Mapped[str] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    schedule = relationship("MonitorSchedule", back_populates="alerts")
