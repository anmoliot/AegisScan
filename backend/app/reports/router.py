from fastapi import APIRouter, HTTPException, Response
from jinja2 import Environment, PackageLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.deps import CurrentUser, DbSession
from app.scans.models import AuditEvent, Scan

router = APIRouter(prefix="/reports", tags=["reports"])
templates = Environment(loader=PackageLoader("app.reports"), autoescape=select_autoescape(["html"]))


@router.get("/{scan_id}.html")
async def download_report(scan_id: str, user: CurrentUser, session: DbSession):
    scan = await session.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
                                .options(selectinload(Scan.findings)))
    if not scan:
        raise HTTPException(404, "Scan not found")
    html = templates.get_template("report.html").render(scan=scan, findings=scan.findings)
    session.add(AuditEvent(user_id=user.id, event_type="report.downloaded", object_id=scan.id))
    await session.commit()
    return Response(html, media_type="text/html", headers={
        "Content-Disposition": f'attachment; filename="aegisscan-{scan.id}.html"',
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
        "X-Content-Type-Options": "nosniff",
    })
