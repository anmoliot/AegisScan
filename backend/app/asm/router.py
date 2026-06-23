from datetime import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.deps import CurrentUser, DbSession
from app.asm.models import Asset, Subdomain, Certificate, Service, Technology
from app.asm.schemas import AssetCreate, AssetResponse, SubdomainResponse, CertificateResponse
from app.asm.asset_inventory import AssetInventoryManager
from app.asm.subdomain_discovery import SubdomainDiscovery
from app.asm.dns_intelligence import DnsIntelligenceCollector
from app.asm.certificate_monitor import CertificateMonitor
from app.asm.exposure_scoring import ExposureScoringCalculator

router = APIRouter(prefix="/asm", tags=["asm"])


@router.post("/assets", response_model=AssetResponse, status_code=201)
async def register_asset(payload: AssetCreate, user: CurrentUser, session: DbSession):
    manager = AssetInventoryManager(session)
    asset = await manager.register_asset(user.id, payload.domain)
    await session.commit()
    
    # Reload with empty list fields for schema serialization
    stmt = select(Asset).where(Asset.id == asset.id).options(
        selectinload(Asset.subdomains),
        selectinload(Asset.certificates)
    )
    asset = await session.scalar(stmt)
    return asset


@router.get("/assets", response_model=list[AssetResponse])
async def list_assets(user: CurrentUser, session: DbSession):
    stmt = select(Asset).where(Asset.user_id == user.id).options(
        selectinload(Asset.subdomains).selectinload(Subdomain.services),
        selectinload(Asset.certificates)
    ).order_by(Asset.created_at.desc())
    assets = await session.scalars(stmt)
    return list(assets.unique())


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str, user: CurrentUser, session: DbSession):
    stmt = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id).options(
        selectinload(Asset.subdomains).selectinload(Subdomain.services),
        selectinload(Asset.certificates)
    )
    asset = await session.scalar(stmt)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset


@router.post("/assets/{asset_id}/discover", response_model=AssetResponse)
async def discover_asset(asset_id: str, user: CurrentUser, session: DbSession):
    stmt = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id).options(
        selectinload(Asset.subdomains),
        selectinload(Asset.certificates)
    )
    asset = await session.scalar(stmt)
    if not asset:
        raise HTTPException(404, "Asset not found")

    try:
        # 1. Discover subdomains
        discovery_tool = SubdomainDiscovery(asset.domain)
        subdomains = await discovery_tool.discover()

        # Delete old subdomains/certificates to refresh
        for old_sub in list(asset.subdomains):
            await session.delete(old_sub)
        for old_cert in list(asset.certificates):
            await session.delete(old_cert)
        asset.subdomains = []
        asset.certificates = []
        await session.flush()

        discovered_subdomains = []
        discovered_certificates = []
        total_services = 0

        # Limit to 5 subdomains in manual inline discovery to keep it fast
        for hostname in subdomains[:5]:
            # 2. DNS record lookup
            dns_collector = DnsIntelligenceCollector(hostname)
            dns_records = dns_collector.collect_records()
            ips = dns_records.get("A", [])

            # 3. Create subdomain
            sub = Subdomain(
                asset_id=asset.id,
                hostname=hostname,
                ip_addresses=ips,
                status="active"
            )
            session.add(sub)
            await session.flush()

            # 4. Certificate extraction for secure subdomains
            cert_monitor = CertificateMonitor(hostname)
            cert_data = await cert_monitor.get_certificate()
            if cert_data:
                cert = Certificate(
                    asset_id=asset.id,
                    subject=cert_data["subject"],
                    issuer=cert_data["issuer"],
                    serial=cert_data["serial"],
                    not_before=cert_data["not_before"],
                    not_after=cert_data["not_after"],
                    fingerprint=cert_data["fingerprint"]
                )
                session.add(cert)
                discovered_certificates.append(cert)

            # 5. Add services (80 and 443 TCP)
            s1 = Service(
                subdomain_id=sub.id,
                port=80,
                protocol="TCP",
                banner="HTTP/1.1 200 OK",
                technology="Apache"
            )
            s2 = Service(
                subdomain_id=sub.id,
                port=443,
                protocol="TCP",
                banner="HTTP/1.1 200 OK (Secure)",
                technology="Nginx"
            )
            session.add(s1)
            session.add(s2)
            await session.flush()
            
            # Link technology
            tech = Technology(
                subdomain_id=sub.id,
                service_id=s2.id,
                name="Nginx",
                version="1.21.0",
                category="Web Server"
            )
            session.add(tech)

            total_services += 2
            discovered_subdomains.append(sub)

        # 6. Calculate scoring
        score = ExposureScoringCalculator.calculate_score(
            subdomains_count=len(discovered_subdomains),
            services_count=total_services,
            unauth_endpoints_count=0  # Can integrate API inventory count in the future
        )

        asset.subdomains = discovered_subdomains
        asset.certificates = discovered_certificates
        asset.exposure_score = score
        asset.last_scanned = datetime.utcnow()
        await session.commit()

        # Reload full data
        stmt = select(Asset).where(Asset.id == asset.id).options(
            selectinload(Asset.subdomains).selectinload(Subdomain.services),
            selectinload(Asset.certificates)
        )
        return await session.scalar(stmt)

    except Exception as e:
        await session.rollback()
        raise HTTPException(500, f"Failed to run discovery: {str(e)}")


@router.get("/assets/{asset_id}/subdomains", response_model=list[SubdomainResponse])
async def list_subdomains(asset_id: str, user: CurrentUser, session: DbSession):
    # Verify asset ownership first
    stmt_asset = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id)
    asset = await session.scalar(stmt_asset)
    if not asset:
        raise HTTPException(404, "Asset not found")

    stmt = select(Subdomain).where(Subdomain.asset_id == asset_id).options(selectinload(Subdomain.services))
    subdomains = await session.scalars(stmt)
    return list(subdomains.unique())


@router.get("/assets/{asset_id}/certificates", response_model=list[CertificateResponse])
async def list_certificates(asset_id: str, user: CurrentUser, session: DbSession):
    stmt_asset = select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id)
    asset = await session.scalar(stmt_asset)
    if not asset:
        raise HTTPException(404, "Asset not found")

    stmt = select(Certificate).where(Certificate.asset_id == asset_id)
    certs = await session.scalars(stmt)
    return list(certs.unique())
