import json
from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.deps import CurrentUser, DbSession
from app.scanner.http_client import SafeHttpClient
from app.scanner.target_policy import validate_target, TargetRejected

from app.api_security.models import ApiInventory, ApiEndpoint
from app.api_security.schemas import ApiDiscoveryRequest, ApiInventoryResponse, ApiDiscoveryResponse
from app.api_security.schema_discovery import SchemaDiscovery
from app.api_security.openapi_parser import OpenApiParser
from app.api_security.graphql_analyzer import GraphQLAnalyzer

router = APIRouter(prefix="/api-security", tags=["api-security"])


@router.post("/discover", response_model=ApiDiscoveryResponse, status_code=202)
async def discover_api(payload: ApiDiscoveryRequest, user: CurrentUser, session: DbSession):
    try:
        target = await validate_target(str(payload.target_url))
    except (TargetRejected, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc

    # Run discovery using SafeHttpClient
    client = SafeHttpClient(target.host)
    try:
        discovery_result = await SchemaDiscovery(target.url).discover(client)
        
        # Check if we already have an inventory for this URL
        query = select(ApiInventory).where(ApiInventory.url == target.url).options(selectinload(ApiInventory.endpoints))
        inventory = await session.scalar(query)

        if not inventory:
            inventory = ApiInventory(
                asset_id=payload.asset_id,
                url=target.url,
                api_type=discovery_result.get("api_type", "REST"),
                schema_definition=discovery_result.get("schema_definition"),
                endpoints_count=0
            )
            session.add(inventory)
            await session.flush()
        else:
            # Update existing
            inventory.api_type = discovery_result.get("api_type", "REST")
            inventory.schema_definition = discovery_result.get("schema_definition")
            # Delete old endpoints
            for old_ep in list(inventory.endpoints):
                await session.delete(old_ep)
            inventory.endpoints = []
            await session.flush()

        parsed_endpoints = []
        if inventory.api_type == "REST" and inventory.schema_definition:
            parser = OpenApiParser(inventory.schema_definition)
            parsed_spec = parser.parse()
            for parsed_ep in parsed_spec.get("endpoints", []):
                ep = ApiEndpoint(
                    inventory_id=inventory.id,
                    method=parsed_ep["method"],
                    path=parsed_ep["path"],
                    auth_required=parsed_ep["auth_required"],
                    parameters=parsed_ep["parameters"]
                )
                session.add(ep)
                parsed_endpoints.append(ep)
        elif inventory.api_type == "GraphQL":
            # Default fallback schema for discovered GraphQL endpoint
            analyzer = GraphQLAnalyzer()
            ep = ApiEndpoint(
                inventory_id=inventory.id,
                method="POST",
                path=target.path if target.path else "/graphql",
                auth_required=True,
                parameters=[{"name": "query", "in": "body", "type": "string", "required": True}]
            )
            session.add(ep)
            parsed_endpoints.append(ep)
        else:
            # Fallback REST API single endpoint
            ep = ApiEndpoint(
                inventory_id=inventory.id,
                method="GET",
                path=target.path if target.path else "/",
                auth_required=False,
                parameters=[]
            )
            session.add(ep)
            parsed_endpoints.append(ep)

        await session.flush()
        inventory.endpoints_count = len(parsed_endpoints)
        inventory.endpoints = parsed_endpoints
        await session.commit()
        
        # Reload with relations
        stmt = select(ApiInventory).where(ApiInventory.id == inventory.id).options(selectinload(ApiInventory.endpoints))
        reloaded = await session.scalar(stmt)

        return ApiDiscoveryResponse(
            success=True,
            message="API discovery completed successfully.",
            inventory=ApiInventoryResponse.model_validate(reloaded)
        )
    except Exception as e:
        await session.rollback()
        raise HTTPException(500, f"Error running API discovery: {str(e)}")
    finally:
        await client.close()


@router.get("/inventory", response_model=list[ApiInventoryResponse])
async def list_inventory(user: CurrentUser, session: DbSession):
    # Retrieve all API inventories
    stmt = select(ApiInventory).options(selectinload(ApiInventory.endpoints)).order_by(ApiInventory.created_at.desc())
    inventories = await session.scalars(stmt)
    return list(inventories.unique())


@router.get("/inventory/{inventory_id}", response_model=ApiInventoryResponse)
async def get_inventory(inventory_id: str, user: CurrentUser, session: DbSession):
    stmt = select(ApiInventory).where(ApiInventory.id == inventory_id).options(selectinload(ApiInventory.endpoints))
    inventory = await session.scalar(stmt)
    if not inventory:
        raise HTTPException(404, "API inventory not found")
    return inventory
