"""
Multi-Tenant Isolation Layer for the Security Operations Platform.

Enforces tenant_id isolation at the SQLAlchemy query and session layer.
All database access through get_tenant_scoped_db() automatically filters queries
and binds writes to the calling user's tenant_id.
"""
from typing import Generator
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from auth import verify_token


def get_current_tenant(user: dict = Depends(verify_token)) -> str:
    """
    Extracts tenant_id from authenticated JWT claims.
    Checks: tenant_id -> organization_id -> org_id -> attributes -> default.
    """
    tenant_id = (
        user.get("tenant_id")
        or user.get("organization_id")
        or user.get("org_id")
        or user.get("tenant")
    )
    if not tenant_id and isinstance(user.get("attributes"), dict):
        attr = user["attributes"].get("tenant_id")
        if attr:
            tenant_id = attr[0] if isinstance(attr, list) else attr

    if not tenant_id:
        tenant_id = "default"

    return str(tenant_id)


class TenantScopedSession:
    """
    A scoped SQLAlchemy session proxy that automatically applies tenant_id
    filters to queries and assigns tenant_id to newly added models.
    """

    def __init__(self, db: Session, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id

    def query(self, *entities, **kwargs):
        """
        Returns a query with tenant_id automatically filtered if the primary entity
        has a tenant_id column.
        """
        q = self.db.query(*entities, **kwargs)
        if entities:
            primary_entity = entities[0]
            if hasattr(primary_entity, "tenant_id"):
                q = q.filter(primary_entity.tenant_id == self.tenant_id)
        return q

    def get_unscoped(self, *entities, **kwargs):
        """
        Returns an unfiltered query to inspect cross-tenant existence for 403 vs 404.
        """
        return self.db.query(*entities, **kwargs)

    def add(self, instance):
        """
        Assigns tenant_id automatically if the model supports it and it's not set
        or needs enforcing from the session context.
        """
        if hasattr(instance, "tenant_id"):
            # Enforce server-side tenant_id, preventing client spoofing
            instance.tenant_id = self.tenant_id
        self.db.add(instance)

    def add_all(self, instances):
        for inst in instances:
            self.add(inst)

    def delete(self, instance):
        if hasattr(instance, "tenant_id") and instance.tenant_id != self.tenant_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied: Cannot delete resource belonging to another tenant",
            )
        self.db.delete(instance)

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def refresh(self, instance):
        self.db.refresh(instance)

    def close(self):
        self.db.close()

    def execute(self, *args, **kwargs):
        return self.db.execute(*args, **kwargs)


def get_tenant_scoped_db(
    user: dict = Depends(verify_token),
) -> Generator[TenantScopedSession, None, None]:
    """
    FastAPI dependency yielding a TenantScopedSession for the current user.
    Import SessionLocal lazily from main to avoid circular imports.
    """
    from main import SessionLocal

    tenant_id = get_current_tenant(user)
    db = SessionLocal()
    scoped = TenantScopedSession(db=db, tenant_id=tenant_id)
    try:
        yield scoped
    finally:
        scoped.close()


def check_resource_access(
    scoped_db: TenantScopedSession,
    model_cls,
    resource_id,
    id_field_name: str = "id",
):
    """
    Finds a resource by ID.
    - If found in the tenant's scoped query -> returns the resource.
    - If found in another tenant -> raises 403 Forbidden.
    - If not found in any tenant -> raises 404 Not Found.
    """
    try:
        if isinstance(resource_id, str) and resource_id.isdigit():
            resource_id = int(resource_id)
    except Exception:
        pass

    id_attr = getattr(model_cls, id_field_name)

    # 1. Check scoped query (current tenant)
    resource = scoped_db.query(model_cls).filter(id_attr == resource_id).first()
    if resource:
        return resource

    # 2. Check unscoped query to differentiate 403 vs 404
    unscoped_resource = (
        scoped_db.get_unscoped(model_cls).filter(id_attr == resource_id).first()
    )
    if unscoped_resource:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: Resource {resource_id} belongs to another tenant",
        )

    raise HTTPException(
        status_code=404,
        detail=f"{model_cls.__name__} {resource_id} not found",
    )
