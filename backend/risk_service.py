"""Read-only projections of current access; historical policy findings stay intact."""
from datetime import date
from models import User, Resource, Grant, Delegation, RoleAssignment
from policy_engine import calculate_effective_access
from risk_engine import calculate_grant_risk, risk_tier, MODEL_VERSION


def risk_dashboard(db):
    today = date.today()
    users = {u.id: u for u in db.query(User).filter(User.is_active == True)}
    resources = {r.id: r for r in db.query(Resource)}
    sources = {
        "DIRECT": {r.id: r for r in db.query(Grant)},
        "DELEGATED": {r.id: r for r in db.query(Delegation)},
        "ROLE_INHERITED": {r.id: r for r in db.query(RoleAssignment)},
    }
    rows = []
    for access in calculate_effective_access(db):
        user = users.get(access.user_id)
        resource = resources.get(access.resource_id)
        source = sources[access.source_type][access.source_id]
        if not user or not resource:
            continue
        if access.source_type == "DIRECT":
            owner, temporary = source.owner, source.is_temporary
        elif access.source_type == "ROLE_INHERITED":
            owner, temporary = source.assigned_by, source.role.is_temporary
        else:
            delegator = users.get(source.delegator_id)
            if not delegator:
                continue
            owner, temporary = delegator.full_name, True
        result = calculate_grant_risk(permission_level=access.permission_level,
            sensitivity=resource.sensitivity, expiry_date=source.expiry_date,
            owner=owner, purpose=source.purpose, is_temporary=temporary, as_of=today)
        rows.append({**result, "key": f"{access.source_type}:{source.id}:{resource.id}:{access.permission_level}",
            "source_type": access.source_type, "source_id": source.id,
            "user_id": user.id, "user_name": user.full_name, "department": user.department,
            "resource_id": resource.id, "resource_name": resource.name,
            "permission_level": access.permission_level, "sensitivity": resource.sensitivity,
            "owner": owner, "purpose": source.purpose, "expiry_date": source.expiry_date,
            "is_temporary": temporary})
    rows.sort(key=lambda r: (-r["score"], -r["days_overdue"], r["user_id"], r["key"]))
    people = []
    for user in users.values():
        grants = [r for r in rows if r["user_id"] == user.id]
        score = max((r["score"] for r in grants), default=0)
        people.append({"user_id": user.id, "user_name": user.full_name, "score": score,
            "tier": risk_tier(score), "access_count": len(grants),
            "stale": any(r["days_overdue"] > 0 for r in grants)})
    people.sort(key=lambda p: (-p["score"], p["user_id"]))
    source_keys = {(r["source_type"], r["source_id"]) for r in rows}
    unclean = {(r["source_type"], r["source_id"]) for r in rows if not r["clean"]}
    for row in rows:
        row["clean_source"] = (row["source_type"], row["source_id"]) not in unclean
    return {"as_of": today, "model_version": MODEL_VERSION, "queue": rows, "people": people,
        "summary": {"high_risk_people": sum(p["score"] >= 70 for p in people),
            "stale_accounts": sum(p["stale"] for p in people),
            "clean_leases": len(source_keys - unclean), "effective_access_provided": len(rows)}}
