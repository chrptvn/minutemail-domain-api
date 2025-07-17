import json

import requests
from fastapi import FastAPI, HTTPException, Header, status
import redis
import os
from typing import List
from pydantic import BaseModel
from jose import jwt, JWTError


class ClaimedDomain(BaseModel):
    domain: str


app = FastAPI()

redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
file_service_url = os.getenv("FILE_SERVICE_URL", "http://tempfile-servlet.minutemail.svc.cluster.local:8080")
redis_port = int(os.getenv("REDIS_PORT", "6379"))
redis_db_domains = int(os.getenv("REDIS_DB", "2"))

KEYCLOAK_URL = "https://keycloak.minutemail.co"
REALM = "minutemail"
AUDIENCE = "account"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"

redis_domains = redis.Redis(host=redis_host, port=redis_port, db=redis_db_domains, decode_responses=True)

async def get_user_id(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = get_claims(auth_header)
        user_id = claims.get("sub")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
    return user_id


def get_claims(auth_header: str) -> dict:
    if auth_header and auth_header.startswith("Bearer "):
        jwt_token = auth_header.removeprefix("Bearer ").strip()
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    resp = requests.get(JWKS_URL)
    resp.raise_for_status()

    jwks = resp.json()
    try:
        claims = jwt.decode(
            jwt_token,
            jwks,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER
        )
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}") from e

    return claims


@app.post("/v1/domains", summary="Claim a new domain")
async def claim_domain(
    req: ClaimedDomain,
    auth_header: str = Header(None, alias="Authorization")
):
    user_id = await get_user_id(auth_header)
    domain_name = req.domain.lower()

    domain_key = f"domain:{domain_name}"
    user_domains_set_key = f"user:{user_id}:domains"

    claimed_by_user_id = redis_domains.get(domain_key)

    if claimed_by_user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Domain '{domain_name}' is already claimed."
        )

    try:
        pipe = redis_domains.pipeline()

        pipe.set(domain_key, user_id)
        pipe.sadd(user_domains_set_key, json.dumps({
            "domain": domain_name,
            "verified": True
        }))

        pipe.execute()

        return {"message": f"Domain '{domain_name}' claimed successfully by user '{user_id}'."}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to claim domain due to an internal error: {e}"
        )


@app.get("/v1/domains", response_model=List[ClaimedDomain], summary="Fetch all domains claimed by the current user")
async def fetch_domains(
    auth_header: str = Header(None, alias="Authorization")
):
    user_id = await get_user_id(auth_header)
    user_domains_set_key = f"user:{user_id}:domains"

    try:
        claimed_domains = redis_domains.smembers(user_domains_set_key)
        return [json.loads(d) for d in claimed_domains]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch domains due to an internal error: {e}"
        )

@app.delete("/v1/domains/drop")
async def delete_all_domains():
    try:
        await redis_domains.flushdb()
        return {"message": "All domains deleted successfully."}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete domains due to an internal error: {e}"
        )


@app.delete("/v1/domains/{domain_name}", summary="Delete a claimed domain")
async def delete_domain(
    domain_name: str,
    auth_header: str = Header(None, alias="Authorization")
):
    user_id = await get_user_id(auth_header)
    domain_name = domain_name.lower() # Ensure consistency

    domain_key = f"domain:{domain_name}"
    user_domains_set_key = f"user:{user_id}:domains"

    # Check if the domain exists and if the current user is its owner
    claimed_by_user_id = redis_domains.get(domain_key)

    if not claimed_by_user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{domain_name}' not found or not claimed."
        )

    if claimed_by_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You are not authorized to delete domain '{domain_name}' as it is claimed by another user."
        )

    try:
        # Start a Redis pipeline for atomic operations
        pipe = redis_domains.pipeline()

        # 1. Delete the domain's ownership key
        await pipe.delete(domain_key)
        # 2. Remove the domain from the user's set of claimed domains
        await pipe.srem(user_domains_set_key, domain_name)

        # Execute all commands in the pipeline atomically
        pipe.execute()

        return {"message": f"Domain '{domain_name}' deleted successfully by user '{user_id}'."}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete domain due to an internal error: {e}"
        )