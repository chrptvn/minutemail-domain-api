import json
import random
import string

import requests
from fastapi import FastAPI, HTTPException, Header, status
import redis
import os
from typing import Optional
from pydantic import BaseModel
from jose import jwt, JWTError
import dns.resolver


class DomainClaim(BaseModel):
    name: str
    mailbox_ttl: Optional[int] = 3600

app = FastAPI()

redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
redis_port = int(os.getenv("REDIS_PORT", "6379"))
redis_db = int(os.getenv("REDIS_DB", "2"))

KEYCLOAK_URL = "https://keycloak.minutemail.co"
REALM = "minutemail"
AUDIENCE = "account"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"

redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)

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


def random_string(length: int):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))


def verify_mx(
    domain: str
):
    domain_name = domain.lower()
    valid_mx_records = ['smtp1.minutemail.co']

    try:
        records = dns.resolver.resolve(domain_name, 'MX')
        mx_hosts = [record.exchange.to_text(omit_final_dot=True).lower() for record in records]

        return all(mx in valid_mx_records for mx in mx_hosts)
    except Exception as e:
        print(f"Failed to get MX records for {domain_name}: {e}")
        return {"valid": False, "error": str(e) if str(e) else "Failed to resolve MX records"}


def verify_txt(
        domain: str,
        txt_verification: str,
):
    domain_name = domain.lower()
    try:
        records = dns.resolver.resolve(domain_name, 'TXT')
        for r in records:
            if txt_verification in r.to_text():
                return True
    except Exception as e:
        print(f"Failed to get TXT records for {domain_name}: {e}")

    return False


@app.post("/v1/domains", summary="Claim a new domain")
async def claim_domain(
    domainClaim: DomainClaim,
    auth_header: str = Header(None, alias="Authorization")
):
    user_id = await get_user_id(auth_header)
    domain_name = domainClaim.name.lower()
    txt_verification = f"minutemail-{random_string(16)}"

    domain_key = f"user:{user_id}:domains"

    try:
        claimed_domain = {
            "name": domain_name,
            "verification": txt_verification,
            "mailbox_ttl": domainClaim.mailbox_ttl
        }

        await redis_client.rpush(domain_key, json.dumps(claimed_domain))

        claimed_domain["mx_valid"] = verify_mx(domain_name)
        claimed_domain["txt_valid"] = False
        return claimed_domain
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to claim domain due to an internal error: {e}"
        )


@app.get("/v1/domains", summary="Fetch all domains claimed by the current user")
async def fetch_domains(
    auth_header: str = Header(None, alias="Authorization")
):
    user_id = await get_user_id(auth_header)
    user_domains_set_key = f"user:{user_id}:domains"

    try:
        claimed_domains = []
        for domain in redis_client.smembers(user_domains_set_key):
            claimed_domain = json.loads(domain)
            claimed_domain["mx_valid"] = verify_mx(claimed_domain["name"])
            claimed_domain["txt_valid"] = verify_txt(claimed_domain["name"], claimed_domain["verification"])
            claimed_domains.append(claimed_domain)
        return claimed_domains
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch domains due to an internal error: {e}"
        )


@app.delete("/v1/domains/{domain_name}", summary="Delete a claimed domain")
async def delete_domain(
    domain_name: str,
    auth_header: str = Header(None, alias="Authorization")
):
    user_id = await get_user_id(auth_header)
    domain_name = domain_name.lower()

    domain_key = f"user:{user_id}:domains"

    try:
        raw_list = redis_client.lrange(domain_key, 0, -1)
        for raw in raw_list:
            content = json.loads(raw)
            if content.get("name") == domain_name:
                redis_client.lrem(domain_key, 1, raw)
                return {"message": f"Domain '{domain_name}' deleted successfully by user '{user_id}'."}

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{domain_name}' not found for user '{user_id}'."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete domain due to an internal error: {e}"
        )