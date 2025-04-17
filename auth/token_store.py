from redis_client import redis_client

def store_refresh_token(jti: str, email: str, expires_in: int):
    redis_client.setex(f"refresh:{jti}", expires_in, email)

def is_token_blacklisted(jti: str) -> bool:
    return redis_client.get(f"blacklist:{jti}") is not None

def blacklist_token(jti: str, expires_in: int):
    redis_client.setex(f"blacklist:{jti}", expires_in, "true")