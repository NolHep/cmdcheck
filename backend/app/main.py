"""cmdcheck FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .db import close_pool, fetch_analysis, run_migrations, upsert_analysis
from .decoder import decode_layers
from .lolbas import load_catalog, match as lolbas_match
from .parser import extract_binaries, parse_command
from .slug import make_slug


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_catalog()
    await run_migrations()
    yield
    await close_pool()


app = FastAPI(title="cmdcheck", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    command: str = Field(min_length=1, max_length=65536)


class ErrorResponse(BaseModel):
    code: str
    detail: str


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(body: AnalyzeRequest) -> dict[str, Any]:
    command = body.command
    slug = make_slug(command)

    # Check for existing analysis (idempotent)
    existing = await fetch_analysis(slug)
    if existing is not None:
        return existing

    ast, parse_error = parse_command(command)
    layers = decode_layers(command)

    # LOLBAS matching: try binaries from the original command and each decoded layer
    lolbas: dict[str, Any] | None = None
    for source in [command, *(layer["value"] for layer in layers)]:
        for binary in extract_binaries(source):
            hit = lolbas_match(binary)
            if hit is not None:
                lolbas = hit
                break
        if lolbas is not None:
            break

    result: dict[str, Any] = {
        "slug": slug,
        "parsed": ast,
        "parsed_error": parse_error,
        "decoded_layers": layers,
        "lolbas_match": lolbas,
    }

    await upsert_analysis(slug, command, result)
    return result


@app.get("/c/{slug}")
async def get_analysis(slug: str) -> dict[str, Any]:
    if len(slug) != 12 or not slug.isalnum():
        raise HTTPException(status_code=400, detail={"code": "invalid_slug", "detail": "Bad slug format"})
    row = await fetch_analysis(slug)
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "Analysis not found"})
    return row
