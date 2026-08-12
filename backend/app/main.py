from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.db import init_db
from app.core.db_ops import seed_admin_user
from app.routers import auth, instances, scenarios


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_admin_user()
    yield


app = FastAPI(title="CyberLab MVP", version="0.1.0", lifespan=lifespan)

# MVP: libera o frontend local. Restringir a origens específicas antes de
# qualquer deploy fora da sua máquina.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scenarios.router)
app.include_router(instances.router)


@app.get("/health")
def health():
    return {"status": "ok"}
