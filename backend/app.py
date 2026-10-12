
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import create_tables
from backend.auth_routes import router as auth_router
from backend.auth_routes import ensure_admin_account
from backend.routes.analysis_routes import router as analysis_router
from backend.routes.dashboard_routes import router as dashboard_router

app = FastAPI(
    title="Phishing Email Detection & Awareness Dashboard",
    description="API for phishing email analysis and awareness",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(analysis_router)
app.include_router(dashboard_router)


@app.on_event("startup")
def startup():
    create_tables()
    ensure_admin_account()


@app.get("/")
def root():
    return {
        "message": "Phishing Email Detection API is running"
    }
