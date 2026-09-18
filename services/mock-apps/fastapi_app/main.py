import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
from middleware import SecurityTelemetryEmitter, SecurityControlPlaneMiddleware

class LoginRequest(BaseModel):
    username: str
    password: str

emitter = SecurityTelemetryEmitter(
    app_id="application-a-auth",
    environment=os.getenv("APP_ENV", "production"),
    control_plane_url=os.getenv("CONTROL_PLANE_URL", "http://localhost:8080/api/v1/telemetry"),
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await emitter.start()
    yield
    await emitter.stop()

app = FastAPI(title="Protected Mock App A", lifespan=lifespan)
app.add_middleware(SecurityControlPlaneMiddleware, emitter=emitter)

@app.get("/")
async def root():
    return {"status": "ok", "app": "application-a-auth"}

@app.post("/api/login")
async def login(req: LoginRequest):
    # Simulated authentication logic
    if req.username == "admin" and req.password == "secret123":
        return {
            "token": "tok_valid_mock_session_1001",
            "user_id": "usr_admin",
            "role": "admin"
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials"
    )

@app.get("/api/users/{user_id}")
async def get_user(user_id: str, x_session_id: str = Header(None)):
    if not x_session_id:
        raise HTTPException(status_code=401, detail="Session required")
    return {"user_id": user_id, "name": f"User {user_id}", "email": f"user{user_id}@example.com"}

@app.get("/api/admin/export")
async def admin_export(x_user_id: str = Header(None), x_session_id: str = Header(None)):
    if x_user_id != "usr_admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")
    return {"export_id": "exp_909", "record_count": 50000, "status": "completed"}
