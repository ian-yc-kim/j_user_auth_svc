from fastapi import FastAPI

from j_user_auth_svc.routers.login import router as login_router

app = FastAPI(debug=True)

# Include login router
app.include_router(login_router)
