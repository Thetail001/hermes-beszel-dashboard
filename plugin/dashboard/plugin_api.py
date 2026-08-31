"""beszel: PocketBase 反代层（阶段1实现，先占位）"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/ping")
async def ping():
    return {"ok": True, "stage": 0}
