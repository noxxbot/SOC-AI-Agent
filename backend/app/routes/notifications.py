from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.notification_service import manager

router = APIRouter()


@router.websocket("/ws/notifications")
async def notifications_ws(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
