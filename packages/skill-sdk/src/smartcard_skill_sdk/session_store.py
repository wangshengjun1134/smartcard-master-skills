import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import uuid


class SkillSession:
    def __init__(
        self,
        skill_id: str,
        session_id: str = "",
        state: str = "",
        data: dict[str, Any] | None = None,
        ttl_seconds: int = 3600
    ):
        self.schema_version = 1
        self.session_id = session_id or str(uuid.uuid4())
        self.skill_id = skill_id
        self.created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.updated_at = self.created_at
        self.status = "CREATED"
        self.state = state or ""
        self.data = data or {}
        self.last_action_id = ""
        self.ttl_seconds = ttl_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "skill_id": self.skill_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "state": self.state,
            "data": self.data,
            "last_action_id": self.last_action_id,
            "ttl_seconds": self.ttl_seconds
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SkillSession":
        session = cls(
            skill_id=data["skill_id"],
            session_id=data["session_id"],
            state=data.get("state", ""),
            data=data.get("data", {}),
            ttl_seconds=data.get("ttl_seconds", 3600)
        )
        session.created_at = data.get("created_at", session.created_at)
        session.updated_at = data.get("updated_at", session.updated_at)
        session.status = data.get("status", "CREATED")
        session.last_action_id = data.get("last_action_id", "")
        return session


class SessionStore:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def save(self, session: SkillSession, skill_id: str) -> None:
        session.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        file_path = self.base_dir / f"session-{session.session_id[:8]}.json"
        
        with tempfile.NamedTemporaryFile(
            mode='w', dir=self.base_dir, delete=False, suffix='.tmp'
        ) as f:
            json.dump(session.to_dict(), f, indent=2)
            temp_path = f.name
        
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, file_path)

    def load(self, session_id: str) -> SkillSession | None:
        file_path = self.base_dir / f"session-{session_id[:8]}.json"
        if not file_path.exists():
            return None
        with open(file_path) as f:
            data = json.load(f)
        return SkillSession.from_dict(data)

    def delete(self, session_id: str) -> None:
        file_path = self.base_dir / f"session-{session_id[:8]}.json"
        if file_path.exists():
            file_path.unlink()

    def create(self, params: dict, skill_id: str) -> SkillSession:
        session = SkillSession(skill_id=skill_id, data={"params": params})
        self.save(session, skill_id)
        return session
