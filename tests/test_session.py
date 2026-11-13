import pytest
import tempfile
import os
from pathlib import Path
from smartcard_skill_sdk.session_store import SkillSession, SessionStore

def test_skill_session_auto_generates_id():
    session = SkillSession(skill_id="test.skill")
    assert session.session_id != ""
    assert len(session.session_id) == 36  # UUID format

def test_skill_session_auto_sets_timestamps():
    session = SkillSession(skill_id="test.skill")
    assert session.created_at != ""
    assert session.updated_at != ""
    assert session.created_at.endswith("Z")

def test_session_store_creates_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        assert Path(tmpdir).exists()

def test_session_store_save_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        session = SkillSession(skill_id="test.skill", state="RUNNING")
        store.save(session, "test.skill")
        
        loaded = store.load(session.session_id)
        assert loaded is not None
        assert loaded.session_id == session.session_id
        assert loaded.state == "RUNNING"

def test_session_store_delete():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        session = SkillSession(skill_id="test.skill")
        store.save(session, "test.skill")
        
        store.delete(session.session_id)
        loaded = store.load(session.session_id)
        assert loaded is None

def test_session_file_permissions():
    """Windows 不支持文件权限，跳过此测试"""
    import sys
    if sys.platform == "win32":
        pytest.skip("Windows does not support file permissions")
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        session = SkillSession(skill_id="test.skill")
        store.save(session, "test.skill")
        
        file_path = Path(tmpdir) / f"session-{session.session_id[:8]}.json"
        stat = os.stat(file_path)
        assert oct(stat.st_mode)[-3:] == "600"
