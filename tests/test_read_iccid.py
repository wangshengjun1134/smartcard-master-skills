import pytest
import tempfile
from read_iccid_skill.skill import ReadIccidSkill
from smartcard_skill_sdk.base import SkillContext, OutputCollector
from smartcard_skill_sdk.session_store import SessionStore, SkillSession

def test_read_iccid_build_apdu():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(tmpdir)
        ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())
        skill = ReadIccidSkill()
        apdu = skill.build_apdu(ctx, {})
        assert apdu == "00A40000023F00"

def test_read_iccid_parse_response():
    skill = ReadIccidSkill()
    result = skill.parse_response("98012345678901234567890", "9000")
    assert "iccid" in result
    assert result["iccid"] == "98012345678901234567"

def test_read_iccid_manifest():
    skill = ReadIccidSkill()
    manifest = skill.get_manifest()
    assert manifest["skillId"] == "read.iccid"
    assert "ICCID" in manifest["description"]
