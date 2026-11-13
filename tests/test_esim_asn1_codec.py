"""ASN.1 编解码测试"""

import pytest
from esim_iot_profile_download.asn1_codec import (
    encode_bf38_authenticate_server_request,
    encode_smdp_signed2,
    encode_bf21_prepare_download_request,
    decode_euicc_info1,
    decode_bf2e_challenge,
    encode_bf57_add_initial_eim,
    encode_bf51_enable_psmo,
    decode_profiles_info,
    Asn1CodecError
)


def test_encode_smdp_signed2():
    """测试 SmdpSigned2 编码"""
    transaction_id = "0102030405060708090A0B0C0D0E0F10"
    result = encode_smdp_signed2(transaction_id, False)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_encode_bf38_authenticate_server_request():
    """测试 BF38 AuthenticateServerRequest 编码"""
    server_signed1 = bytes.fromhex("3000")
    server_signature1 = bytes(64)
    euicc_ci_pk_id = bytes.fromhex("0102030405060708")
    server_certificate = bytes.fromhex("3000")
    matching_id = "TEST12345"
    tac = bytes.fromhex("00000000")
    
    result = encode_bf38_authenticate_server_request(
        server_signed1=server_signed1,
        server_signature1=server_signature1,
        euicc_ci_pk_id=euicc_ci_pk_id,
        server_certificate=server_certificate,
        matching_id=matching_id,
        tac=tac
    )
    
    assert isinstance(result, bytes)
    assert result[:2] == b'\xbf\x38'  # BF38 tag


def test_encode_bf21_prepare_download_request():
    """测试 BF21 PrepareDownloadRequest 编码"""
    smdp_signed2 = encode_smdp_signed2("0102030405060708090A0B0C0D0E0F10", False)
    smdp_signature2 = bytes(64)
    smdp_certificate = bytes.fromhex("3000")
    
    result = encode_bf21_prepare_download_request(
        smdp_signed2=smdp_signed2,
        smdp_signature2=smdp_signature2,
        smdp_certificate=smdp_certificate
    )
    
    assert isinstance(result, bytes)
    assert result[:2] == b'\xbf\x21'  # BF21 tag


def test_decode_bf2e_challenge():
    """测试 BF2E Challenge 解码"""
    # 构造一个有效的 BF2E 响应
    challenge = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
    response = bytes.fromhex("BF2E138010") + challenge
    
    result = decode_bf2e_challenge(response)
    assert result == challenge


def test_decode_bf2e_challenge_too_short():
    """测试 BF2E Challenge 解码 - 数据过短"""
    response = bytes.fromhex("BF2E")
    
    with pytest.raises(Asn1CodecError):
        decode_bf2e_challenge(response)


def test_encode_bf57_add_initial_eim():
    """测试 BF57 AddInitialEim 编码"""
    eim_id = "test-eim-001"
    eim_counter = 1
    
    result = encode_bf57_add_initial_eim(
        eim_id=eim_id,
        eim_counter=eim_counter
    )
    
    assert isinstance(result, bytes)
    assert result[:2] == b'\xbf\x57'  # BF57 tag


def test_encode_bf51_enable_psmo():
    """测试 BF51 EnablePSMO 编码"""
    iccid = "986810325476981032F4"  # BCD 编码的 ICCID
    profile_id = "A0000005591010FFFFFFFF8900001000"
    eim_counter = 2
    
    result = encode_bf51_enable_psmo(
        iccid=iccid,
        profile_id=profile_id,
        eim_counter=eim_counter
    )
    
    assert isinstance(result, bytes)
    assert result[:2] == b'\xbf\x51'  # BF51 tag


def test_decode_profiles_info_enabled():
    """测试 GetProfilesInfo 解码 - ENABLED 状态"""
    # 构造包含 9F70 01 01 的响应（profileState = ENABLED）
    response = bytes.fromhex("BF2D0A9F700101")
    
    result = decode_profiles_info(response)
    assert result.get("profile_state") == "ENABLED"


def test_decode_profiles_info_disabled():
    """测试 GetProfilesInfo 解码 - DISABLED 状态"""
    # 构造包含 9F70 01 00 的响应（profileState = DISABLED）
    response = bytes.fromhex("BF2D0A9F700100")
    
    result = decode_profiles_info(response)
    assert result.get("profile_state") == "DISABLED"


def test_decode_profiles_info_empty():
    """测试 GetProfilesInfo 解码 - 空响应"""
    result = decode_profiles_info(b"")
    assert result.get("profile_state") is None
