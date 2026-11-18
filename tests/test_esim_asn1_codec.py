"""ASN.1 编解码测试"""

import pytest
from esim_iot_profile_download.asn1_codec import (
    encode_bf38_authenticate_server_request,
    encode_smdp_signed2,
    encode_bf21_prepare_download_request,
    decode_euicc_info1,
    decode_bf2e_challenge,
    encode_bf57_add_initial_eim,
    encode_enable_psmo,
    encode_psmo_list,
    encode_euicc_package_signed,
    decode_profiles_info,
    decode_profile_installation_result,
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
    """测试 BF57 AddInitialEim 编码（对齐参考日志字节）"""
    spki = bytes.fromhex(
        "301306072A8648CE3D020106082A8648CE3D030107"
        "034200" + "04" + "11" * 64
    )

    result = encode_bf57_add_initial_eim(
        eim_id="testeim1",
        counter_value=1,
        eim_public_key_spki=spki,
        eim_fqdn="eimfqdn.example.com",
        eim_id_type=3
    )

    assert result[:2] == b'\xbf\x57'
    # 参考日志: BF57 8188 A0 8185 30 8182 80 08 "testeim1" 81 13 "eimfqdn.example.com" 82 01 03 83 01 01 A5 5B A0 59
    assert result.hex().upper().startswith(
        "BF578188A0818530818280087465737465696D31"
        "811365696D6671646E2E6578616D706C652E636F6D"
        "820103830101A55BA059"
    )


def test_encode_bf51_enable_psmo():
    """测试 LoadEuiccPackage(BF51) 编码（对齐参考日志字节）"""
    eid = bytes.fromhex("89049032123451234512345678901235")
    iccid_bcd = bytes.fromhex("989209012143658709F5")

    psmo_list = encode_psmo_list(encode_enable_psmo(iccid_bcd))
    signed = encode_euicc_package_signed("testeim1", eid, 2, psmo_list)

    assert signed.hex().upper() == (
        "302F80087465737465696D315A1089049032123451234512345678901235"
        "810102A00EA30C5A0A989209012143658709F5"
    )


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


def test_decode_profile_installation_result_success():
    """测试 ProfileInstallationResult 解码 - 成功分支 (finalResult = A0)"""
    response = bytes.fromhex(
        "BF3716BF2711"          # BF37 { BF27 }
        "800101"                # transactionId
        "A208A0064F04800101"    # finalResult { A0 { 4F ... } }
        "5F3700"                # 占位签名
    )

    result = decode_profile_installation_result(response)
    assert result["ok"] is True
    assert result["transaction_id"] == "01"


def test_decode_profile_installation_result_error():
    """测试 ProfileInstallationResult 解码 - 错误分支 (finalResult = A1)

    来自真实卡片: 重复安装同一 Profile 时 eUICC 在 storeMetadata 阶段中止。
    """
    response = bytes.fromhex(
        "BF37818ABF2744800101BF2F2F80020204810207800C19"
        "74657374736D6470706C7573312E6578616D706C652E636F6D"
        "5A0A989209012143658709F5"
        "060388370A"
        "A208A106800102810109"
        "5F3740E42F03EE010CCE2D9508F11F6273E3AFB65EA00C477EDBF77B27BCAB5E5A9A780AA3"
        "076D88DC4650ECA99A28255867FAEE68FCD1CA40861B633F0B31F3BC559F"
    )

    result = decode_profile_installation_result(response)
    assert result["ok"] is False
    assert result["transaction_id"] == "01"
    assert result["bpp_command_id"] == 2
    assert result["bpp_command"] == "storeMetadata"
    assert result["error_reason"] == 9
