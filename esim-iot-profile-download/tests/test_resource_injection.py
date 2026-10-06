#!/usr/bin/env python3
"""资源外部注入测试（离线，无需读卡器）

覆盖：证书/私钥的 PEM 文本与 base64 DER 注入、包内默认回退、缺文件报错、
UPP 载荷注入（hex/base64）。

运行：cd <skill 根目录> && python3 -m unittest tests.test_resource_injection -v
"""

import base64
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

import main as skill_main

CERTS = os.path.join(ROOT, 'resources', 'certs')


def _read(path: str) -> bytes:
    with open(path, 'rb') as fh:
        return fh.read()


class TestMaterialDecoding(unittest.TestCase):
    def test_pem_text_is_passed_through(self):
        pem = _read(os.path.join(CERTS, 'SK_S_SM_DPauth_ECDSA_NIST.pem'))
        self.assertEqual(skill_main._decode_material(pem.decode(), 'dp_auth_key'), pem)

    def test_base64_der_is_decoded(self):
        der = _read(os.path.join(CERTS, 'CERT_S_SM_DPauth_ECDSA_NIST.der'))
        self.assertEqual(
            skill_main._decode_material(base64.b64encode(der).decode(), 'dp_auth_cert'), der)

    def test_invalid_value_is_rejected(self):
        for bad in ('', '   ', 'não-base64!!'):
            with self.assertRaises(ValueError):
                skill_main._decode_material(bad, 'dp_auth_key')


class TestPayloadDecoding(unittest.TestCase):
    def test_hex_payload(self):
        self.assertEqual(skill_main._decode_payload('A0 40 80 01'), bytes.fromhex('A0408001'))

    def test_base64_payload(self):
        self.assertEqual(skill_main._decode_payload('oECAAQ=='), b'\xa0@\x80\x01')


class TestPkiInjection(unittest.TestCase):
    """包内证书作为默认；外部注入可完全替代（含无资源目录的场景）"""

    def _certs_as_overrides(self):
        return {
            'dp_auth_key': _read(os.path.join(CERTS, 'SK_S_SM_DPauth_ECDSA_NIST.pem')).decode(),
            'dp_auth_cert': base64.b64encode(
                _read(os.path.join(CERTS, 'CERT_S_SM_DPauth_ECDSA_NIST.der'))).decode(),
            'dp_pb_key': _read(os.path.join(CERTS, 'SK_S_SM_DPpb_ECDSA_NIST.pem')).decode(),
            'dp_pb_cert': base64.b64encode(
                _read(os.path.join(CERTS, 'CERT_S_SM_DPpb_ECDSA_NIST.der'))).decode(),
            'ci_cert': _read(os.path.join(CERTS, 'CERT_CI_ECDSA_NIST.pem')).decode(),
            'eim_key': _read(os.path.join(CERTS, 'SK_EIM_ECDSA_NIST.pem')).decode(),
            'eim_cert': base64.b64encode(
                _read(os.path.join(CERTS, 'CERT_EIM_ECDSA_NIST.der'))).decode(),
        }

    def test_defaults_from_packaged_resources(self):
        pki = skill_main.load_pki_from_resources(os.path.join(ROOT, 'resources'))
        self.assertIsNotNone(pki['eim_identity'])
        self.assertEqual(pki['dp_auth_identity'].private_key.public_key().public_numbers(),
                         skill_main._load_private_key_auto(
                             _read(os.path.join(CERTS, 'SK_S_SM_DPauth_ECDSA_NIST.pem'))
                         ).public_key().public_numbers())

    def test_full_injection_without_resources_dir(self):
        """资源目录为空（甚至不存在）时，全靠注入也能构建 PKI"""
        with tempfile.TemporaryDirectory() as empty_dir:
            pki = skill_main.load_pki_from_resources(empty_dir, self._certs_as_overrides())
        self.assertIsNotNone(pki['dp_auth_identity'])
        self.assertIsNotNone(pki['dp_pb_identity'])
        self.assertIsNotNone(pki['ci_cert'])
        self.assertIsNotNone(pki['eim_identity'])

    def test_injection_overrides_packaged_default(self):
        """注入值优先于包内默认文件（用另一套新生成的私钥替换）"""
        from cryptography.hazmat.primitives import serialization
        from src.pki_manager import generate_ecdsa_p256_keypair

        with tempfile.TemporaryDirectory() as empty_dir:
            new_key, _ = generate_ecdsa_p256_keypair()
            pem = new_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            overrides = self._certs_as_overrides()
            overrides['dp_auth_key'] = pem.decode()
            pki = skill_main.load_pki_from_resources(empty_dir, overrides)

        self.assertEqual(
            pki['dp_auth_identity'].private_key.private_numbers().private_value,
            new_key.private_numbers().private_value,
        )

    def test_missing_default_without_override_reports_param_name(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            with self.assertRaises(FileNotFoundError) as ctx:
                skill_main.load_pki_from_resources(empty_dir)
        self.assertIn('dp_auth_key', str(ctx.exception))

    def test_eim_is_optional(self):
        """无 eIM 证书且未注入 → eim_identity 为 None（direct 模式可用）"""
        overrides = self._certs_as_overrides()
        overrides.pop('eim_key')
        overrides.pop('eim_cert')
        with tempfile.TemporaryDirectory() as empty_dir:
            pki = skill_main.load_pki_from_resources(empty_dir, overrides)
        self.assertIsNone(pki['eim_identity'])


class TestPayloadInjection(unittest.TestCase):
    def test_injected_payload_wins_over_files(self):
        payload = skill_main.load_profile_payload(
            os.path.join(ROOT, 'resources'), '8929901012345678905', 'A0 40 80 01')
        self.assertEqual(payload, bytes.fromhex('A0408001'))

    def test_packaged_payload_used_when_not_injected(self):
        payload = skill_main.load_profile_payload(
            os.path.join(ROOT, 'resources'), '8929901012345678905')
        self.assertGreater(len(payload), 0)


if __name__ == '__main__':
    unittest.main()
