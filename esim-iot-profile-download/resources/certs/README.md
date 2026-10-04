# 证书文件目录

## 已复制的证书文件

从 Java 测试平台复制的证书文件：

### DPauth 证书（用于 InitiateAuthentication 签名）
- `SK_S_SM_DPauth_ECDSA_NIST.pem` - DPauth 私钥 (PEM 格式)
- `CERT_S_SM_DPauth_ECDSA_NIST.der` - DPauth 证书 (DER 格式)

### DP Profile Binding 证书（用于 BPP 签名）
- `SK_S_SM_DPpb_ECDSA_NIST.pem` - DP Profile Binding 私钥 (PEM 格式)
- `CERT_S_SM_DPpb_ECDSA_NIST.der` - DP Profile Binding 证书 (DER 格式)

### CI 根证书（信任根）
- `CERT_CI_ECDSA_NIST.pem` - CI 根证书 (PEM 格式)

## 证书验证

```bash
# 验证 CI 根证书
openssl x509 -in CERT_CI_ECDSA_NIST.pem -inform PEM -subject -issuer -noout

# 验证 DPauth 证书
openssl x509 -in CERT_S_SM_DPauth_ECDSA_NIST.der -inform DER -subject -issuer -noout

# 验证 DP Profile Binding 证书
openssl x509 -in CERT_S_SM_DPpb_ECDSA_NIST.der -inform DER -subject -issuer -noout

# 验证证书链
openssl verify -CAfile CERT_CI_ECDSA_NIST.pem CERT_S_SM_DPauth_ECDSA_NIST.der
openssl verify -CAfile CERT_CI_ECDSA_NIST.pem CERT_S_SM_DPpb_ECDSA_NIST.der
```

## 来源

这些证书来自 Java 测试平台：
```
***REMOVED***/source/iot-test-platform/case-factory/perftest/IOT_PERF_TEST_Install_Enable_Profile/src/main/resources/sgp26/Valid Test Cases/
```
