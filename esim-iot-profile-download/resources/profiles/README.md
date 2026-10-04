# Profile 文件目录

## 已复制的 Profile 文件

从 Java 测试平台复制的 Profile 文件：

- `PROFILE_OPERATIONAL1_8929901012345678905F.HEX` - UPP (User Profile Package)，十六进制文本格式

## 文件格式

### 十六进制文本格式 (.HEX)
```
A040800102810103821447534D412050726F66696C65205061636B616765...
```

### 二进制格式 (.bin)
```
[二进制数据]
```

## 文件命名规则

1. **按 ICCID 匹配**（优先级最高）：
   - `PROFILE_OPERATIONAL1_8929901012345678905F.HEX`
   - `PROFILE_OPERATIONAL1_8929901012345678905.bin`

2. **默认文件**（当没有 ICCID 匹配时）：
   - `PROFILE_OPERATIONAL1.HEX`
   - `PROFILE_OPERATIONAL1.bin`

## 来源

这个 Profile 文件来自 Java 测试平台：
```
***REMOVED***/source/iot-test-platform/case-factory/perftest/IOT_PERF_TEST_Install_Enable_Profile/src/main/resources/profiles/PROFILE_OPERATIONAL1_8929901012345678905F.HEX
```

## 查看 Profile 内容

```bash
# 查看文件内容（十六进制）
cat PROFILE_OPERATIONAL1_8929901012345678905F.HEX

# 转换为二进制并查看
xxd PROFILE_OPERATIONAL1_8929901012345678905F.HEX | head -20

# 查看文件大小
ls -lh PROFILE_OPERATIONAL1_8929901012345678905F.HEX
```
