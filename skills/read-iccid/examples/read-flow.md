# ICCID 读取示例

## 示例 1：标准流程

### 请求

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "method": "skill.init",
  "params": {
    "skillId": "read.iccid",
    "input": {"readerId": "reader-01"}
  }
}
```

### 响应

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "result": {
    "sessionId": "5f1c2d7e-8a9b-4c3d-9e0f-123456789abc",
    "manifest": {
      "skillId": "read.iccid",
      "name": "读取 ICCID",
      "description": "读取 SIM 卡的 ICCID（集成电路卡标识符）",
      "version": "1.0.0",
      "requiresReader": true,
      "supportsSession": true
    },
    "status": "INITIALIZED"
  }
}
```

## 示例 2：完整执行流程

### Step 1: SELECT MF

**请求:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-2",
  "method": "skill.start",
  "params": {"sessionId": "5f1c2d7e-..."}
}
```

**响应:**
```json
{
  "sessionId": "5f1c2d7e-...",
  "status": "CONTINUE",
  "nextAction": {
    "actionId": "read.iccid.select-mf",
    "type": "APDU",
    "name": "选择主文件",
    "description": "SELECT MF (3F00)",
    "payload": {"apdu": "00A40000023F00"}
  }
}
```

### Step 2: SELECT EF_ICCID

**请求:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-3",
  "method": "skill.handleActionResult",
  "params": {
    "sessionId": "5f1c2d7e-...",
    "result": {
      "actionId": "read.iccid.select-mf",
      "type": "APDU_RESULT",
      "status": "OK",
      "data": {"response": "", "sw": "9000"}
    }
  }
}
```

**响应:**
```json
{
  "sessionId": "5f1c2d7e-...",
  "status": "CONTINUE",
  "nextAction": {
    "actionId": "read.iccid.select-iccid",
    "type": "APDU",
    "name": "选择 ICCID 文件",
    "description": "SELECT EF_ICCID (2FE2)",
    "payload": {"apdu": "00A40000022FE2"}
  }
}
```

### Step 3: READ BINARY

**请求:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-4",
  "method": "skill.handleActionResult",
  "params": {
    "sessionId": "5f1c2d7e-...",
    "result": {
      "actionId": "read.iccid.select-iccid",
      "type": "APDU_RESULT",
      "status": "OK",
      "data": {"response": "", "sw": "9000"}
    }
  }
}
```

**响应:**
```json
{
  "sessionId": "5f1c2d7e-...",
  "status": "CONTINUE",
  "nextAction": {
    "actionId": "read.iccid.read-binary",
    "type": "APDU",
    "name": "读取 ICCID 数据",
    "description": "READ BINARY (10 字节)",
    "payload": {"apdu": "00B000000A"}
  }
}
```

### Step 4: 完成

**请求:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-5",
  "method": "skill.handleActionResult",
  "params": {
    "sessionId": "5f1c2d7e-...",
    "result": {
      "actionId": "read.iccid.read-binary",
      "type": "APDU_RESULT",
      "status": "OK",
      "data": {"response": "986810325476981032F3", "sw": "9000"}
    }
  }
}
```

**响应:**
```json
{
  "sessionId": "5f1c2d7e-...",
  "status": "SUCCESS",
  "data": {
    "iccid": "898601234567890123"
  }
}
```
