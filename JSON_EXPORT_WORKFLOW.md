# JSON 导出工作流说明

## 概述

本文档说明了 PCAP 分析和 AI 协调的完整数据流。现在系统会自动生成完整的 JSON 数据包文件，并智能合并后发送给 AI 分析。

## 工作流程

### 1. PCAP 分析阶段（pcap_analyzer.py）

当用户选择 PCAP 文件并点击"分析"后：

```
PCAP 文件 → 加载到内存 → 分块（每块50个包）
    ↓
每块分析 (_analyze_chunk)
    ↓
完整 JSON 导出 → 保存到 tmp/chunk_001.json, chunk_002.json ...
    ↓
返回分析结果（包含 json_file 路径）
```

#### 关键变化：
- **JSON 保存位置**：`tmp/chunk_XXX.json`（自动创建）
- **保存格式**：完整的 PacketDecompiler 输出（所有协议层、字段、hex dump）
- **内存管理**：JSON 数据只保存在文件中，不存储在内存的大型数据结构中
- **返回信息**：每个 PACKETS_JSON 结果包含 `json_file` 字段指向实际文件

### 2. GUI 数据传递（ctf_gui.py）

分析完成后，GUI 保存原始分析结果（包含文件路径）：

```python
self.network_analysis_results = results  # 保存原始结果
```

当用户点击"AI深度分析"后，直接传递这些结果给 AI 协调器。

### 3. AI 分析阶段（ai_coordinator.py）

AI 协调器接收分析结果，使用新的 `process_chunked_data()` 方法：

```
接收分析结果
    ↓
检查是否有 json_file 字段
    ↓
是 → 从 tmp 文件夹读取 JSON 文件
    ↓
否 → 使用降级模式（原始分块处理）
    ↓
智能块合并（每3个块合并为1个）
    ↓
为每个合并块构造 prompt（包含完整 JSON 数据）
    ↓
发送给 AI 分析
    ↓
汇总结果 → 最终综合分析
```

## 数据流细节

### PACKETS_JSON 结构

来自 pcap_analyzer.py 的每个 PACKETS_JSON 项：

```python
{
    "type": "PACKETS_JSON",
    "chunk_id": 1,
    "packet_count": 50,
    "json_file": "tmp/chunk_001.json",  # ← 关键字段
    "content": "[JSON数据已保存到文件: tmp/chunk_001.json]",
    "packets_data": [...]  # 本地使用
}
```

### JSON 文件格式（tmp/chunk_001.json）

完整的数据包 JSON 数组，每个包包含：

```json
{
    "packet_id": "1",
    "timestamp": "2015-08-18 10:40:33",
    "packet_length": 1234,
    "protocols": ["eth", "ip", "tcp", "http"],
    "layers": {
        "eth": {
            "fields": {...}
        },
        "ip": {
            "fields": {...}
        },
        "tcp": {
            "fields": {...}
        },
        "http": {
            "fields": {
                "request_method": "POST",
                "request_uri": "/upload.php",
                ...
            }
        }
    },
    "payload": "hex encoded or binary data",
    "raw_hex": "00 01 02 03 ... (hex dump)",
    ...
}
```

## 块合并策略

### 为什么需要合并？

- **防止 token 超限**：直接发送所有块会导致 token 数超过 AI 模型限制
- **保留上下文**：合并块让 AI 看到相邻数据包的关联性
- **提高效率**：一次发送 3 个块，减少 API 调用次数

### 合并策略

1. **收集**：从 `tmp/` 读取所有 `chunk_*.json` 文件
2. **分组**：每 3 个文件为一组（可根据 token 限制调整）
3. **构造 Prompt**：
   - 包含合并块的序列信息
   - 直接嵌入完整 JSON 数据
   - 添加分析任务描述
4. **发送**：一次性发送给 AI（包含多个原始块）
5. **合并**：最后执行综合分析，去重所有发现的 flag

## 使用流程

### 用户视角

1. **选择 PCAP 文件** → 点击"分析"
   - 系统自动生成 `tmp/chunk_*.json` 文件
   - 分析结果显示在表格中

2. **点击"AI深度分析"**
   - 系统使用保存的分析结果
   - 自动读取 JSON 文件

3. **配置 API 并提问**
   - 输入问题或使用默认提示
   - 点击"询问AI"

4. **查看结果**
   - AI 返回的 flag 列表
   - 完整的分析报告

## 关键改进点

| 改进项 | 之前 | 现在 |
|--------|------|------|
| 发送给 AI 的数据 | 元数据 + 小摘要 | 完整 JSON 数据 |
| 数据存储位置 | 全在内存 | JSON 文件 + 内存 |
| 数据量 | 极少（KB 级） | 完整（MB 级） |
| AI 分析质量 | 低（数据不足） | 高（完整信息） |
| 块处理方式 | 逐块发送 | 智能合并后发送 |
| Token 管理 | 无 | 有（50KB 限制） |

## 文件位置

```
d:\Python_Project\traffic\
├── tmp/                          ← JSON 文件保存位置
│   ├── chunk_001.json
│   ├── chunk_002.json
│   └── ...
├── analyzers/
│   └── pcap_analyzer.py         ← 产生 JSON 文件
├── ai_coordinator.py            ← 读取 JSON 文件
├── ctf_gui.py                  ← GUI 传递数据
└── main.py                     ← 程序入口
```

## 故障排查

### 问题：AI 收到的数据仍然是旧格式
**解决**：清理 Python 缓存
```powershell
Remove-Item -Path __pycache__, analyzers/__pycache__ -Recurse -Force
```

### 问题：tmp 文件夹没有生成 JSON
**检查**：
1. PCAP 文件是否成功加载
2. 是否有足够的磁盘空间
3. 查看分析日志中的 JSON 导出信息

### 问题：AI 仍然超 token 限制
**调整**：修改 ai_coordinator.py 中的 `chunk_size` 参数（默认 3）
```python
chunk_size = 2  # 改为合并 2 个块而不是 3 个
```

## 性能预期

- **PCAP 大小 10MB**：约 200 个数据包 → 4 个块 → 2 个合并批次
- **每个合并批次处理时间**：10-30 秒（取决于 AI 响应）
- **总耗时**：1-3 分钟（包括 API 调用和综合分析）

## 下一步优化

1. **动态 token 计算**：根据实际 token 数自动调整块大小
2. **增量分析**：记录已分析的块，避免重复分析
3. **缓存机制**：缓存 AI 响应以加速重复查询
4. **多线程处理**：并行处理多个合并批次（需谨慎处理 API 限流）
