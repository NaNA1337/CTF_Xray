# CTF X-Ray 分析工具

一个基于AI的CTF网络流量分析工具，专门用于PCAP文件中的flag识别和提取。

## 功能特性

### 核心功能

- **PCAP文件分析** - 支持PCAP格式网络流量分析
- **AI驱动的Flag识别** - 使用iFlow AI模型进行智能flag检测
- **多协议支持** - HTTP、DNS、TCP、ICMP等协议分析
- **日志文件分析** - 支持从日志和文本文件中识别flag
- **深度数据提取** - 详细的TCP流、HTTP内容、DNS查询提取

### 对话功能

- **多轮对话支持** - 维持完整的对话历史上下文
- **灵活的AI交互** - 支持自然语言指令，AI根据用户提示灵活回复
- **对话历史管理** - 清晰的UI展示对话历史

### Flag检测

- **8种正则模式匹配**
  - `flag{...}`、`FLAG{...}`
  - `ctf{...}`、`CTF{...}`
  - 长字符串识别
  - MD5/SHA1/SHA256哈希值检测

- **优先级处理**
  - FLAG_REGEX_MATCH (最高)
  - TCP_STREAM
  - HTTP
  - DNS
  - ICMP
  - ALL_DATA (最低)

### 大数据处理

- **分批处理** - 超过50KB自动分批，避免token超限
- **上下文窗口管理** - 支持256K和128K两个上下文规模
- **动态内容截断** - 根据token限制动态调整数据量


## 项目结构

```
CTF_Xray/
├── main.py                  # 主程序入口
├── ctf_gui.py              # GUI界面（PySide6）
├── ai_coordinator.py       # AI协调和提示词构造
├── requirements.txt        # 项目依赖
├── analyzers/
│   ├── file_analyzer.py   # 文件分析器
│   ├── log_analyzer.py    # 日志分析器
│   └── pcap_analyzer.py   # PCAP分析器（核心）
└── README.md              # 本文件
```

## 安装

### 1. 克隆项目

```bash
git clone https://github.com/NaNA1337/CTF_Xray.git
cd CTF_Xray
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置API密钥

在GUI中配置iFlow API密钥：
- 获取API密钥：https://platfrom.iflow.cn
- 在设置中输入密钥和模型名称

## 使用方法

### 启动应用

```bash
python main.py
```

### 基本工作流

1. **选择分析文件**
   - 支持PCAP、日志、文本等文件格式
   - 点击"选择文件"按钮选择目标文件

2. **配置AI参数**
   - 输入iFlow API密钥
   - 可选：输入自定义模型名称（默认: TBStars2-200B-A13B）

3. **设置分析提示词**
   - 在"提示词"输入框输入分析要求
   - 例如：`请找出所有flag格式的内容`
   - AI会根据你的提示词灵活调整分析方式

4. **执行分析**
   - 点击"开始分析"按钮
   - 查看实时分析结果

5. **查看结果**
   - **Flag结果**: 展示识别到的所有flag
   - **推理过程**: AI的分析思路和判断依据
   - **对话历史**: 完整的分析对话记录

#### 清除历史

- 点击"清空历史"按钮清除对话历史
- 开始新的分析过程

## Flag识别能力

### 支持的Flag格式

| 格式 | 示例 | 识别方式 |
|------|------|--------|
| 标准flag | `flag{abc123}` | 正则匹配 |
| 大写FLAG | `FLAG{ABC123}` | 正则匹配 |
| CTF格式 | `ctf{secret}` | 正则匹配 |
| 哈希值 | MD5/SHA1/SHA256 | 哈希识别+包装 |
| 长字符串 | 50+ 字符纯字符串 | 长度判断 |

### AI响应格式

AI会自动识别多种响应格式：

- **JSON格式**: `{"flag": "...", "reason": "..."}`
- **纯文本格式**: 自动从响应中提取flag{...}等格式
- **key:value格式**: `flag: xxx` 这样的格式

## 数据处理流程

```
选择文件
  ↓
分析器处理（PCAP/日志/文件）
  ├─ 正则flag匹配 (FLAG_SEARCH)
  ├─ TCP流提取 (TCP_STREAM)
  ├─ HTTP内容提取 (HTTP)
  ├─ DNS查询提取 (DNS_FLAG)
  ├─ ICMP数据提取 (ICMP_DATA)
  └─ 其他数据 (ALL_DATA)
  ↓
按优先级组织数据
  ↓
构造AI提示词
  ├─ 网络流量数据 → 详细信息展示
  ├─ 日志/文件 → 列表展示
  └─ 用户提示词 → 作为分析指导
  ↓
调用iFlow API
  ├─ 小数据 (<50KB) → 单次处理
  └─ 大数据 (>50KB) → 分批处理
  ↓
解析AI响应
  ├─ JSON解析
  ├─ Regex提取 (flag{...})
  ├─ 哈希识别
  └─ Key:value解析
  ↓
GUI展示结果
```

