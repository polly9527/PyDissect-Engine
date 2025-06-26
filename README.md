# AI-Powered Extensible Network Protocol Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

这是一个基于 AI 驱动的、可扩展的网络流量协议检测与分析框架。项目包含两个核心组件：一个用于实时流量捕获与协议识别的**检测引擎**，和一个利用大语言模型（LLM）自动从 Wireshark C 源码生成新协议解析器的**规则工厂**。

## 核心理念

本项目的创新之处在于其“规则生成自动化”的工作流，旨在解决传统流量检测工具协议库更新慢、自定义协议支持难的问题。

```
+------------------+     +--------------------------+     +----------------------+
| Wireshark C 源码 | --> |  规则工厂 (batch_...py)  | --> |  Python 解析器 .py   |
|  (dissectors/)   |     | (LLM-Powered Analysis)   |     |    (detectors/)      |
+------------------+     +--------------------------+     +----------+-----------+
                                                                     |
                                                                     | (Loads)
                                                                     |
                                                         +-----------v-----------+
                                                         |  检测引擎 (traffic...) |
                                                         +-----------+-----------+
                                                                     | (Analyzes)
                                                                     |
                                                         +-----------v-----------+
                                                         |    实时网络流量        |
                                                         +-----------------------+
```

1.  **规则工厂 (`batch_generate_protocol_analysis_and_rules_v2.py`)**: 读取 Wireshark 的 C 语言解析器源码，利用 Gemini AI 深度分析协议的识别逻辑、端口和关键结构，自动生成符合本框架规范的 Python 解析器文件。
2.  **检测引擎 (`traffic_detector_v2.py`)**: 一个高性能的实时流量嗅探器。它动态加载 `detectors` 目录下的所有 Python 解析器，并利用它们来识别和解析实时网络流量，最终输出结构化的日志。

## 主要特性

- **AI 驱动**: 自动将 Wireshark 的专家知识转化为可执行的 Python 解析器。
- **高度可扩展**: 只需提供新的 Wireshark 解析器 C 源码，即可自动为新协议添加支持，无需手动编写识别代码。
- **高性能**: 检测引擎采用基于端口的高效分发策略，避免对每个数据包运行所有解析器。
- **实时统计**: 在控制台周期性地输出运行状态，包括处理速度（PPS）和各协议命中次数。
- **结构化日志**: 将识别出的协议数据以 JSON 格式输出到独立的日志文件中，便于后续分析。
- **安全可靠**: 默认使用环境变量管理 API 密钥，保障您的凭据安全。

## 目录结构

```
.
├── dissectors/             # [输入] 存放 Wireshark 的 C 语言协议解析器源码 (*.c)
├── protocol_analysis/      # [中间产物] 存放 AI 生成的 HTML 协议分析报告
├── detectors/              # [最终产物] 存放 AI 生成的 Python 解析器 (*.py)
├── log/                    # [日志] 存放检测引擎的运行日志和错误日志
├── traffic_detector_v2.py  # [核心] 实时流量检测引擎
├── batch_generate_protocol_analysis_and_detectors_v2.py # [核心] AI 规则生成工厂
├── 自定义协议解析器编写说明.html # 手动编写解析器的规范文档
├── README.md               # 本文档
└── requirements.txt        # Python 依赖列表
```

## 安装与配置

**1. 克隆项目**
```bash
git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
cd your-repo-name
```

**2. 安装系统依赖 (libpcap)**
`pcapy` 库需要 `libpcap` 的支持。

- 在 Debian/Ubuntu 上:
  ```bash
  sudo apt-get update && sudo apt-get install libpcap-dev python3-dev
  ```
- 在 RedHat/CentOS 上:
  ```bash
  sudo yum install libpcap-devel python3-devel
  ```
- 在 macOS 上 (使用 Homebrew):
  ```bash
  brew install libpcap
  ```

**3. 创建并激活 Python 虚拟环境**
```bash
python3 -m venv venv
source venv/bin/activate  # 在 Windows 上使用 `venv\Scripts\activate`
```

**4. 安装 Python 依赖**
```bash
pip install -r requirements.txt
```

**5. 配置 API 密钥**
将 `.env.example` 文件（如果提供）复制为 `.env`，或者手动创建一个 `.env` 文件，并填入您的 Google Gemini API 密钥：
```
GEMINI_API_KEY="YOUR_API_KEY_HERE"
```

## 使用方法

### 流程一：自动生成新的协议解析器

1.  **准备源码**: 将您想要支持的协议的 Wireshark 解析器 C 源码文件（例如 `packet-dns.c`）放入 `dissectors` 文件夹。
2.  **运行规则工厂**:
    ```bash
    python batch_generate_protocol_analysis_and_rules_v2.py
    ```
    脚本会自动执行两个步骤：
    - 首先，在 `protocol_analysis` 目录生成 HTML 分析报告。
    - 然后，根据报告在 `detectors` 目录生成对应的 Python 解析器 `.py` 文件。

### 流程二：运行检测引擎捕获流量

1.  **确保解析器存在**: 确保 `detectors` 目录中已经有您想检测的协议的解析器文件。
2.  **运行检测引擎**:
    网络嗅探需要管理员权限，请使用 `sudo`。
    ```bash
    sudo python traffic_detector_v2.py
    ```
    - 程序会自动选择一个网络接口并开始监听。
    - 控制台会周期性地打印流量统计信息。
    - 识别出的协议数据将被记录在 `log` 文件夹下的对应日志文件中。
