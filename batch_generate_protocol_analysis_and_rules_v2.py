import os
import json
import re
import time
import sys
import google.generativeai as genai
from dotenv import load_dotenv

# 加载 .env 文件中的环境变量
load_dotenv() 

# 从环境变量中读取 API_KEY
API_KEY = os.getenv("GEMINI_API_KEY")

# --- 代理设置 ---
PROXY_HOST = "127.0.0.1"
PROXY_PORT = "10809"
if PROXY_HOST and PROXY_PORT:
    proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
    os.environ['HTTP_PROXY'] = proxy_url
    os.environ['HTTPS_PROXY'] = proxy_url
    print(f"已设置代理: {proxy_url}")
else:
    print("警告: 未配置代理，将不使用代理。")

# --- 配置 ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 步骤1输入
WIRESHARK_DISSECTORS_DIR = os.path.join(SCRIPT_DIR, "dissectors")
# 步骤1输出 / 步骤2输入
HTML_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "protocol_analysis")
# 步骤2输出 (已按您的要求修改)
DETECTORS_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "detectors")
ERROR_LOG_FILE = os.path.join(SCRIPT_DIR, "ERROR.log")
# 加载 .env 文件中的环境变量
load_dotenv() 

# 从环境变量中读取 API_KEY
API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL_NAME = 'gemini-2.5-flash-preview-05-20'

# --- 动态加载解析器编写说明 ---
PARSER_GUIDE_FILE_PATH = os.path.join(SCRIPT_DIR, "自定义协议解析器编写说明.html")

def read_file_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            print(f"错误：无法读取文件 {file_path}: {e}")
            return None

PARSER_GUIDE = read_file_content(PARSER_GUIDE_FILE_PATH)

# --- 提示词 (经检查，无需修改) ---
PROMPT_TEMPLATE_1_HTML = """
请基于提供的 Wireshark 解析器 C 语言源代码，深入分析其协议识别与解析机制，并按照以下要求生成独立的 HTML 文件内容。

文件一：XX协议启发式识别分析（单包）.html
目标：详细分析该代码中用于单包识别的启发式函数逻辑。
内容要求：
1. Mermaid 流程图: 根据启发式函数的逻辑，生成 Mermaid graph TD 格式的流程图伪代码。
2. 关键宏定义: 以表格形式，列出并说明在启发式检测中使用的关键 C 语言宏。
3. 检测方法总结: 用不依赖代码的语言描述该启发式检测方法，并提供一个符合检测逻辑的 16 进制样例数据。
4. 启发式函数源码: 完整提取启发式函数相关的源代码。

文件二：XX解析器高级功能分析.html
目标：分析代码中超越单包识别的、有状态的、跨包的协议分析功能。
内容要求：如果代码中包含TCP 流重组、会话跟踪等高级功能，请创建此文件并分析其实现原理和代码逻辑。

文件三：XX协议端口注册信息.html
目标：整理代码中用于协议识别的所有标准及周知端口。
内容要求：如果代码注册了任何端口号，请创建此文件，并以表格形式清晰地列出所有注册的端口信息（端口号、传输层协议、关联协议名称）。

通用要求：
- 所有内容始终使用简体中文回答。
- 所有 HTML 文件需注意格式美化，确保内容清晰、易于阅读。
- 将以上三个文件的内容合并成一个单独的、完整的 HTML 文档。

以下是 Wireshark 解析器代码：
{code}
"""
PROMPT_TEMPLATE_2_PY = """
作为一名专业的网络协议分析和Python开发工程师，请严格遵循以下两个文档，生成一个功能完整的Python协议解析器文件。

**文档一：协议解析器编写规范 (附件)**
这是编写解析器必须遵守的规则、函数签名、文件结构和设计要点。你必须严格按照此规范生成代码。

**文档二：协议分析报告 (如下)**
这份HTML报告详细描述了目标协议的识别逻辑、端口信息和关键字段。你需要从中提取所有必要信息来填充代码逻辑。

**你的任务：**

1.  **通读并理解** 上述两个文档。
2.  **生成一个完整的 Python 文件内容**。该文件应包含：
    * 一个高效的 `is_...` **协议识别函数**，基于分析报告中的“启发式识别”逻辑。
    * 一个详细的 `parse_...` **协议解析函数**，解析报告中提到的关键字段。
    * 一个核心的 `register()` **注册函数**，正确填写协议 `name` 和 `subscriptions`（从报告中提取端口信息）。
3.  **代码要求**：
    * 代码必须健壮，包含 `try...except` 块来处理解析错误。
    * 所有函数签名和返回类型必须与规范文档中的定义完全一致。
    * 最终的输出**只能包含纯粹的 Python 代码**。不要包含任何解释性文字或 Markdown 代码块标记 (例如 ```python ... ```)。

**协议分析报告内容如下:**
{html_content}
"""

# --- 错误记录和退出函数 ---
def log_error_and_exit(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] 错误: {message}\n"
    try:
        with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(full_message)
        print(f"严重错误已记录到 {ERROR_LOG_FILE}。程序即将中止。")
    except Exception as e:
        print(f"写入错误日志失败: {e}")
        print(f"原始错误信息: {full_message}")
    sys.exit(1)

# --- API 调用函数 (流式) ---
def call_gemini_api(prompt_text, model, guide=None, request_timeout=300):
    print(f"  API请求发送中 (流式)... (等待最多 {request_timeout} 秒)")
    full_response_text = ""
    error_message = None

    try:
        content_to_send = [prompt_text]
        if guide:
            content_to_send.append(guide)

        response = model.generate_content(
            content_to_send,
            stream=True,
            request_options={"timeout": request_timeout}
        )

        response_chunks = []
        print("  AI回复 (流式): ", end="", flush=True)
        for chunk in response:
            if chunk.text:
                print(chunk.text, end="", flush=True)
                response_chunks.append(chunk.text)
        
        print() 

        full_response_text = "".join(response_chunks)

        if hasattr(response, 'prompt_feedback') and response.prompt_feedback.block_reason:
            error_message = f"请求可能因安全原因被阻止。原因: {response.prompt_feedback.block_reason}"
            return None, error_message

        if not full_response_text:
            if not hasattr(response, 'candidates') or not response.candidates:
                error_message = "API响应中没有候选内容。"
                return None, error_message
        
        return full_response_text, None

    except Exception as e:
        print(f"\n  Gemini API 调用或流式处理失败。错误: {e}")
        error_message = f"API调用异常: {str(e)}"
        return None, error_message


# --- 文件保存函数 ---
def save_output_file(content, output_path):
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"已成功保存文件到: {output_path}")
        return output_path
    except Exception as e:
        log_message = f"保存文件 {output_path} 失败: {e}"
        print(f"错误: {log_message}")
        with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f_err:
            f_err.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 错误: {log_message}\n")
        return None

def clean_python_code(raw_code):
    return re.sub(r"^```python\s*([\s\S]*?)\s*```$", r"\1", raw_code.strip(), flags=re.MULTILINE)

# --- 主函数 ---
def main():
    if not API_KEY or "YOUR_API_KEY" in API_KEY:
        log_error_and_exit("API_KEY 未配置或为默认占位符。")

    if PARSER_GUIDE is None:
        log_error_and_exit(f"未能加载解析器编写说明文件 ({PARSER_GUIDE_FILE_PATH})。")

    try:
        genai.configure(api_key=API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        print(f"已成功配置并连接到 Gemini 模型: {GEMINI_MODEL_NAME}")
    except Exception as e:
        log_error_and_exit(f"初始化 Gemini 模型失败: {e}")

    # --- 步骤 1: 从 C 源码生成 HTML 分析报告 ---
    print("\n--- 步骤 1: 从 C 源码生成 HTML 分析报告 ---")
    if not os.path.exists(WIRESHARK_DISSECTORS_DIR):
        log_error_and_exit(f"输入目录 '{WIRESHARK_DISSECTORS_DIR}' 不存在。")

    c_files = [f for f in os.listdir(WIRESHARK_DISSECTORS_DIR) if f.startswith("packet-") and f.endswith(".c")]

    for filename in c_files:
        protocol_name_match = re.search(r'packet-(.+)\.c', filename)
        if not protocol_name_match: continue
        protocol_name = protocol_name_match.group(1).upper().replace('-', '_')
        print(f"\n处理协议: {protocol_name} (文件: {filename})")

        html_file_path = os.path.join(HTML_OUTPUT_DIR, f"{protocol_name}_analysis.html")
        if os.path.exists(html_file_path):
            print(f"发现已存在的分析报告: {html_file_path}，跳过HTML生成。")
            continue

        c_file_path = os.path.join(WIRESHARK_DISSECTORS_DIR, filename)
        code = read_file_content(c_file_path)
        if not code:
            print(f"未能读取文件 {filename} 的内容，跳过。")
            continue
        
        print(f"正在为 {protocol_name} 生成 HTML 分析报告...")
        prompt1 = PROMPT_TEMPLATE_1_HTML.format(code=code)
        html_content, error_message = call_gemini_api(prompt1, model)
        
        if html_content:
            save_output_file(html_content, html_file_path)
        else:
            print(f"错误: 为协议 {protocol_name} 生成HTML内容的API调用失败。错误: {error_message}")


    # --- 步骤 2: 从 HTML 分析报告生成 Python 解析器 ---
    print("\n--- 步骤 2: 从 HTML 分析报告生成 Python 解析器 ---")
    if not os.path.exists(HTML_OUTPUT_DIR) or not os.listdir(HTML_OUTPUT_DIR):
        log_error_and_exit(f"分析报告目录 '{HTML_OUTPUT_DIR}' 为空，无法生成解析器。请确保步骤1成功执行。")

    html_files = [f for f in os.listdir(HTML_OUTPUT_DIR) if f.endswith("_analysis.html")]

    for filename in html_files:
        protocol_name_match = re.search(r'(.+)_analysis\.html', filename)
        if not protocol_name_match: continue
        protocol_name = protocol_name_match.group(1)
        
        detector_filename = f"{protocol_name.lower().replace('-', '_')}_detector.py"
        detector_filepath = os.path.join(DETECTORS_OUTPUT_DIR, detector_filename)

        if os.path.exists(detector_filepath):
            print(f"发现已存在的解析器: {detector_filepath}，跳过Python代码生成。")
            continue

        print(f"\n处理报告: {filename} (协议: {protocol_name})")
        html_file_path = os.path.join(HTML_OUTPUT_DIR, filename)
        html_content = read_file_content(html_file_path)
        if not html_content:
            print(f"未能读取文件 {filename} 的内容，跳过。")
            continue

        print(f"正在为 {protocol_name} 生成 Python 解析器代码...")
        prompt2 = PROMPT_TEMPLATE_2_PY.format(html_content=html_content)
        python_code, error_message = call_gemini_api(prompt2, model, guide=PARSER_GUIDE)

        if python_code:
            cleaned_code = clean_python_code(python_code)
            save_output_file(cleaned_code, detector_filepath)
        else:
            print(f"错误: 为协议 {protocol_name} 生成Python代码的API调用失败。错误: {error_message}")
            
    print("\n--- 所有任务处理完毕 ---")

if __name__ == "__main__":
    main()