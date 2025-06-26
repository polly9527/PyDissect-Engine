import os
import re
import sys
import time

import google.generativeai as genai
from dotenv import load_dotenv

# --- Initial Setup ---

# Load environment variables from a .env file
load_dotenv()

# Get API Key from environment
API_KEY = os.getenv("GEMINI_API_KEY")

# --- Proxy Configuration ---
PROXY_HOST = "127.0.0.1"
PROXY_PORT = "10809"
if PROXY_HOST and PROXY_PORT:
    proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
    os.environ['HTTP_PROXY'] = proxy_url
    os.environ['HTTPS_PROXY'] = proxy_url
    print(f"Proxy has been set to: {proxy_url}")
else:
    print("Warning: Proxy not configured. Proceeding without a proxy.")

# --- File and Model Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WIRESHARK_DISSECTORS_DIR = os.path.join(SCRIPT_DIR, "dissectors")
HTML_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "protocol_analysis")
DETECTORS_OUTPUT_DIR = os.path.join(SCRIPT_DIR, "detectors")
ERROR_LOG_FILE = os.path.join(SCRIPT_DIR, "ERROR.log")
GEMINI_MODEL_NAME = 'gemini-1.5-pro-latest'

# --- Load Parser Writing Guide ---
PARSER_GUIDE_FILE_PATH = os.path.join(SCRIPT_DIR, "自定义协议解析器编写说明.html")

def read_file_content(file_path):
    """Reads file content with fallback encoding."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            print(f"Error: Could not read file {file_path}: {e}")
            return None

PARSER_GUIDE = read_file_content(PARSER_GUIDE_FILE_PATH)

# --- Prompts ---
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

# --- Utility Functions ---

def log_error_and_exit(message):
    """Logs a fatal error to a file and exits the script."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] FATAL: {message}\n"
    try:
        with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(full_message)
        print(f"A fatal error occurred. Details logged to {ERROR_LOG_FILE}. Exiting.")
    except Exception as e:
        print(f"Failed to write to error log: {e}")
        print(f"Original fatal error: {full_message}")
    sys.exit(1)

def call_gemini_api(prompt_text, model, guide=None, request_timeout=600):
    """
    Calls the Gemini API, providing status updates on the data stream process.
    """
    print(f"  API请求发送中... (超时: {request_timeout}秒)")
    full_response_text = ""
    error_message = None

    try:
        content_to_send = [prompt_text]
        if guide:
            content_to_send.append(guide)

        stream_start_time = time.time()
        print(f"  [{time.strftime('%H:%M:%S')}] 开始从 API 接收数据流...")

        response = model.generate_content(
            content_to_send,
            stream=True,
            request_options={"timeout": request_timeout}
        )

        response_chunks = []
        total_chars_received = 0
        last_print_time = time.time()

        # Silently collect all response chunks while counting characters
        for chunk in response:
            if chunk.text:
                total_chars_received += len(chunk.text)
                response_chunks.append(chunk.text)
            
            # Print status update every 10 seconds
            current_time = time.time()
            if current_time - last_print_time >= 10:
                print(f"\r  > [进行中] 已接收: {total_chars_received} 字符...", end="", flush=True)
                last_print_time = current_time
        
        full_response_text = "".join(response_chunks)
        stream_end_time = time.time()
        total_duration = stream_end_time - stream_start_time

        # Clear the in-progress line before printing the final summary
        print(f"\r{' ' * 80}\r", end="")

        print(f"  [{time.strftime('%H:%M:%S')}] 数据流接收完毕。")
        print(f"  > 总计接收字符: {total_chars_received} | 总计耗时: {total_duration:.2f} 秒")

        # Check for blocking reasons after the stream is complete
        if hasattr(response, 'prompt_feedback') and response.prompt_feedback.block_reason:
            error_message = f"Request was blocked. Reason: {response.prompt_feedback.block_reason}"
            return None, error_message

        if not full_response_text:
            print("  警告: API 返回了空的数据流。")

        return full_response_text, None

    except Exception as e:
        print(f"\n  Gemini API 调用或流式处理失败。错误: {e}")
        error_message = f"API call exception: {str(e)}"
        return None, error_message

def save_output_file(content, output_path):
    """Saves content to a file, creating directories if needed."""
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  > 已成功保存文件到: {output_path}")
        return output_path
    except Exception as e:
        log_message = f"Failed to save file {output_path}: {e}"
        print(f"Error: {log_message}")
        with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f_err:
            f_err.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {log_message}\n")
        return None

def clean_python_code(raw_code):
    """Removes markdown code block fences from a string."""
    return re.sub(r"^```python\s*([\s\S]*?)\s*```$", r"\1", raw_code.strip(), flags=re.MULTILINE)

# --- Main Execution ---

def main():
    """Main function to run the two-step generation process."""
    if not API_KEY:
        log_error_and_exit("GEMINI_API_KEY is not configured. Please set it in your .env file.")

    if PARSER_GUIDE is None:
        log_error_and_exit(f"Could not load the parser guide file ({PARSER_GUIDE_FILE_PATH}).")

    try:
        genai.configure(api_key=API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        print(f"Successfully configured and connected to Gemini model: {GEMINI_MODEL_NAME}")
    except Exception as e:
        log_error_and_exit(f"Failed to initialize Gemini model: {e}")

    # --- Step 1: Generate HTML Analysis Reports from C Source ---
    print("\n--- Step 1: Generating HTML Analysis Reports from C Source ---")
    if not os.path.exists(WIRESHARK_DISSECTORS_DIR):
        log_error_and_exit(f"Input directory '{WIRESHARK_DISSECTORS_DIR}' does not exist.")

    c_files = [f for f in os.listdir(WIRESHARK_DISSECTORS_DIR) if f.startswith("packet-") and f.endswith(".c")]

    for filename in c_files:
        protocol_name_match = re.search(r'packet-(.+)\.c', filename)
        if not protocol_name_match:
            continue
        protocol_name = protocol_name_match.group(1).upper().replace('-', '_')
        print(f"\nProcessing protocol: {protocol_name} (File: {filename})")

        html_file_path = os.path.join(HTML_OUTPUT_DIR, f"{protocol_name}_analysis.html")
        if os.path.exists(html_file_path):
            print(f"Analysis report already exists, skipping HTML generation: {html_file_path}")
            continue

        c_file_path = os.path.join(WIRESHARK_DISSECTORS_DIR, filename)
        code = read_file_content(c_file_path)
        if not code:
            print(f"Could not read content from {filename}, skipping.")
            continue
        
        print(f"Generating HTML analysis report for {protocol_name}...")
        # FIX: Define prompt1 by formatting the template with the file's code
        prompt1 = PROMPT_TEMPLATE_1_HTML.format(code=code)
        html_content, error_message = call_gemini_api(prompt1, model)
        
        if html_content:
            save_output_file(html_content, html_file_path)
        else:
            print(f"Error: API call to generate HTML for {protocol_name} failed. Error: {error_message}")

    # --- Step 2: Generate Python Parsers from HTML Analysis Reports ---
    print("\n--- Step 2: Generating Python Parsers from HTML Analysis Reports ---")
    if not os.path.exists(HTML_OUTPUT_DIR) or not os.listdir(HTML_OUTPUT_DIR):
        log_error_and_exit(f"Analysis report directory '{HTML_OUTPUT_DIR}' is empty. Cannot generate parsers.")

    html_files = [f for f in os.listdir(HTML_OUTPUT_DIR) if f.endswith("_analysis.html")]

    for filename in html_files:
        protocol_name_match = re.search(r'(.+)_analysis\.html', filename)
        if not protocol_name_match:
            continue
        protocol_name = protocol_name_match.group(1)
        
        detector_filename = f"{protocol_name.lower().replace('-', '_')}_detector.py"
        detector_filepath = os.path.join(DETECTORS_OUTPUT_DIR, detector_filename)

        if os.path.exists(detector_filepath):
            print(f"\nParser already exists, skipping Python code generation: {detector_filepath}")
            continue

        print(f"\nProcessing report: {filename} (Protocol: {protocol_name})")
        html_file_path = os.path.join(HTML_OUTPUT_DIR, filename)
        html_content = read_file_content(html_file_path)
        if not html_content:
            print(f"Could not read content from {filename}, skipping.")
            continue

        print(f"Generating Python parser code for {protocol_name}...")
        prompt2 = PROMPT_TEMPLATE_2_PY.format(html_content=html_content)
        python_code, error_message = call_gemini_api(prompt2, model, guide=PARSER_GUIDE)

        if python_code:
            cleaned_code = clean_python_code(python_code)
            save_output_file(cleaned_code, detector_filepath)
        else:
            print(f"Error: API call to generate Python code for {protocol_name} failed. Error: {error_message}")
            
    print("\n--- All tasks completed ---")

if __name__ == "__main__":
    main()
