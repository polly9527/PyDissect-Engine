# traffic_detector_v2.py (最终版-错误日志分离)

import pcapy
import dpkt
import os
import logging
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
import time
import importlib
from typing import List, Dict, Any, Optional, Set

# --- 配置常量 ---
DETECTORS_DIR_NAME: str = "detectors"
LOG_DIR_NAME: str = "log"
# 日志格式，用于文件
LOG_FORMAT: str = '%(asctime)s - %(name)s:%(levelname)s - P:%(process)d - T:%(thread)d\n%(message)s'
ERROR_LOG_FILENAME: str = "error.log" # 新增：错误日志文件名

PCAP_SNAPLEN: int = 65536
PCAP_PROMISCUOUS: bool = True
PCAP_TIMEOUT_MS: int = 100
STATS_INTERVAL_SECONDS: int = 60
MIN_ETH_FRAME_SIZE: int = 14

PREFERRED_INTERFACES: List[str] = [
    "eth0", "en0", "以太网", "Ethernet", "WLAN", "wlan0", "Wi-Fi", "wlp", "eno",
]

# --- 日志与统计 ---

def _initialize_bootstrap_logger() -> logging.Logger:
    """
    初始化用于程序启动和捕获全局消息的日志记录器。
    它包含两个处理器：
    1. StreamHandler: 将所有INFO及以上级别的信息打印到控制台。
    2. RotatingFileHandler: 将所有ERROR及以上级别的信息写入到单独的 error.log 文件中。
    """
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_DIR_NAME)
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("BootstrapTrafficDetector")
    logger.setLevel(logging.INFO)  # 设置记录器捕获INFO及以上级别
    logger.propagate = False

    # 防止重复添加处理器
    if logger.hasHandlers():
        logger.handlers.clear()

    # 1. 控制台处理器 (INFO 及以上)
    console_formatter = logging.Formatter('%(asctime)s [%(levelname)s] (Bootstrap) %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(console_formatter)
    logger.addHandler(stream_handler)

    # 2. 错误日志文件处理器 (ERROR 及以上)
    error_log_path = os.path.join(log_dir, ERROR_LOG_FILENAME)
    file_formatter = logging.Formatter(LOG_FORMAT)
    try:
        # 使用 RotatingFileHandler 来防止日志文件过大
        error_file_handler = RotatingFileHandler(
            error_log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8'
        )
        error_file_handler.setLevel(logging.ERROR) # <-- 关键：只记录ERROR级别
        error_file_handler.setFormatter(file_formatter)
        logger.addHandler(error_file_handler)
    except Exception as e:
        # 如果文件处理器创建失败，仍在控制台打印错误
        logger.error(f"无法为错误日志创建文件处理器: {e}")

    return logger


BOOTSTRAP_LOGGER: logging.Logger = _initialize_bootstrap_logger()

def setup_logging(detector_names: Set[str]) -> Dict[str, logging.Logger]:
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_DIR_NAME)
    os.makedirs(log_dir, exist_ok=True)
    formatter = logging.Formatter(LOG_FORMAT)
    loggers: Dict[str, logging.Logger] = {}
    for name in detector_names:
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.handlers = []
        log_file_path = os.path.join(log_dir, f"{name}_detected_{datetime.now().strftime('%Y%m%d')}.log")
        try:
            handler = RotatingFileHandler(log_file_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        except Exception as e:
            BOOTSTRAP_LOGGER.error(f"为协议 '{name}' 创建文件日志处理器失败: {e}")
        logger.propagate = False
        loggers[name] = logger
    return loggers

# --- 其他类和函数保持不变 (TrafficStats, load_detectors, DetectorDispatcher) ---
class TrafficStats:
    def __init__(self, detector_names: Set[str]):
        self.total_packets_processed: int = 0
        self.detector_hits: Dict[str, int] = {name: 0 for name in detector_names}
        self.start_time: float = time.time()
        self.last_print_time: float = self.start_time
    def increment_processed(self): self.total_packets_processed += 1
    def increment_hit(self, name: str):
        if name in self.detector_hits: self.detector_hits[name] += 1
    def print_summary(self):
        elapsed = time.time() - self.start_time
        pps = self.total_packets_processed / elapsed if elapsed > 0 else 0
        msg = f"\n--- 状态更新 ({datetime.now().strftime('%H:%M:%S')}) ---\n" \
              f"  运行时间: {elapsed:.2f} 秒\n" \
              f"  已处理包: {self.total_packets_processed} (均速: {pps:.2f} PPS)\n" \
              f"  协议命中统计:\n"
        for name, count in self.detector_hits.items():
            msg += f"    - {name}: {count} 次\n"
        msg += "  -------------------------------------------"
        BOOTSTRAP_LOGGER.info(msg)
        self.last_print_time = time.time()
def load_detectors(detectors_dir: str) -> List[Dict[str, Any]]:
    loaded_detectors = []
    if not os.path.isdir(detectors_dir):
        BOOTSTRAP_LOGGER.warning(f"识别器目录 '{detectors_dir}' 不存在。")
        return []
    for filename in os.listdir(detectors_dir):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = f"{os.path.basename(detectors_dir)}.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                if hasattr(module, 'register') and callable(module.register):
                    registration_info = module.register()
                    if 'name' in registration_info and 'function' in registration_info:
                        loaded_detectors.append(registration_info)
                        BOOTSTRAP_LOGGER.info(f"成功加载识别器: {registration_info['name']}")
            except Exception as e:
                BOOTSTRAP_LOGGER.error(f"加载识别器 {filename} 失败: {e}")
    return loaded_detectors
class DetectorDispatcher:
    def __init__(self, detectors: List[Dict[str, Any]]):
        self.port_map: Dict[str, Dict[int, List[Dict[str, Any]]]] = {"TCP": {}, "UDP": {}}
        self.build_port_map(detectors)
    def build_port_map(self, detectors: List[Dict[str, Any]]):
        for detector in detectors:
            subs = detector.get("subscriptions", {}).get("port_based", [])
            for sub in subs:
                protocol = sub.get("protocol", "").upper()
                port = sub.get("port")
                if protocol in self.port_map and isinstance(port, int):
                    if port not in self.port_map[protocol]: self.port_map[protocol][port] = []
                    self.port_map[protocol][port].append(detector)
    def dispatch(self, transport_protocol: str, l4_segment: Any) -> Optional[Dict[str, Any]]:
        payload = l4_segment.data
        if not payload: return None
        port_detectors = self.port_map.get(transport_protocol, {})
        detectors_to_run = list({d['name']: d for d in port_detectors.get(l4_segment.sport, []) + port_detectors.get(l4_segment.dport, [])}.values())
        for detector in detectors_to_run:
            if detector["function"](payload, l4_segment.sport, l4_segment.dport):
                return detector
        return None

# --- packet_handler 函数 (无变化) ---
def packet_handler(
    header: Any, pkt_data_l2: bytes, dispatcher: DetectorDispatcher,
    loggers: Dict[str, logging.Logger], stats: TrafficStats
):
    try:
        if len(pkt_data_l2) < MIN_ETH_FRAME_SIZE: return
        
        eth = dpkt.ethernet.Ethernet(pkt_data_l2)
        ip = eth.data

        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return

        l4 = ip.data
        if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)): return
        
        stats.increment_processed()
        payload = l4.data
        if not payload: return

        matched_detector = dispatcher.dispatch(l4.__class__.__name__.upper(), l4)

        if matched_detector:
            name = matched_detector['name']
            stats.increment_hit(name)
            logger = loggers.get(name)
            if not logger: return

            if 'parser_function' in matched_detector:
                parser = matched_detector['parser_function']
                parsed_result = parser(payload)
                
                if parsed_result:
                    src_ip = dpkt.utils.inet_to_str(ip.src)
                    dst_ip = dpkt.utils.inet_to_str(ip.dst)
                    
                    json_output = json.dumps(parsed_result, indent=4, ensure_ascii=False)
                    log_message = (
                        f"Source: {src_ip}:{l4.sport} -> Destination: {dst_ip}:{l4.dport}\n"
                        f"{json_output}\n"
                    )
                    logger.info(log_message)

    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, AttributeError):
        pass
    except Exception as e:
        # 这一行的日志现在会同时输出到控制台和 error.log
        BOOTSTRAP_LOGGER.error(f"处理数据包时发生未知错误: {e}", exc_info=True)


# --- 主执行模块 (无变化) ---
def capture_traffic(interface_name: str, detectors_dir: str):
    detectors = load_detectors(detectors_dir)
    if not detectors:
        BOOTSTRAP_LOGGER.error("未能加载任何有效的协议识别器，脚本终止。")
        return
    dispatcher = DetectorDispatcher(detectors)
    detector_names = {d["name"] for d in detectors}
    loggers = setup_logging(detector_names)
    stats = TrafficStats(detector_names)
    BOOTSTRAP_LOGGER.info(f"已注册 {len(detectors)} 个协议识别器: {list(detector_names)}")
    try:
        cap = pcapy.open_live(interface_name, PCAP_SNAPLEN, PCAP_PROMISCUOUS, PCAP_TIMEOUT_MS)
        BOOTSTRAP_LOGGER.info(f"成功在接口 '{interface_name}' 上开始捕获...")
        while True:
            header, pkt_data = cap.next()
            if pkt_data:
                packet_handler(header, pkt_data, dispatcher, loggers, stats)
            if time.time() - stats.last_print_time >= STATS_INTERVAL_SECONDS:
                stats.print_summary()
    except pcapy.PcapError as e:
        BOOTSTRAP_LOGGER.error(f"PcapError: {e}. 请检查权限或接口名称。")
    except KeyboardInterrupt:
        BOOTSTRAP_LOGGER.info("\n用户中断捕获。")
    finally:
        BOOTSTRAP_LOGGER.info("正在打印最终统计...")
        stats.print_summary()
        BOOTSTRAP_LOGGER.info("脚本已关闭。")
def _select_network_interface() -> Optional[str]:
    try:
        devices = pcapy.findalldevs()
        if not devices: BOOTSTRAP_LOGGER.error("未找到任何网络接口。"); return None
        for pref in PREFERRED_INTERFACES:
            for dev in devices:
                if pref.lower() in dev.lower() and 'lo' not in dev.lower(): return dev
        return devices[0]
    except pcapy.PcapError as e:
        BOOTSTRAP_LOGGER.error(f"无法列出网络接口: {e}"); return None

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    detectors_dir_path = os.path.join(script_dir, DETECTORS_DIR_NAME)
    
    selected_interface = _select_network_interface()
    if selected_interface:
        capture_traffic(selected_interface, detectors_dir_path)
    else:
        BOOTSTRAP_LOGGER.error("无法启动，未能选择有效的网络接口。")