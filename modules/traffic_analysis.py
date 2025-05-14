import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QHBoxLayout,
                             QSplitter, QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Thread ---
class AnalysisThread(QThread):
    analysis_complete = pyqtSignal(str, bool) # result_text, is_attack

    def __init__(self, http_data, parent=None):
        super().__init__(parent)
        self.http_data = http_data
        self.api_adapter = APIAdapter() # Create instance here

    def run(self):
        try:
            prompt_text = f"""请进行网络安全分析。请严格按照以下步骤执行：
1. 分析以下HTTP请求的各个组成部分
2. 识别是否存在SQL注入、XSS、CSRF、反序列化、文件上传、路径遍历、OWASPTop10、等常见攻击特征
3. 检查User-Agent等头部信息是否可疑
4. 如果数据包中有一些编码后的内容，一定要解码后再进行分析
5. 最终结论：是否为攻击流量（是/否）

请用中文按以下格式响应：
【分析结果】是/否
【依据】简明扼要列出技术依据

HTTP请求数据：
{self.http_data}"""
            
            # 创建正确的消息列表格式
            messages = [
                {"role": "system", "content": "你是一个专业的网络安全分析师，擅长识别HTTP流量中的攻击模式。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info("Starting traffic analysis via API...")
            result = self.api_adapter.chat_completion(messages)
            is_attack = "【分析结果】是" in result
            logging.info(f"Traffic analysis complete. Is attack: {is_attack}")
            self.analysis_complete.emit(result, is_attack)

        except Exception as e:
            error_msg = f"错误发生: {str(e)}"
            logging.error(f"Traffic analysis thread error: {error_msg}", exc_info=True)
            self.analysis_complete.emit(error_msg, False)


class DecodingThread(QThread):
    decoding_complete = pyqtSignal(str)

    def __init__(self, encoded_str, parent=None):
        super().__init__(parent)
        self.encoded_str = encoded_str
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            prompt_text = f"""请完整分析并解码以下字符串，要求：
1. 识别所有可能的编码方式（包括嵌套编码）
2. 通过自己重新编码，确认自己解码正确
3. 展示完整的解码过程
4. 输出最终解码结果

原始字符串：{self.encoded_str}

请用中文按以下格式响应：
【编码分析】列出检测到的编码类型及层级
【解码过程】逐步展示解码步骤
【最终结果】解码后的明文内容"""
            
            # 创建正确的消息列表格式
            messages = [
                {"role": "system", "content": "你是一个专业的编码分析专家，精通各种编码和解码技术。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info("Starting decoding via API...")
            result = self.api_adapter.chat_completion(messages)
            logging.info("Decoding complete.")
            self.decoding_complete.emit(result)

        except Exception as e:
            error_msg = f"解码错误: {str(e)}"
            logging.error(f"Decoding thread error: {error_msg}", exc_info=True)
            self.decoding_complete.emit(error_msg)

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the Traffic Analysis tab."""
    tab = QWidget()
    splitter = QSplitter(Qt.Horizontal)
    layout = QHBoxLayout(tab)
    layout.addWidget(splitter)
    layout.setContentsMargins(5, 5, 5, 5) # Reduced margins

    # --- Left Panel (Analysis) ---
    left_panel = QWidget()
    left_layout = QVBoxLayout(left_panel)
    left_layout.addWidget(QLabel("网络流量智能分析系统", font=QFont("Arial", 16, QFont.Bold))) # Smaller font

    left_layout.addWidget(QLabel("请输入HTTP请求数据:"))
    input_frame, main_window.traffic_input = create_scroll_textedit("粘贴HTTP请求数据...", read_only=False)
    left_layout.addWidget(input_frame, 1) # Add stretch factor

    main_window.traffic_analyze_btn = QPushButton("开始智能分析")
    main_window.traffic_analyze_btn.clicked.connect(lambda: start_traffic_analysis(main_window))
    left_layout.addWidget(main_window.traffic_analyze_btn)

    left_layout.addWidget(QLabel("AI分析结果:"))
    result_frame, main_window.traffic_result = create_scroll_textedit(read_only=True)
    left_layout.addWidget(result_frame, 1) # Add stretch factor

    # --- Right Panel (Decoding) ---
    right_panel = QWidget()
    right_layout = QVBoxLayout(right_panel)
    right_layout.addWidget(QLabel("AI全智能解码", font=QFont("Arial", 14, QFont.Bold))) # Smaller font

    right_layout.addWidget(QLabel("待解码内容:"))
    decode_input_frame, main_window.decode_input = create_scroll_textedit("输入需要解码的字符串...", read_only=False)
    right_layout.addWidget(decode_input_frame, 1)

    main_window.decode_btn = QPushButton("AI智能解码")
    main_window.decode_btn.clicked.connect(lambda: start_decoding(main_window))
    right_layout.addWidget(main_window.decode_btn)

    right_layout.addWidget(QLabel("解码结果:"))
    decode_result_frame, main_window.decode_result = create_scroll_textedit(read_only=True)
    right_layout.addWidget(decode_result_frame, 1)

    splitter.addWidget(left_panel)
    splitter.addWidget(right_panel)
    splitter.setSizes([main_window.width() // 2, main_window.width() // 2]) # Initial equal split

    main_window.tab_widget.addTab(tab, "流量分析")

def start_traffic_analysis(main_window):
    """Slot to start the traffic analysis thread."""
    http_data = main_window.traffic_input.toPlainText().strip()
    if not http_data:
        main_window.show_status("请输入有效的HTTP请求数据", "red")
        return

    main_window.traffic_analyze_btn.setEnabled(False)
    main_window.traffic_result.setStyleSheet("") # Reset style
    main_window.traffic_result.setPlainText("分析中...")
    main_window.show_status("正在进行流量分析...", "#007acc")

    # Keep a reference to the thread
    main_window.analysis_thread = AnalysisThread(http_data)
    main_window.analysis_thread.analysis_complete.connect(
        lambda result, is_attack: show_traffic_result(main_window, result, is_attack)
    )
    main_window.analysis_thread.start()

def show_traffic_result(main_window, result, is_attack):
    """Slot to display traffic analysis results."""
    main_window.traffic_analyze_btn.setEnabled(True)
    main_window.traffic_result.setPlainText(result) # Use plain text first

    # Apply styling based on result
    # Get current theme for colors (assuming theme data is accessible)
    current_theme_name = main_window.theme_selector.currentText()
    theme = getattr(main_window.config, 'THEMES', {}).get(current_theme_name, {})
    
    # Default text color from theme, but ensure contrast by forcing white on dark backgrounds
    text_color = "#ffffff"  # Default to white text for better contrast on colored backgrounds

    if "错误发生" in result:
         bg_color = theme.get("error_bg", "#ffcccc")  # Lighter red background
         border_color = theme.get("error_border", "#DC143C")  # Crimson
         text_color = "#000000"  # Black text on light background
         status = "分析时发生错误"
         status_color = "#ff4757"
    elif is_attack:
        # Use lighter red background for better readability
        bg_color = theme.get("attack_bg", "#ffeded")  # Much lighter red background
        border_color = theme.get("attack_border", "#e94560")  # Lighter red border
        text_color = "#800000"  # Dark red text on light background for emphasis
        status = "检测到恶意流量！"
        status_color = "#e94560"  # Original attack color
    else:
        bg_color = theme.get("normal_bg", "#eeffee")  # Light green background
        border_color = theme.get("normal_border", "#2ed573")  # Lighter green border
        text_color = "#006400"  # Dark green text on light background
        status = "流量正常"
        status_color = "#2ed573"  # Original normal color

    # Use a simpler style for better readability across themes
    main_window.traffic_result.setStyleSheet(f"""
        QTextEdit {{
            background-color: {bg_color};
            color: {text_color}; 
            border: 1px solid {border_color};
            border-radius: 4px;
            padding: 8px;
            font-family: Menlo, Consolas, monospace; /* Monospace font */
            font-size: 12px;
        }}
    """)

    main_window.show_status(status, status_color)


def start_decoding(main_window):
    """Slot to start the decoding thread."""
    text = main_window.decode_input.toPlainText().strip()
    if not text:
        main_window.show_status("请输入需要解码的内容", "red")
        return

    main_window.decode_btn.setEnabled(False)
    main_window.decode_result.setPlainText("解码中...")
    main_window.show_status("正在进行解码...", "#007acc")

    main_window.decoding_thread = DecodingThread(text)
    main_window.decoding_thread.decoding_complete.connect(
        lambda result: show_decoding_result(main_window, result)
    )
    main_window.decoding_thread.start()

def show_decoding_result(main_window, result):
    """Slot to display decoding results."""
    main_window.decode_btn.setEnabled(True)
    main_window.decode_result.setPlainText(result)

    if "解码错误" in result:
        main_window.show_status("解码时发生错误", "red")
    else:
        main_window.show_status("解码完成", "#2ed573")