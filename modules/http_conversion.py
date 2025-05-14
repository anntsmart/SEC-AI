import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Thread ---
class HttpToPythonThread(QThread):
    conversion_complete = pyqtSignal(str)

    def __init__(self, http_request, parent=None):
        super().__init__(parent)
        self.http_request = http_request
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            prompt_text = f"""你是一个专业Python开发助手，请将以下HTTP请求转换为规范的Python代码（使用requests库）。按以下步骤处理：
要求：
1.用户输入：完整请求头（包含Content-Type和Authorization）
2.用户输入：完整的请求题（包含请求方法、URL和参数）
3.用户输入：请求体的内容（如果有）
4.默认不进行SSL验证
5.输出：完整的Python代码，包含请求头、请求体和请求方法

请用中文按以下格式响应：
【Python代码】输出转换后的Python代码，不使用markdown格式，不要有其他多余的输出

这是用户输入的内容：
{self.http_request}"""
            
            # 创建正确的消息列表格式
            messages = [
                {"role": "system", "content": "你是一个专业的Python开发者，擅长将HTTP请求转换为标准的Python requests代码。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info("Starting HTTP to Python conversion via API...")
            # Use higher temperature for creative tasks like code generation
            result = self.api_adapter.chat_completion(messages, temperature=0.5)
            # Post-process to remove potential markdown fences
            if result.strip().startswith("【Python代码】"):
                 result = result.split("【Python代码】", 1)[1].strip()
            if result.startswith("```python"):
                result = result[len("```python"):].strip()
            if result.endswith("```"):
                result = result[:-len("```")].strip()
            logging.info("HTTP conversion complete.")
            self.conversion_complete.emit(result)

        except Exception as e:
            error_msg = f"转换错误: {str(e)}"
            logging.error(f"HTTP conversion thread error: {error_msg}", exc_info=True)
            self.conversion_complete.emit(error_msg)

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the HTTP to Python tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("HTTP转Python代码", font=QFont("Arial", 16, QFont.Bold)))

    layout.addWidget(QLabel("输入HTTP请求:"))
    input_frame, main_window.http_input = create_scroll_textedit("粘贴HTTP请求...", read_only=False)
    layout.addWidget(input_frame, 1)

    main_window.convert_btn = QPushButton("开始转换")
    main_window.convert_btn.clicked.connect(lambda: start_http_conversion(main_window))
    layout.addWidget(main_window.convert_btn)

    layout.addWidget(QLabel("转换结果 (Python requests):"))
    # Use monospace font for code
    result_frame, main_window.conversion_result = create_scroll_textedit(read_only=True, font_family='Consolas', font_size=11)
    layout.addWidget(result_frame, 1)

    main_window.tab_widget.addTab(tab, "HTTP转Python")

def start_http_conversion(main_window):
    """Slot to start the HTTP conversion thread."""
    http_request = main_window.http_input.toPlainText().strip()
    if not http_request:
        main_window.show_status("请输入HTTP请求", "red")
        return

    main_window.convert_btn.setEnabled(False)
    main_window.conversion_result.setPlainText("转换中...")
    main_window.show_status("正在转换HTTP请求...", "#007acc")

    main_window.http_thread = HttpToPythonThread(http_request)
    main_window.http_thread.conversion_complete.connect(
        lambda result: show_conversion_result(main_window, result)
    )
    main_window.http_thread.start()

def show_conversion_result(main_window, result):
    """Slot to display HTTP conversion results."""
    main_window.convert_btn.setEnabled(True)
    main_window.conversion_result.setPlainText(result)
    if "转换错误" in result:
        main_window.show_status("HTTP转换时发生错误", "red")
    else:
        main_window.show_status("转换完成", "#2ed573")