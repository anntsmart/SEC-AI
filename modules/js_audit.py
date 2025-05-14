import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Thread ---
class JsAuditThread(QThread):
    audit_complete = pyqtSignal(str)

    def __init__(self, js_code, parent=None):
        super().__init__(parent)
        self.js_code = js_code
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            prompt_text = f"""请对以下JavaScript代码进行完整的安全审计，要求：
1. 识别XSS、CSRF、不安全的DOM操作、敏感信息泄露、eval使用等安全问题
2. 检查第三方库的安全性和版本漏洞
3. 分析代码逻辑漏洞
4. 提供修复建议

请用中文按以下格式响应：
【高危漏洞】列出高危安全问题及位置
【中低危问题】列出中低风险问题
【修复建议】提供具体修复方案

JavaScript代码：
{self.js_code}"""
            
            # 创建正确的消息列表格式
            messages = [
                {"role": "system", "content": "你是一个专业的JavaScript安全审计专家，擅长发现Web前端代码中的安全问题。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info("Starting JS audit via API...")
            result = self.api_adapter.chat_completion(messages)
            logging.info("JS audit complete.")
            self.audit_complete.emit(result)

        except Exception as e:
            error_msg = f"审计错误: {str(e)}"
            logging.error(f"JS audit thread error: {error_msg}", exc_info=True)
            self.audit_complete.emit(error_msg)

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the JS Audit tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("JavaScript代码安全审计", font=QFont("Arial", 16, QFont.Bold)))

    layout.addWidget(QLabel("输入待审计代码:"))
    input_frame, main_window.js_input = create_scroll_textedit("粘贴JavaScript代码...", read_only=False)
    layout.addWidget(input_frame, 1) # Stretch factor

    main_window.js_audit_btn = QPushButton("开始安全审计")
    main_window.js_audit_btn.clicked.connect(lambda: start_js_audit(main_window))
    layout.addWidget(main_window.js_audit_btn)

    layout.addWidget(QLabel("审计结果:"))
    result_frame, main_window.js_result = create_scroll_textedit(read_only=True)
    layout.addWidget(result_frame, 1) # Stretch factor

    main_window.tab_widget.addTab(tab, "JS审计")

def start_js_audit(main_window):
    """Slot to start the JS audit thread."""
    js_code = main_window.js_input.toPlainText().strip()
    if not js_code:
        main_window.show_status("请输入JavaScript代码", "red")
        return

    main_window.js_audit_btn.setEnabled(False)
    main_window.js_result.setPlainText("审计中...")
    main_window.show_status("正在进行JS代码审计...", "#007acc")


    main_window.js_audit_thread = JsAuditThread(js_code)
    main_window.js_audit_thread.audit_complete.connect(
        lambda result: show_js_audit_result(main_window, result)
    )
    main_window.js_audit_thread.start()

def show_js_audit_result(main_window, result):
    """Slot to display JS audit results."""
    main_window.js_audit_btn.setEnabled(True)
    main_window.js_result.setPlainText(result)
    if "审计错误" in result:
        main_window.show_status("JS审计时发生错误", "red")
    else:
        main_window.show_status("代码审计完成", "#2ed573")