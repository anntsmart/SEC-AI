import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Thread ---
class ProcessAnalysisThread(QThread):
    process_complete = pyqtSignal(str)

    def __init__(self, process_data, parent=None):
        super().__init__(parent)
        self.process_data = process_data
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            prompt_text = f"""你是一个Windows/Linux进程分析工程师，要求：
1. 用户将输出tasklist或者ps aux的结果
2. 帮助用户分析输出你所有认识的进程信息
3. 识别可能的恶意进程
4. 识别杀毒软件进程
5. 识别其他软件进程

tasklist或者ps aux的结果：{self.process_data}

按优先级列出需要关注的进程
【可疑进程】
【杀软进程】
【第三方软件进程】
给出具体操作建议：
• 安全进程的可终止性评估
"""
            
            # 创建正确的消息列表格式
            messages = [
                {"role": "system", "content": "你是一个专业的Windows/Linux进程分析工程师，擅长识别进程并评估其安全性。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info("Starting process analysis via API...")
            result = self.api_adapter.chat_completion(messages)
            logging.info("Process analysis complete.")
            self.process_complete.emit(result)

        except Exception as e:
            error_msg = f"进程分析错误: {str(e)}"
            logging.error(f"Process analysis thread error: {error_msg}", exc_info=True)
            self.process_complete.emit(error_msg)

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the Process Analysis tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("进程分析系统", font=QFont("Arial", 16, QFont.Bold)))

    layout.addWidget(QLabel("输入进程列表 (tasklist / ps aux):"))
    input_frame, main_window.process_input = create_scroll_textedit("粘贴tasklist或ps aux信息...", read_only=False)
    layout.addWidget(input_frame, 1)

    main_window.process_btn = QPushButton("开始进程分析")
    main_window.process_btn.clicked.connect(lambda: start_process_analysis(main_window))
    layout.addWidget(main_window.process_btn)

    layout.addWidget(QLabel("分析结果:"))
    result_frame, main_window.process_result = create_scroll_textedit(read_only=True)
    layout.addWidget(result_frame, 1)

    main_window.tab_widget.addTab(tab, "进程分析")

def start_process_analysis(main_window):
    """Slot to start the process analysis thread."""
    process_data = main_window.process_input.toPlainText().strip()
    if not process_data:
        main_window.show_status("请输入进程信息", "red")
        return

    main_window.process_btn.setEnabled(False)
    main_window.process_result.setPlainText("分析中...")
    main_window.show_status("正在进行进程分析...", "#007acc")

    main_window.process_thread = ProcessAnalysisThread(process_data)
    main_window.process_thread.process_complete.connect(
        lambda result: show_process_result(main_window, result)
    )
    main_window.process_thread.start()

def show_process_result(main_window, result):
    """Slot to display process analysis results."""
    main_window.process_btn.setEnabled(True)
    main_window.process_result.setPlainText(result)
    if "进程分析错误" in result:
        main_window.show_status("进程分析时发生错误", "red")
    else:
        main_window.show_status("进程分析完成", "#2ed573")