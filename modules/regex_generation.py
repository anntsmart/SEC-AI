import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Thread ---
class RegexGenThread(QThread):
    regex_complete = pyqtSignal(str)

    def __init__(self, source_text, sample_text, parent=None):
        super().__init__(parent)
        self.source_text = source_text
        self.sample_text = sample_text
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            prompt_text = f"""根据源文本和目标样本，生成最佳的正则表达式来匹配样本中的内容。

目标样本（需要匹配的内容）：
```
{self.sample_text}
```

源文本：
```
{self.source_text}
```

请直接输出生成的多个正则表达式，每行一个，不要包含任何解释或说明，不要使用markdown格式输出"""
            
            # 创建正确的消息列表格式
            messages = [
                {"role": "system", "content": "你是一个正则表达式专家，能够基于源文本和样本创建精确的正则表达式。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info("Starting regex generation via API...")
            # Temperature might need adjustment for regex accuracy vs creativity
            result = self.api_adapter.chat_completion(messages, temperature=0.4)
            logging.info("Regex generation complete.")
            self.regex_complete.emit(result)

        except Exception as e:
            error_msg = f"正则表达式生成错误: {str(e)}"
            logging.error(f"Regex generation thread error: {error_msg}", exc_info=True)
            self.regex_complete.emit(error_msg)

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the Regex Generation tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("正则表达式生成", font=QFont("Arial", 16, QFont.Bold)))

    columns_widget = QWidget()
    column_layout = QHBoxLayout(columns_widget)

    # --- Left Column (Inputs) ---
    left_widget = QWidget()
    left_layout = QVBoxLayout(left_widget)

    left_layout.addWidget(QLabel("源文本 (用于提取模式):"))
    source_frame, main_window.regex_source = create_scroll_textedit("源文本...", read_only=False)
    left_layout.addWidget(source_frame, 1)

    left_layout.addWidget(QLabel("目标样本 (需要匹配的内容):"))
    sample_frame, main_window.regex_sample = create_scroll_textedit("样本格式...", read_only=False)
    left_layout.addWidget(sample_frame, 1)

    # --- Right Column (Button & Result) ---
    right_widget = QWidget()
    right_layout = QVBoxLayout(right_widget)

    main_window.regex_btn = QPushButton("生成正则表达式")
    main_window.regex_btn.clicked.connect(lambda: start_regex_generation(main_window))
    right_layout.addWidget(main_window.regex_btn)
    right_layout.addStretch(1)


    right_layout.addWidget(QLabel("生成的正则表达式:"))
    # Regex results benefit from monospace
    result_frame, main_window.regex_result = create_scroll_textedit(read_only=True, font_family='Consolas', font_size=11)
    right_layout.addWidget(result_frame, 5) # More stretch for result
    right_layout.addStretch(1)

    column_layout.addWidget(left_widget, 1)
    column_layout.addWidget(right_widget, 1)

    layout.addWidget(columns_widget)

    main_window.tab_widget.addTab(tab, "正则生成")

def start_regex_generation(main_window):
    """Slot to start the regex generation thread."""
    source_text = main_window.regex_source.toPlainText().strip()
    sample_text = main_window.regex_sample.toPlainText().strip()
    if not source_text or not sample_text:
        main_window.show_status("请输入源文本和样本格式", "red")
        return

    main_window.regex_btn.setEnabled(False)
    main_window.regex_result.setPlainText("生成中...")
    main_window.show_status("正在生成正则表达式...", "#007acc")

    main_window.regex_thread = RegexGenThread(source_text, sample_text)
    main_window.regex_thread.regex_complete.connect(
        lambda result: show_regex_result(main_window, result)
    )
    main_window.regex_thread.start()

def show_regex_result(main_window, result):
    """Slot to display regex generation results."""
    main_window.regex_btn.setEnabled(True)
    main_window.regex_result.setPlainText(result)
    if "正则表达式生成错误" in result:
        main_window.show_status("正则生成时发生错误", "red")
    else:
        main_window.show_status("正则表达式生成完成", "#2ed573")
