import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Thread ---
class TextProcessThread(QThread):
    process_complete = pyqtSignal(str)

    def __init__(self, source_text, sample_text, parent=None):
        super().__init__(parent)
        self.source_text = source_text
        self.sample_text = sample_text
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            prompt_text = f"""请根据提供的源文本和样本格式，编写一个python转换脚本，该脚本能够自动将源文本转换为与样本格式相匹配的格式。要求脚本逻辑清晰，转换可靠。

样本格式：
```
{self.sample_text}
```

源文本：
```
{self.source_text}
```

请直接输出python脚本，不要包含任何解释或说明。不使用markdown格式"""
            
            # 创建正确的消息列表格式
            messages = [
                {"role": "system", "content": "你是一个专业的Python开发者，擅长编写文本处理和转换脚本。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info("Starting text processing via API...")
            # Use higher temperature for creative tasks like code generation
            result = self.api_adapter.chat_completion(messages, temperature=0.6)
            # Post-process to remove potential markdown fences
            if result.strip().startswith("```python"):
                result = result[len("```python"):].strip()
            if result.endswith("```"):
                result = result[:-len("```")].strip()
            logging.info("Text processing complete.")
            self.process_complete.emit(result)

        except Exception as e:
            error_msg = f"文本处理错误: {str(e)}"
            logging.error(f"Text processing thread error: {error_msg}", exc_info=True)
            self.process_complete.emit(error_msg)

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the Text Processing tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("AI文本格式转换 (生成Python脚本)", font=QFont("Arial", 16, QFont.Bold)))

    columns_widget = QWidget()
    column_layout = QHBoxLayout(columns_widget)

    # --- Left Column (Inputs) ---
    left_widget = QWidget()
    left_layout = QVBoxLayout(left_widget)

    left_layout.addWidget(QLabel("源文本:"))
    source_frame, main_window.text_source = create_scroll_textedit("源文本...", read_only=False)
    left_layout.addWidget(source_frame, 1) # Stretch

    left_layout.addWidget(QLabel("样本格式:"))
    sample_frame, main_window.text_sample = create_scroll_textedit("样本格式...", read_only=False)
    left_layout.addWidget(sample_frame, 1) # Stretch

    # --- Right Column (Button & Result) ---
    right_widget = QWidget()
    right_layout = QVBoxLayout(right_widget)

    main_window.text_process_btn = QPushButton("生成转换脚本")
    main_window.text_process_btn.clicked.connect(lambda: start_text_processing(main_window))
    # Add some spacing or alignment if needed
    right_layout.addWidget(main_window.text_process_btn)
    right_layout.addStretch(1) # Push button towards top if desired

    right_layout.addWidget(QLabel("生成的Python脚本:"))
    result_frame, main_window.text_result = create_scroll_textedit(read_only=True, font_family='Consolas', font_size=11)
    right_layout.addWidget(result_frame, 5) # More stretch for result
    right_layout.addStretch(1)

    column_layout.addWidget(left_widget, 1) # Give left side equal weight initially
    column_layout.addWidget(right_widget, 1) # Give right side equal weight initially

    layout.addWidget(columns_widget) # Add the two columns to the main layout

    main_window.tab_widget.addTab(tab, "文本处理")

def start_text_processing(main_window):
    """Slot to start the text processing thread."""
    source_text = main_window.text_source.toPlainText().strip()
    sample_text = main_window.text_sample.toPlainText().strip()
    if not source_text or not sample_text:
        main_window.show_status("请输入源文本和样本格式", "red")
        return

    main_window.text_process_btn.setEnabled(False)
    main_window.text_result.setPlainText("生成脚本中...")
    main_window.show_status("正在处理文本格式...", "#007acc")

    main_window.text_thread = TextProcessThread(source_text, sample_text)
    main_window.text_thread.process_complete.connect(
        lambda result: show_text_result(main_window, result)
    )
    main_window.text_thread.start()

def show_text_result(main_window, result):
    """Slot to display text processing results."""
    main_window.text_process_btn.setEnabled(True)
    main_window.text_result.setPlainText(result)
    if "文本处理错误" in result:
        main_window.show_status("文本处理时发生错误", "red")
    else:
        main_window.show_status("文本处理完成", "#2ed573")