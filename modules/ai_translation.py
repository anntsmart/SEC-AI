import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout,
                             QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Thread ---
class TranslationThread(QThread):
    translation_complete = pyqtSignal(str)

    def __init__(self, text, source_lang, target_lang, parent=None):
        super().__init__(parent)
        self.text = text
        self.source_lang = source_lang if source_lang != "自动检测" else "auto"
        self.target_lang = target_lang
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            # Adjust source language based on selection
            source_lang_prompt = f"从{self.source_lang}" if self.source_lang != "auto" else "自动检测源语言，然后"

            prompt_text = f"""请将以下文本{source_lang_prompt}专业地翻译成{self.target_lang}。要求：
1. 保持技术术语准确性（特别是网络安全相关词汇）
2. 保留代码格式和变量名（例如在```code```块中）
3. 正确处理专业缩写（如XSS、SQLi等）
4. 输出仅需翻译结果，无需额外说明

待翻译内容：
```
{self.text}
```"""
            # Format as a proper messages list
            messages = [
                {"role": "system", "content": "你是一个专业的技术翻译助手，精通网络安全和IT领域的术语翻译。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info(f"Starting translation ({self.source_lang} -> {self.target_lang}) via API...")
            result = self.api_adapter.chat_completion(messages, temperature=0.3) # Lower temp for factual translation
            logging.info("Translation complete.")
            self.translation_complete.emit(result)

        except Exception as e:
            error_msg = f"翻译错误: {str(e)}"
            logging.error(f"Translation thread error: {error_msg}", exc_info=True)
            self.translation_complete.emit(error_msg)

# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the AI Translation tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("AI多语言专业翻译", font=QFont("Arial", 16, QFont.Bold)))

    # --- Language Selection ---
    lang_control_widget = QWidget()
    lang_layout = QHBoxLayout(lang_control_widget)

    lang_layout.addWidget(QLabel("源语言:"))
    main_window.trans_source_lang = QComboBox()
    main_window.trans_source_lang.addItems(["自动检测", "中文", "英文", "日文", "韩文", "德文", "法文", "俄文", "西班牙文"])
    lang_layout.addWidget(main_window.trans_source_lang)

    lang_layout.addWidget(QLabel("目标语言:"))
    main_window.trans_target_lang = QComboBox()
    main_window.trans_target_lang.addItems(["中文", "英文", "日文", "韩文", "德文", "法文", "俄文", "西班牙文"])
    # Default target often English or Chinese
    try:
         main_window.trans_target_lang.setCurrentText("中文")
    except:
         pass # Ignore if "中文" not present
    lang_layout.addWidget(main_window.trans_target_lang)
    lang_layout.addStretch()
    layout.addWidget(lang_control_widget)


    # --- Text Input/Output Areas ---
    trans_columns_widget = QWidget()
    trans_layout = QHBoxLayout(trans_columns_widget)

    # Left Input
    left_widget = QWidget()
    left_v_layout = QVBoxLayout(left_widget)
    left_v_layout.addWidget(QLabel("原文:"))
    input_frame, main_window.trans_input = create_scroll_textedit("输入待翻译内容...", read_only=False)
    left_v_layout.addWidget(input_frame)
    left_v_layout.setContentsMargins(0,0,0,0)

    # Right Output
    right_widget = QWidget()
    right_v_layout = QVBoxLayout(right_widget)
    right_v_layout.addWidget(QLabel("译文:"))
    output_frame, main_window.trans_output = create_scroll_textedit(read_only=True)
    right_v_layout.addWidget(output_frame)
    right_v_layout.setContentsMargins(0,0,0,0)


    trans_layout.addWidget(left_widget)
    trans_layout.addWidget(right_widget)
    layout.addWidget(trans_columns_widget)


    # --- Translate Button ---
    main_window.trans_btn = QPushButton("开始翻译")
    main_window.trans_btn.clicked.connect(lambda: start_translation(main_window))
    layout.addWidget(main_window.trans_btn)

    main_window.tab_widget.addTab(tab, "AI翻译")

def start_translation(main_window):
    """Slot to start the translation thread."""
    text = main_window.trans_input.toPlainText().strip()
    if not text:
        main_window.show_status("请输入需要翻译的内容", "red")
        return

    source_lang = main_window.trans_source_lang.currentText()
    target_lang = main_window.trans_target_lang.currentText()

    if source_lang == target_lang and source_lang != "自动检测":
        main_window.show_status("源语言和目标语言不能相同", "orange")
        return

    main_window.trans_btn.setEnabled(False)
    main_window.trans_output.setPlainText("翻译中...")
    main_window.show_status("正在进行翻译...", "#007acc")

    main_window.trans_thread = TranslationThread(text, source_lang, target_lang)
    main_window.trans_thread.translation_complete.connect(
        lambda result: show_translation_result(main_window, result)
    )
    main_window.trans_thread.start()

def show_translation_result(main_window, result):
    """Slot to display translation results."""
    main_window.trans_btn.setEnabled(True)
    main_window.trans_output.setPlainText(result)
    if "翻译错误" in result:
        main_window.show_status("翻译时发生错误", "red")
    else:
        main_window.show_status("翻译完成", "#2ed573")
