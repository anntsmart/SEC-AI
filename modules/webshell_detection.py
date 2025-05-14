import logging
import os
import glob
import threading
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout,
                             QCheckBox, QFileDialog, QProgressBar)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from api_adapter import APIAdapter
from ui_utils import create_scroll_textedit

# --- Worker Threads ---
class WebShellAnalysisThread(QThread):
    """Analyzes a single file content for webshell characteristics."""
    analysis_complete = pyqtSignal(str, bool) # result_text, is_malicious

    def __init__(self, file_content, file_path="N/A", parent=None): # Added file_path for context
        super().__init__(parent)
        self.file_content = file_content
        self.file_path = file_path # Store for logging/error messages
        self.api_adapter = APIAdapter()

    def run(self):
        try:
            # Limit content size sent to API
            content_to_analyze = self.file_content[:4000] if len(self.file_content) > 4000 else self.file_content

            prompt_text = f"""请分析以下文件内容是否为WebShell或内存马。要求：
1. 检查PHP/JSP/ASP等WebShell特征（如加密函数、执行系统命令、文件操作）
2. 识别内存马特征（如无文件落地、进程注入、异常网络连接）
3. 分析代码中的可疑功能（如命令执行、文件上传、信息收集）
4. 检查混淆编码、加密手段等规避技术
5. 最终结论：是否为恶意软件（是/否）
6. 如果否，则简单回答"安全文件"，其他不要输出

请用中文按以下格式响应（如果是安全文件则只输出"安全文件"）：
【分析结果】是/否
【恶意类型】WebShell/内存马/其他
【技术特征】列出检测到的技术指标
【风险等级】高/中/低

文件内容：
```
{content_to_analyze}
```"""
            
            # Format as proper messages list
            messages = [
                {"role": "system", "content": "你是一个专业的安全分析师，精通网络安全和WebShell检测。"},
                {"role": "user", "content": prompt_text}
            ]
            
            logging.info(f"Starting webshell analysis for {self.file_path} via API...")
            result = self.api_adapter.chat_completion(messages)
            is_malicious = "【分析结果】是" in result
            logging.info(f"Webshell analysis for {self.file_path} complete. Malicious: {is_malicious}")
            self.analysis_complete.emit(result, is_malicious)

        except Exception as e:
            error_msg = f"文件 '{os.path.basename(self.file_path)}' 分析错误: {str(e)}"
            logging.error(f"Webshell analysis thread error for {self.file_path}: {error_msg}", exc_info=True)
            self.analysis_complete.emit(error_msg, False)


class BatchWebShellAnalysisThread(QThread):
    """Batch Webshell detection thread."""
    progress_updated = pyqtSignal(int, str, str) # percent, status_message, result_chunk
    scan_complete = pyqtSignal()

    def __init__(self, file_paths, parent=None):
        super().__init__(parent)
        self.file_paths = file_paths
        self.api_adapter = APIAdapter()
        self.running = True
        self._lock = threading.Lock() # For thread safety if needed, though signals are safe

    def run(self):
        total = len(self.file_paths)
        if total == 0:
             self.progress_updated.emit(100, "未找到符合条件的文件", "")
             self.scan_complete.emit()
             return

        logging.info(f"Starting batch webshell scan for {total} files.")
        malicious_count = 0

        for i, file_path in enumerate(self.file_paths):
            with self._lock:
                if not self.running:
                    logging.info("Batch webshell scan stopped by user.")
                    break

            percent = int(((i + 1) / total) * 100) # Use i+1 for progress
            status = f"正在扫描 {i+1}/{total}: {os.path.basename(file_path)}"
            self.progress_updated.emit(percent, status, "") # Update progress before processing

            try:
                logging.debug(f"Reading file: {file_path}")
                # Use UTF-8 encoding, ignore errors for potentially corrupt files
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000) # Read only first 50KB to avoid memory issues
                if not content:
                     logging.warning(f"File is empty or unreadable: {file_path}")
                     result_text = f"\n文件: {file_path} - 空文件或无法读取\n"
                     self.progress_updated.emit(percent, f"跳过空文件: {os.path.basename(file_path)}", result_text)
                     continue

                # --- Call single file analysis logic ---
                # Limit content size sent to API
                content_to_analyze = content[:4000] if len(content) > 4000 else content

                prompt_text = f"""请分析以下文件内容是否为WebShell或内存马。要求：
1. 检查PHP/JSP/ASP等WebShell特征（如eval, base64_decode, system, passthru, shell_exec, assert等）
2. 识别内存马特征（如Java Agent, Servlet Filter/Listener注入, Spring Interceptor等）
3. 分析代码中的可疑功能（命令执行, 文件管理, 数据库操作, 反弹shell）
4. 检查混淆、加密、编码技术
5. 最终结论：是否为恶意软件（是/否）
6. 如果否，则简单回答"安全文件"，其他不要输出

请用中文按以下格式响应（安全文件则只输出"安全文件"）：
【分析结果】是/否
【恶意类型】WebShell/内存马/其他
【技术特征】列出检测到的技术指标
【风险等级】高/中/低

文件内容：
```
{content_to_analyze}
```"""

                # Format as proper messages list
                messages = [
                    {"role": "system", "content": "你是一个专业的安全分析师，精通网络安全和WebShell检测。"},
                    {"role": "user", "content": prompt_text}
                ]
                
                logging.info(f"Analyzing file {i+1}/{total}: {file_path}")
                result = self.api_adapter.chat_completion(messages)
                is_malicious = "【分析结果】是" in result

                if is_malicious:
                    malicious_count += 1
                    result_text = f"\n--- 恶意文件 [{malicious_count}] ---\n文件: {file_path}\n{result}\n{'='*50}\n"
                    status = f"检测到恶意文件: {os.path.basename(file_path)}"
                    logging.warning(f"Malicious file detected: {file_path}")
                    self.progress_updated.emit(percent, status, result_text)
                else:
                    # Only log safe files if needed, to avoid flooding output
                    # result_text = f"文件: {file_path} - 安全\n"
                    status = f"安全文件: {os.path.basename(file_path)}"
                    # self.progress_updated.emit(percent, status, result_text) # Optionally emit safe results
                    logging.info(f"Safe file: {file_path}")
                    # Update status without adding to result textedit for safe files
                    self.progress_updated.emit(percent, status, "")


            except FileNotFoundError:
                 error_msg = f"\n\n文件: {file_path}\n错误: 文件未找到\n{'='*50}\n"
                 logging.error(f"File not found during batch scan: {file_path}")
                 self.progress_updated.emit(percent, f"错误: 文件未找到 {os.path.basename(file_path)}", error_msg)
            except PermissionError:
                 error_msg = f"\n\n文件: {file_path}\n错误: 权限不足\n{'='*50}\n"
                 logging.error(f"Permission error reading file: {file_path}")
                 self.progress_updated.emit(percent, f"错误: 权限不足 {os.path.basename(file_path)}", error_msg)
            except Exception as e:
                error_msg = f"\n\n文件: {file_path}\n读取或分析错误: {str(e)}\n{'='*50}\n"
                logging.error(f"Error processing file {file_path}: {e}", exc_info=True)
                self.progress_updated.emit(percent, f"处理错误: {os.path.basename(file_path)}", error_msg)

        final_status = "扫描完成" if self.running else "扫描被用户中止"
        final_status += f" (检测到 {malicious_count} 个可疑文件)"
        logging.info(f"Batch webshell scan finished. Malicious count: {malicious_count}")
        self.progress_updated.emit(100, final_status, "")
        self.scan_complete.emit()

    def stop(self):
         with self._lock:
            logging.info("Stop signal received for batch webshell scan.")
            self.running = False


# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the Webshell Detection tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("WebShell检测系统", font=QFont("Arial", 16, QFont.Bold)))

    # --- File/Directory Selection ---
    file_control_widget = QWidget()
    file_layout = QHBoxLayout(file_control_widget)
    main_window.webshell_btn_choose_file = QPushButton("选择单个文件")
    main_window.webshell_btn_choose_dir = QPushButton("选择扫描目录")
    main_window.webshell_label_scan_path = QLabel("未选择文件/目录")
    main_window.webshell_label_scan_path.setWordWrap(True) # Allow wrapping
    file_layout.addWidget(main_window.webshell_btn_choose_file)
    file_layout.addWidget(main_window.webshell_btn_choose_dir)
    file_layout.addWidget(main_window.webshell_label_scan_path, 1) # Stretch label
    file_layout.setContentsMargins(0,0,0,0)
    layout.addWidget(file_control_widget)

    # --- File Type Filters ---
    filter_control_widget = QWidget()
    filter_layout = QHBoxLayout(filter_control_widget)
    main_window.webshell_check_php = QCheckBox("PHP")
    main_window.webshell_check_jsp = QCheckBox("JSP")
    main_window.webshell_check_asp = QCheckBox("ASP")
    # Default checks
    main_window.webshell_check_php.setChecked(True)
    main_window.webshell_check_jsp.setChecked(True)
    main_window.webshell_check_asp.setChecked(True)
    filter_layout.addWidget(QLabel("检测文件类型:"))
    filter_layout.addWidget(main_window.webshell_check_php)
    filter_layout.addWidget(main_window.webshell_check_jsp)
    filter_layout.addWidget(main_window.webshell_check_asp)
    filter_layout.addStretch()
    filter_layout.setContentsMargins(0,0,0,0)
    layout.addWidget(filter_control_widget)

    # --- Progress Bar ---
    main_window.webshell_progress = QProgressBar()
    main_window.webshell_progress.setValue(0)
    main_window.webshell_progress.setTextVisible(True)
    layout.addWidget(main_window.webshell_progress)

    # --- Action Buttons ---
    action_widget = QWidget()
    action_layout = QHBoxLayout(action_widget)
    main_window.webshell_btn_start_scan = QPushButton("开始深度检测")
    main_window.webshell_btn_stop_scan = QPushButton("停止扫描")
    main_window.webshell_btn_stop_scan.setEnabled(False) # Initially disabled
    action_layout.addWidget(main_window.webshell_btn_start_scan)
    action_layout.addWidget(main_window.webshell_btn_stop_scan)
    action_layout.addStretch()
    action_layout.setContentsMargins(0,0,0,0)
    layout.addWidget(action_widget)


    # --- Result Area ---
    layout.addWidget(QLabel("检测结果 (仅显示可疑文件):"))
    result_frame, main_window.webshell_result = create_scroll_textedit(read_only=True)
    layout.addWidget(result_frame, 1) # Stretch factor

    # --- Connect Signals ---
    main_window.webshell_btn_choose_file.clicked.connect(lambda: choose_webshell_file(main_window))
    main_window.webshell_btn_choose_dir.clicked.connect(lambda: choose_webshell_dir(main_window))
    main_window.webshell_btn_start_scan.clicked.connect(lambda: start_webshell_scan(main_window))
    main_window.webshell_btn_stop_scan.clicked.connect(lambda: stop_webshell_scan(main_window))

     # Store files list in main window instance
    main_window.webshell_files_to_scan = []

    main_window.tab_widget.addTab(tab, "WebShell检测")

def choose_webshell_file(main_window):
    """Slot to choose a single file."""
    options = QFileDialog.Options()
    # options |= QFileDialog.DontUseNativeDialog
    file_path, _ = QFileDialog.getOpenFileName(main_window,
                                               "选择检测文件",
                                               "", # Start directory
                                               "Web Files (*.php *.jsp *.asp);;All Files (*)",
                                               options=options)
    if file_path:
        main_window.webshell_files_to_scan = [file_path]
        main_window.webshell_label_scan_path.setText(f"已选文件: {os.path.basename(file_path)}")
        main_window.webshell_progress.setValue(0)
        main_window.webshell_progress.setFormat("Ready to scan 1 file")


def choose_webshell_dir(main_window):
    """Slot to choose a directory."""
    options = QFileDialog.Options()
    options |= QFileDialog.ShowDirsOnly
    # options |= QFileDialog.DontUseNativeDialog
    directory = QFileDialog.getExistingDirectory(main_window,
                                                 "选择扫描目录",
                                                 "", # Start directory
                                                 options=options)
    if directory:
        main_window.webshell_scan_target_dir = directory # Store directory
        main_window.webshell_label_scan_path.setText(f"已选目录: {directory}")
        # Scan files immediately after selection to update count
        scan_webshell_files_in_dir(main_window)


def scan_webshell_files_in_dir(main_window):
    """Scans the selected directory based on checkbox filters."""
    if not hasattr(main_window, 'webshell_scan_target_dir') or not main_window.webshell_scan_target_dir:
        return

    directory = main_window.webshell_scan_target_dir
    exts = []
    if main_window.webshell_check_php.isChecked(): exts.append('*.php')
    if main_window.webshell_check_jsp.isChecked(): exts.append('*.jsp')
    if main_window.webshell_check_asp.isChecked(): exts.append('*.asp')

    if not exts:
        main_window.webshell_files_to_scan = []
        main_window.show_status("请至少选择一种文件类型", "orange")
        main_window.webshell_progress.setValue(0)
        main_window.webshell_progress.setFormat("请选择文件类型")
        return

    logging.info(f"Scanning directory {directory} for extensions: {exts}")
    main_window.webshell_files_to_scan = []
    for ext in exts:
        # Use Pathlib for potentially better recursive globbing and handling
        from pathlib import Path
        try:
             pattern = f'**/{ext}'
             found_files = list(Path(directory).rglob(pattern))
             main_window.webshell_files_to_scan.extend([str(f) for f in found_files])
             logging.debug(f"Found {len(found_files)} files for pattern {pattern}")
        except Exception as e:
             logging.error(f"Error during globbing for {ext} in {directory}: {e}", exc_info=True)
             main_window.show_status(f"扫描文件时出错: {e}", "red")


    file_count = len(main_window.webshell_files_to_scan)
    logging.info(f"Found {file_count} total files to scan.")
    main_window.show_status(f"发现 {file_count} 个待检测文件", "#2ed573")
    main_window.webshell_progress.setMaximum(file_count if file_count > 0 else 100) # Avoid max 0
    main_window.webshell_progress.setValue(0)
    main_window.webshell_progress.setFormat(f"Ready to scan {file_count} files")


def start_webshell_scan(main_window):
    """Slot to start the webshell scan thread."""
     # If a directory was selected, re-scan files in case filters changed
    if hasattr(main_window, 'webshell_scan_target_dir') and main_window.webshell_scan_target_dir:
        scan_webshell_files_in_dir(main_window)

    if not hasattr(main_window, 'webshell_files_to_scan') or not main_window.webshell_files_to_scan:
        main_window.show_status("请先选择文件或目录，并确保选择了文件类型", "red")
        return

    main_window.webshell_btn_start_scan.setEnabled(False)
    main_window.webshell_btn_stop_scan.setEnabled(True)
    main_window.webshell_result.clear()
    main_window.webshell_progress.setValue(0)
    main_window.webshell_progress.setFormat("%p% - Scanning...")
    main_window.show_status("开始批量扫描...", "#007acc")


    # Create and start the batch thread
    main_window.batch_webshell_thread = BatchWebShellAnalysisThread(main_window.webshell_files_to_scan)
    main_window.batch_webshell_thread.progress_updated.connect(
        lambda p, s, r: update_webshell_progress(main_window, p, s, r)
    )
    main_window.batch_webshell_thread.scan_complete.connect(
        lambda: webshell_scan_complete(main_window)
    )
    main_window.batch_webshell_thread.start()


def stop_webshell_scan(main_window):
    """Slot to stop the running webshell scan thread."""
    if hasattr(main_window, 'batch_webshell_thread') and main_window.batch_webshell_thread.isRunning():
        logging.info("Attempting to stop batch webshell scan...")
        main_window.batch_webshell_thread.stop()
        main_window.webshell_btn_stop_scan.setEnabled(False)
        main_window.webshell_btn_stop_scan.setText("停止中...")
        main_window.show_status("正在停止扫描...", "orange")
    else:
        logging.warning("Stop scan called but no thread is running.")


def update_webshell_progress(main_window, percent, status, result_chunk):
    """Slot to update progress bar and result text area."""
    # Ensure progress bar doesn't exceed maximum if file count is low
    max_val = main_window.webshell_progress.maximum()
    current_val = int((percent / 100) * max_val)
    main_window.webshell_progress.setValue(current_val)
    main_window.webshell_progress.setFormat(f"%p% - {status}")

    status_color = "#007acc" # Default blue/info
    if "检测到恶意文件" in status:
        status_color = "#ff4757" # Red
    elif "安全文件" in status:
        status_color = "#2ed573" # Green
    elif "错误" in status or "失败" in status:
        status_color = "orange" # Orange/Yellow for warnings/errors

    main_window.show_status(status, status_color)

    # Only append actual results (malicious findings or errors)
    if result_chunk and result_chunk.strip():
         main_window.webshell_result.insertPlainText(result_chunk)
         main_window.webshell_result.ensureCursorVisible() # Scroll to bottom


def webshell_scan_complete(main_window):
    """Slot called when the batch scan thread finishes."""
    logging.info("Webshell scan complete signal received.")
    main_window.webshell_btn_start_scan.setEnabled(True)
    main_window.webshell_btn_stop_scan.setEnabled(False)
    main_window.webshell_btn_stop_scan.setText("停止扫描") # Reset button text

    # Get final status from progress bar text
    final_status = main_window.webshell_progress.format().split('- ', 1)[-1].strip()
    if not final_status or "%" in final_status: # Handle cases where format wasn't updated correctly
        final_status = "扫描完成"

    main_window.show_status(final_status, "#2ed573" if "中止" not in final_status else "orange")
    main_window.webshell_progress.setValue(main_window.webshell_progress.maximum()) # Ensure it's 100%