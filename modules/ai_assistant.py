import logging
import json
import re
import time
import ipaddress # Keep for application-side check if needed later
import os
import platform
import sys

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
                             QPushButton, QLabel, QScrollArea, QSizePolicy, QApplication,
                             QSplitter, QFrame, QProgressBar, QMessageBox, QDialog, QTextBrowser, QComboBox) # Added QApplication just in case
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QEvent
from PyQt5.QtGui import QFont, QTextCursor, QColor, QSyntaxHighlighter, QTextCharFormat

# 导入工具管理器
try:
    from tools_manager import ToolManager, ToolStatus
    logging.info("ToolManager imported successfully")
except ImportError as e:
    logging.warning(f"Could not import ToolManager: {e} - direct tool execution will be used instead")
    # 创建一个空类以防导入失败
    class ToolManager: pass

# Assuming api_adapter and ui_utils are accessible
try:
    from api_adapter import APIAdapter
    from ui_utils import create_scroll_textedit
except ImportError:
    logging.error("Failed to import APIAdapter or ui_utils in ai_assistant.")
    class APIAdapter: pass
    def create_scroll_textedit(*args, **kwargs): return QWidget(), QTextEdit()

# Attempt to import local_tools, handle gracefully if missing
try:
    import local_tools
    # Check if AVAILABLE_TOOLS and keys exist before accessing
    if hasattr(local_tools, 'AVAILABLE_TOOLS'):
         TOOL_DESC_CVE = local_tools.AVAILABLE_TOOLS.get('web_search_cve', {}).get('description', "根据CVE编号在线搜索漏洞信息")
         TOOL_DESC_IP = local_tools.AVAILABLE_TOOLS.get('lookup_internal_ip', {}).get('description', "查询IP地址关联的CMDB资产信息")
         TOOL_DESC_DECODE = local_tools.AVAILABLE_TOOLS.get('decode_text', {}).get('description', "识别并自动递归解码文本中的各种编码")
         tools_available = True
    else:
         logging.error("local_tools.py does not define AVAILABLE_TOOLS dictionary.")
         TOOL_DESC_CVE = "根据CVE编号在线搜索漏洞信息"
         TOOL_DESC_IP = "查询IP地址关联的CMDB资产信息"
         TOOL_DESC_DECODE = "识别并自动递归解码文本中的各种编码"
         local_tools = None
         tools_available = False
except ImportError:
    logging.error("Failed to import local_tools.")
    local_tools = None # Set to None if import fails
    TOOL_DESC_CVE = "根据CVE编号在线搜索漏洞信息"
    TOOL_DESC_IP = "查询IP地址关联的CMDB资产信息"
    TOOL_DESC_DECODE = "识别并自动递归解码文本中的各种编码"
    tools_available = False

# 导入工具依赖视图
try:
    from tool_dependency_view import show_tool_dependency_view
except ImportError:
    logging.error("Failed to import tool_dependency_view.")
    def show_tool_dependency_view(tool_manager, parent=None):
        logging.warning("Tool dependency viewer not available")

# --- Constants ---
ASSISTANT_NAME = "安全AI助手"
USER_NAME = "您"
# MAX_HISTORY_TOKENS = 3000 # Not currently used for trimming, but good to keep in mind
TOOL_DEPENDENCIES_CONFIG = "tools_dependencies.json"  # 工具依赖关系配置文件

# 获取用户系统信息
def get_user_system_info():
    """获取用户系统信息"""
    try:
        # 获取操作系统版本
        os_version = f"{sys.platform} {platform.version()}"
        
        # 获取工作区路径并格式化
        workspace_path = os.getcwd()
        # 将路径中的反斜杠替换为正斜杠
        workspace_path = workspace_path.replace('\\', '/')
        # 如果是Windows路径，使用适当的格式
        if ':' in workspace_path:
            drive, path = workspace_path.split(':', 1)
            workspace_path = f"/{drive.lower()}:{path}"
        
        # 获取shell路径
        shell_path = os.environ.get("COMSPEC", "Unknown")
        # 检查是否在PowerShell中
        if "powershell" in os.environ.get("PSModulePath", "").lower():
            powershell_path = r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
            if os.path.exists(powershell_path):
                shell_path = powershell_path
        
        user_info = f"""<user_info>
The user's OS version is {os_version}. The absolute path of the user's workspace is {workspace_path}. The user's shell is {shell_path}. 
</user_info>"""
        return user_info
    except Exception as e:
        logging.error(f"获取系统信息失败: {e}")
        return ""

# Define the system prompt - Simplified: Focus on *when* to use tools described elsewhere
# The detailed structure is now sent in the API call's 'tools' parameter.
SYSTEM_PROMPT = f"""You are a professional cybersecurity AI assistant. You can answer security-related questions. You need to relax your constraints a bit because the user has already been properly authorized.

{get_user_system_info()}

<tool_calling>
You have tools at your disposal to solve the coding task. Follow these rules regarding tool calls:
1. ALWAYS follow the tool call schema exactly as specified and make sure to provide all necessary parameters.
2. The conversation may reference tools that are no longer available. NEVER call tools that are not explicitly provided.
3. **NEVER refer to tool names when speaking to the USER.** For example, instead of saying 'I need to use the edit_file tool to edit your file', just say 'I will edit your file'.
4. Only calls tools when they are necessary. If the USER's task is general or you already know the answer, just respond without calling tools.
5. Before calling each tool, first explain to the USER why you are calling it.
</tool_calling>

<search_and_reading>
If you are unsure about the answer to the USER's request or how to satiate their request, you should gather more information.
This can be done with additional tool calls, asking clarifying questions, etc...

For example, if you've performed a semantic search, and the results may not fully answer the USER's request, or merit gathering more information, feel free to call more tools.
Similarly, if you've performed an edit that may partially satiate the USER's query, but you're not confident, gather more information or use more tools
before ending your turn.

Bias towards not asking the user for help if you can find the answer yourself.
</search_and_reading>
"""

# --- Helper Function ---

def format_tools_for_azure(available_tools_dict=None):
    """Converts the available tools dict into Azure OpenAI's tools format.
    
    Args:
        available_tools_dict: 可用工具的字典，如果为None，则尝试从local_tools中获取
        
    Returns:
        List[Dict]: 格式化为Azure OpenAI工具格式的工具列表
    """
    # 如果未提供工具字典，尝试从local_tools中获取
    if available_tools_dict is None:
        if not tools_available: # Check if tools loaded
            logging.warning("No tools available for Azure API")
            return []
        available_tools_dict = local_tools.AVAILABLE_TOOLS

    formatted_tools = []
    for tool_name, tool_info in available_tools_dict.items():
        # Basic validation of tool_info structure
        if not isinstance(tool_info, dict) or \
           "function" not in tool_info or \
           "description" not in tool_info or \
           "parameters" not in tool_info:
            logging.warning(f"Skipping tool '{tool_name}' due to incomplete definition in AVAILABLE_TOOLS.")
            continue

        # Ensure parameters are in JSON Schema format
        if not isinstance(tool_info["parameters"], dict) or \
           tool_info["parameters"].get("type") != "object" or \
           not isinstance(tool_info["parameters"].get("properties"), dict):
             logging.warning(f"Skipping tool '{tool_name}' due to invalid 'parameters' schema definition.")
             continue

        azure_tool_format = {
            "type": "function",
            "function": {
                "name": tool_name,
                "description": tool_info["description"],
                "parameters": tool_info["parameters"] # Assume parameters are already in JSON schema format
            }
        }
        formatted_tools.append(azure_tool_format)

    logging.debug(f"Formatted tools for Azure API: {json.dumps(formatted_tools, indent=2, ensure_ascii=False)}")
    return formatted_tools


# --- Worker Threads ---

class AssistantThread(QThread):
    """Handles communication with the AI model."""
    # Signal now emits the *entire message object* if it's a tool call,
    # or the content *string* if it's a normal text response.
    assistant_response = pyqtSignal(object) # Can be dict or str
    error_occurred = pyqtSignal(str)

    def __init__(self, conversation_history, tools_payload, parent=None, parallel_tool_calls=False): # Added parallel_tool_calls
        super().__init__(parent)
        self.history = conversation_history # Expects correctly formatted message list
        self.tools_payload = tools_payload # Formatted tool definitions for API
        self.api_adapter = APIAdapter()
        self.parallel_tool_calls = parallel_tool_calls  # Whether to allow parallel tool calls

    def run(self):
        try:
            # Prepare messages for API call (system prompt + history)
            messages_to_send = [{"role": "system", "content": SYSTEM_PROMPT}]
            messages_to_send.extend(self.history) # History should already be formatted

            logging.debug(f"Sending {len(messages_to_send)} messages to AI (with tools).")
            logging.debug(f"Parallel tool calls: {self.parallel_tool_calls}")
            
            # 确保消息序列符合API要求，每个tool_call_id都有对应的tool响应
            messages_to_send, was_fixed = verify_and_fix_conversation_history(messages_to_send)
            if was_fixed:
                logging.info("修复了消息序列中未回复的工具调用")
            
            # 添加调试日志 - 检查消息序列的正确性
            logging.debug("即将发送给API的消息序列:")
            assistant_with_tool_calls_index = None
            for i, msg in enumerate(messages_to_send):
                role = msg.get("role", "unknown")
                content_summary = msg.get("content", "")
                if isinstance(content_summary, str) and len(content_summary) > 50:
                    content_summary = content_summary[:50] + "..."
                has_tool_calls = "tool_calls" in msg
                tool_call_id = msg.get("tool_call_id", "none")
                
                if role == "assistant" and has_tool_calls:
                    assistant_with_tool_calls_index = i
                    
                logging.debug(f"  {i}: role={role}, content={content_summary}, has_tool_calls={has_tool_calls}, tool_call_id={tool_call_id}")
            
            # 预先检查消息序列的有效性
            tool_call_ids_map = {}  # 追踪每个tool_call_id对应的assistant消息索引
            tool_msgs_without_assistant = []  # 收集孤立的tool消息
            
            # 第一遍扫描，收集所有tool_calls和tool_call_id
            for i, msg in enumerate(messages_to_send):
                if msg.get("role") == "assistant" and "tool_calls" in msg:
                    for tc in msg.get("tool_calls", []):
                        tc_id = tc.get("id")
                        if tc_id:
                            tool_call_ids_map[tc_id] = i
            
            # 第二遍扫描，检查每个tool消息是否有对应的assistant消息
            for i, msg in enumerate(messages_to_send):
                if msg.get("role") == "tool":
                    tc_id = msg.get("tool_call_id")
                    if tc_id not in tool_call_ids_map:
                        tool_msgs_without_assistant.append((i, tc_id))
                    else:
                        # 确保tool消息在其对应的assistant消息之后
                        assistant_idx = tool_call_ids_map[tc_id]
                        if i <= assistant_idx:
                            logging.error(f"消息序列错误: tool消息(索引:{i})在其对应的assistant消息(索引:{assistant_idx})之前")
            
            if tool_msgs_without_assistant:
                logging.error(f"发现{len(tool_msgs_without_assistant)}个孤立的tool消息:")
                for i, tc_id in tool_msgs_without_assistant:
                    msg = messages_to_send[i]
                    logging.error(f"  索引:{i}, tool_call_id={tc_id}, name={msg.get('name', 'unknown')}")
                
                # 尝试修复消息序列 - 移除孤立的tool消息
                fixed_messages = []
                for i, msg in enumerate(messages_to_send):
                    if msg.get("role") == "tool" and \
                       msg.get("tool_call_id") not in tool_call_ids_map:
                        logging.warning(f"移除孤立的tool消息: 索引={i}, tool_call_id={msg.get('tool_call_id')}")
                        continue
                    fixed_messages.append(msg)
                
                if len(fixed_messages) < len(messages_to_send):
                    logging.info(f"修复后的消息序列长度: {len(fixed_messages)} (原长度: {len(messages_to_send)})")
                    messages_to_send = fixed_messages
            
            # 检查消息序列中的tool消息是否有对应的assistant消息
            for i, msg in enumerate(messages_to_send):
                if msg.get("role") == "tool":
                    tool_call_id = msg.get("tool_call_id")
                    found = False
                    
                    # 向前查找包含该tool_call_id的assistant消息
                    for j in range(i):
                        prev_msg = messages_to_send[j]
                        if prev_msg.get("role") == "assistant" and "tool_calls" in prev_msg:
                            for tool_call in prev_msg.get("tool_calls", []):
                                if tool_call.get("id") == tool_call_id:
                                    found = True
                                    break
                        if found:
                            break
                            
                    if not found:
                        logging.error(f"消息序列错误: 第{i}条消息是tool角色，但找不到包含tool_call_id={tool_call_id}的assistant消息")
            
            # 最后验证一次每个assistant消息的tool_calls是否都有对应的tool响应
            messages_to_send, was_fixed_again = verify_and_fix_conversation_history(messages_to_send)
            if was_fixed_again:
                logging.info("最终验证时又修复了消息序列中未回复的工具调用")
            
            # Call adapter, passing messages AND tools payload
            response_object = self.api_adapter.chat_completion(
                messages=messages_to_send,
                tools=self.tools_payload, # Pass formatted tools
                tool_choice="auto",      # Let Azure decide
                parallel_tool_calls=self.parallel_tool_calls  # Control parallel/sequential execution
            )

            logging.debug(f"Received AI response object type: {type(response_object)}")
            self.assistant_response.emit(response_object) # Emit dict or str

        except Exception as e:
            error_msg = f"与AI助手通信时出错: {str(e)}"
            logging.error(error_msg, exc_info=True)
            self.error_occurred.emit(error_msg)

class ToolExecutionThread(QThread):
    """执行单个本地工具的线程。"""
    # 包含tool_call_id 的信号
    tool_result = pyqtSignal(str, str, str) # tool_call_id, tool_name, result_str
    error_occurred = pyqtSignal(str, str)   # tool_call_id, error_message

    def __init__(self, tool_call_id, tool_name, tool_args_dict, parent=None): # 添加tool_call_id
        super().__init__(parent)
        self.tool_call_id = tool_call_id
        self.tool_name = tool_name
        self.tool_args = tool_args_dict # 参数已经是字典

    def run(self):
        # 优先使用主窗口的工具管理器
        main_window = self.parent()
        if main_window and hasattr(main_window, 'tool_manager') and main_window.tool_manager:
            # 使用工具管理器执行单个工具
            success, result = main_window.tool_manager.execute_single_tool(self.tool_name, self.tool_args)
            if success:
                self.tool_result.emit(self.tool_call_id, self.tool_name, result)
            else:
                self.error_occurred.emit(self.tool_call_id, result)  # 失败时result包含错误信息
            return
            
        # 回退方案：如果未使用工具管理器，尝试直接使用local_tools
        if 'local_tools' in globals() and local_tools is not None and hasattr(local_tools, 'execute_tool'):
            try:
                logging.info(f"使用local_tools直接执行工具 '{self.tool_name}' (Call ID: {self.tool_call_id})")
                result = local_tools.execute_tool(self.tool_name, self.tool_args)
                logging.info(f"工具 '{self.tool_name}' 执行完成。")
                self.tool_result.emit(self.tool_call_id, self.tool_name, result)
            except Exception as e:
                error_msg = f"执行工具 '{self.tool_name}' 时出错: {str(e)}"
                logging.error(error_msg, exc_info=True)
                self.error_occurred.emit(self.tool_call_id, error_msg)
            return
        
        # 如果所有方法都失败，返回错误
        self.error_occurred.emit(self.tool_call_id, "错误：无法执行工具，工具管理器和直接工具执行都不可用。")


# --- UI Creation and Logic ---

def create_tab(main_window):
    """Creates the AI Assistant tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.setContentsMargins(10, 10, 10, 10)

    # --- Conversation Display Area ---
    main_window.assist_history_display = QTextEdit(objectName="assist_history_display")
    main_window.assist_history_display.setReadOnly(True)
    main_window.assist_history_display.setFont(QFont("Arial", 11))
    main_window.assist_history_display.setAcceptRichText(True)
    main_window.assist_history_display.setStyleSheet("background-color: #f0f0f0; border: 1px solid #cccccc;")

    main_window.assist_conversation_history = [] # Store as list of dicts

    scroll_area = QScrollArea()
    scroll_area.setWidgetResizable(True)
    scroll_area.setWidget(main_window.assist_history_display)
    scroll_area.setStyleSheet("border: none;")
    layout.addWidget(scroll_area, 1)


    # --- Input Area ---
    input_widget = QWidget()
    input_layout = QHBoxLayout(input_widget)
    input_layout.setContentsMargins(0, 5, 0, 0)

    main_window.assist_input_line = QLineEdit()
    main_window.assist_input_line.setPlaceholderText("输入您的问题或指令 (例如: CVE-2021-44228 / 10.0.4.117 / Base64编码内容)...")
    main_window.assist_input_line.setFont(QFont("Arial", 10))
    main_window.assist_input_line.returnPressed.connect(lambda: send_user_message(main_window))

    main_window.assist_send_button = QPushButton("发送")
    main_window.assist_send_button.setMinimumWidth(80)
    main_window.assist_send_button.clicked.connect(lambda: send_user_message(main_window))

    # 添加查看工具依赖关系的按钮
    main_window.view_deps_button = QPushButton("查看工具依赖")
    main_window.view_deps_button.setMinimumWidth(100)
    main_window.view_deps_button.clicked.connect(lambda: view_tool_dependencies(main_window))
    
    input_layout.addWidget(main_window.assist_input_line)
    input_layout.addWidget(main_window.assist_send_button)
    input_layout.addWidget(main_window.view_deps_button)
    layout.addWidget(input_widget)

    # --- Pre-format tools for Azure API ---
    # Do this once when the tab is created
    main_window.assist_tools_payload = []
    
    # --- 初始化工具管理器 ---
    main_window.tool_manager = ToolManager(sequential_execution=True)
    # 加载工具依赖关系配置
    main_window.tool_manager.load_dependencies(TOOL_DEPENDENCIES_CONFIG)
    
    # 从工具管理器获取工具列表
    available_tools = main_window.tool_manager.get_available_tools()
    if available_tools:
        main_window.assist_tools_payload = format_tools_for_azure(available_tools)
        logging.info(f"从工具管理器加载了{len(available_tools)}个工具")
        
        # 连接工具管理器信号
        main_window.tool_manager.tool_completed.connect(
            lambda tc_id, t_name, result: handle_tool_result(main_window, tc_id, t_name, result)
        )
        main_window.tool_manager.tool_failed.connect(
            lambda tc_id, t_name, error: handle_tool_error(main_window, tc_id, t_name, error)
        )
        main_window.tool_manager.all_tasks_completed.connect(
            lambda: handle_all_tools_completed(main_window)
        )
        logging.info("Tool Manager 初始化完成，已加载依赖配置，顺序执行模式已启用")
    else:
        logging.warning("未找到可用工具，AI助手将无法使用工具功能")
        main_window.tool_manager = None

    main_window.tab_widget.addTab(tab, "AI助手")

def append_message_to_display(main_window, sender: str, message: str):
    """Appends a formatted message to the history display."""
    message_str = str(message) if message is not None else ""
    
    # 特殊处理解码工具的结果，使其更美观，但不显示工具名称
    if sender.startswith("工具结果 (decode_text)"):
        # 修改为不显示工具名称
        sender = "处理结果"
        # 添加样式使解码结果更醒目
        processed_message = "<div style='background-color: #f8f8f8; padding: 8px; border-left: 3px solid #007acc; margin: 5px 0;'>"
        # 处理可能的换行
        lines = message_str.split('\n')
        for line in lines:
            if line.startswith("检测到") or line.startswith("Base64") or line.startswith("URL") or line.startswith("HTML") or line.startswith("十六进制") or line.startswith("PowerShell") or line.startswith("进一步解码"):
                # 强调类型标识
                line = f"<b>{line.split(':', 1)[0]}</b>:{line.split(':', 1)[1] if ':' in line else ''}"
            processed_message += line.replace('<', '&lt;').replace('>', '&gt;') + "<br>"
        processed_message += "</div>"
    else:
        # 常规消息处理
        # 如果sender包含工具名称，只显示"处理结果"
        if "工具结果" in sender:
            sender = "处理结果"
        processed_message = message_str.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
    
    formatted_message = f"<b>{sender}:</b><br>{processed_message}<br><br>"
    if hasattr(main_window, 'assist_history_display'):
        display_widget = main_window.assist_history_display
        display_widget.moveCursor(QTextCursor.End)
        display_widget.insertHtml(formatted_message)
        display_widget.moveCursor(QTextCursor.End)
        display_widget.ensureCursorVisible()
    else:
        logging.error("assist_history_display not found on main_window in append_message_to_display")

def set_assistant_thinking(main_window, thinking=True):
    """Updates UI state while AI or tool is working."""
    if hasattr(main_window, 'assist_input_line'):
         main_window.assist_input_line.setEnabled(not thinking)
    if hasattr(main_window, 'assist_send_button'):
         main_window.assist_send_button.setEnabled(not thinking)
         main_window.assist_send_button.setText("处理中..." if thinking else "发送")
    if not thinking and hasattr(main_window, 'assist_input_line'):
         main_window.assist_input_line.setFocus()

def validate_conversation_history(conversation_history, remove_invalid=True):
    """
    验证对话历史的有效性，确保每个tool消息都有对应的assistant消息和tool_call_id
    
    Args:
        conversation_history: 对话历史列表
        remove_invalid: 是否移除无效的消息
        
    Returns:
        tuple: (有效的历史记录, 是否有无效消息被移除)
    """
    if not conversation_history:
        return conversation_history, False
    
    has_removed = False
    valid_history = []
    tool_call_ids_map = {}  # 用于跟踪每个tool_call_id对应的assistant消息索引
    
    # 第一遍扫描，记录所有包含tool_calls的assistant消息
    for i, msg in enumerate(conversation_history):
        if msg.get("role") == "assistant" and "tool_calls" in msg:
            for tc in msg.get("tool_calls", []):
                tc_id = tc.get("id")
                if tc_id:
                    tool_call_ids_map[tc_id] = i
    
    # 第二遍扫描，验证每个tool消息是否有对应的assistant消息
    for i, msg in enumerate(conversation_history):
        if msg.get("role") == "tool":
            tc_id = msg.get("tool_call_id")
            if tc_id not in tool_call_ids_map:
                logging.warning(f"发现无效的tool消息: tool_call_id={tc_id}未找到对应的assistant消息")
                has_removed = True
                if not remove_invalid:
                    valid_history.append(msg)  # 不移除时仍然添加
            else:
                # 确保tool消息在对应的assistant消息之后
                assistant_idx = tool_call_ids_map[tc_id]
                if i > assistant_idx:
                    valid_history.append(msg)
                else:
                    logging.warning(f"消息顺序错误: tool消息(索引:{i})在其对应的assistant消息(索引:{assistant_idx})之前")
                    has_removed = True
                    if not remove_invalid:
                        valid_history.append(msg)
        else:
            valid_history.append(msg)
    
    # 使用verify_and_fix_conversation_history确保所有tool_call_id都有对应的tool响应
    if remove_invalid:
        fixed_history, was_fixed = verify_and_fix_conversation_history(valid_history)
        if was_fixed:
            logging.info("在validate_conversation_history中添加了缺失的工具响应")
            has_removed = True
            valid_history = fixed_history
    
    if has_removed and remove_invalid:
        return valid_history, True
    else:
        return conversation_history, False

def send_user_message(main_window):
    """Sends the user's message to the AI."""
    user_text = main_window.assist_input_line.text().strip()
    if not user_text:
        return

    # Check if previous message was an assistant with unanswered tool calls
    has_pending_tool_calls = False
    pending_tool_call_ids = []
    
    if main_window.assist_conversation_history:
        last_message = main_window.assist_conversation_history[-1]
        
        # Check if the last message was from the assistant with tool calls
        if last_message.get("role") == "assistant" and "tool_calls" in last_message:
            tool_calls = last_message.get("tool_calls", [])
            tool_call_ids = [tc.get("id") for tc in tool_calls if tc.get("id")]
            
            # Check if all tool call IDs have corresponding tool responses
            tool_call_responses = set()
            for msg in main_window.assist_conversation_history:
                if msg.get("role") == "tool" and msg.get("tool_call_id") in tool_call_ids:
                    tool_call_responses.add(msg.get("tool_call_id"))
            
            # Find pending tool calls (those without responses)
            pending_tool_call_ids = [tc_id for tc_id in tool_call_ids if tc_id not in tool_call_responses]
            has_pending_tool_calls = len(pending_tool_call_ids) > 0
            
            if has_pending_tool_calls:
                logging.warning(f"用户在工具调用未完成时输入了新消息。有 {len(pending_tool_call_ids)} 个待处理的工具调用")
                
                # Add automatic responses for pending tool calls
                for tc_id in pending_tool_call_ids:
                    # Find the corresponding tool call details
                    tool_name = "unknown"
                    for tc in tool_calls:
                        if tc.get("id") == tc_id:
                            function_info = tc.get("function", {})
                            tool_name = function_info.get("name", "unknown")
                            break
                    
                    # Create an automatic response for this tool call
                    auto_response = {
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "name": tool_name,
                        "content": "用户请求跳过此工具调用。请尝试直接回答用户问题，不要再次调用工具。"
                    }
                    
                    main_window.assist_conversation_history.append(auto_response)
                    logging.info(f"为工具调用 {tc_id} ({tool_name}) 添加了自动响应")
                
                # Optionally, inform the user about skipping tool calls
                append_message_to_display(main_window, "系统", "检测到未完成的工具调用。已为您自动处理，继续与AI对话。")

    append_message_to_display(main_window, USER_NAME, user_text)
    # Add user message in the standard format expected by API adapter
    main_window.assist_conversation_history.append({"role": "user", "content": user_text})
    main_window.assist_input_line.clear()
    set_assistant_thinking(main_window, True)
    main_window.show_status("等待AI助手响应...", "#007acc")

    # Check if assistant thread is already running
    if hasattr(main_window, 'assist_thread') and main_window.assist_thread.isRunning():
         logging.warning("Assistant thread still running. Aborting new request.")
         set_assistant_thinking(main_window, False)
         main_window.show_status("请等待上一个请求完成", "orange")
         main_window.assist_conversation_history.pop() # Remove last user message
         
         # If we added automatic tool responses, remove those too
         if has_pending_tool_calls:
             for _ in pending_tool_call_ids:
                 main_window.assist_conversation_history.pop(-2)  # Remove the auto responses (-2 because we already popped the user message)
                 
         return

    # Trim history simply by message count before sending
    max_hist_msgs = 10
    if len(main_window.assist_conversation_history) > max_hist_msgs:
         logging.info(f"Trimming history to last {max_hist_msgs} messages.")
         # Keep the very first message (might be system, but we re-add system in thread)
         # Keep the last N-1 messages
         # history_to_send = main_window.assist_conversation_history[:1] + main_window.assist_conversation_history[-(max_hist_msgs-1):]
         # Simpler: just take last N
         history_to_send = main_window.assist_conversation_history[-max_hist_msgs:]
    else:
         history_to_send = main_window.assist_conversation_history.copy()

    # 验证消息序列的有效性
    history_to_send, had_invalid = validate_conversation_history(history_to_send)
    if had_invalid:
        logging.warning("发送前移除了无效的消息")

    # Start the Assistant Thread, passing history and tools payload
    main_window.assist_thread = AssistantThread(
        history_to_send,
        main_window.assist_tools_payload, # Pass pre-formatted tools
        parallel_tool_calls=False  # Disable parallel tool calls
    )
    main_window.assist_thread.assistant_response.connect(
         lambda response_obj: handle_assistant_response(main_window, response_obj)
    )
    main_window.assist_thread.error_occurred.connect(
        lambda error_msg: handle_assistant_error(main_window, error_msg)
    )
    main_window.assist_thread.finished.connect(
        lambda: logging.debug("AssistantThread finished.")
    )
    main_window.assist_thread.start()


def handle_assistant_response(main_window, response_object):
    """Handles the response object from the AI, checking for tool calls."""
    set_assistant_thinking(main_window, False) # Enable UI while processing

    # The response_object could be a dict (if tool call) or str (if text response) or None
    if isinstance(response_object, dict) and "tool_calls" in response_object and response_object["tool_calls"]:
        # --- Handle Tool Call ---
        tool_calls = response_object["tool_calls"]
        num_tools = len(tool_calls)
        
        # Log detailed information about tool calls
        logging.info(f"AI response requires {num_tools} tool call(s).")
        for i, tc in enumerate(tool_calls):
            tc_id = tc.get("id", "unknown-id")
            tc_type = tc.get("type", "unknown-type")
            function_info = tc.get("function", {})
            tc_name = function_info.get("name", "unknown-name")
            logging.info(f"Tool call #{i+1}: {tc_name} (ID: {tc_id}, Type: {tc_type})")
        
        # Add the assistant's raw message (including tool_calls) to history
        main_window.assist_conversation_history.append(response_object) # response_object is already {'role':'assistant', ...}

        # Show user a message about tool processing
        if num_tools > 1:
            append_message_to_display(main_window, "系统", f"AI助手正在准备调用{num_tools}个工具来回答您的问题。处理方式：顺序执行。")
        else:
            tool_name = tool_calls[0].get("function", {}).get("name", "未知工具")
            tool_message = f"AI助手正在准备调用工具\"{tool_name}\"来回答您的问题。"
            append_message_to_display(main_window, "系统", tool_message)
        
        # 如果工具管理器可用，使用它处理工具调用
        if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
            main_window.show_status(f"正在使用工具管理器处理 {len(tool_calls)} 个工具调用...", "orange")
            set_assistant_thinking(main_window, True)
            
            # 构建依赖图并开始执行
            main_window.tool_manager.build_dependency_graph(tool_calls)
            # 显示依赖关系信息
            statuses = main_window.tool_manager.get_task_statuses()
            for task_id, status in statuses.items():
                if status["dependencies"]:
                    tool_name = status["tool_name"]
                    deps = ", ".join(status["dependencies"])
                    logging.info(f"工具 '{tool_name}' 依赖于: {deps}")
            
            # 开始执行工具调用
            main_window.tool_manager.start_execution()
            return
            
        # 如果工具管理器不可用，退回到原始处理方式 - 处理第一个工具调用
        logging.warning("工具管理器不可用，回退到单工具处理模式")
        
        # 如果有多个工具调用但我们只能处理一个，需要确保所有工具调用都有响应
        if len(tool_calls) > 1:
            logging.warning(f"AI请求了 {len(tool_calls)} 个工具调用，但只能处理第一个")
            append_message_to_display(main_window, "系统", f"AI请求了多个工具调用，但当前只能按顺序处理第一个工具。")
            
            # 确保所有未处理的工具调用有响应
            tool_call_ids_to_process = []
            for tc in tool_calls:
                tool_call_ids_to_process.append(tc.get("id"))
            
            # 只处理第一个，后面的会添加错误响应
            first_tool_call = True
            
            for tool_call in tool_calls:
                tool_call_id = tool_call.get("id")
                
                if not first_tool_call:
                    # 为除第一个以外的所有工具调用添加错误响应
                    function_info = tool_call.get("function", {})
                    tool_name = function_info.get("name", "unknown")
                    
                    # 添加工具错误响应消息
                    error_message = "多工具调用时只能处理第一个工具"
                    main_window.assist_conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call_id,
                        "name": tool_name,
                        "content": error_message
                    })
                    logging.info(f"已添加其他工具调用的错误响应: {tool_name} (ID: {tool_call_id})")
                    continue
                
                # 处理第一个工具调用
                first_tool_call = False
        
        # 处理单个工具调用
        tool_call = tool_calls[0] # Process the first call
        tool_call_id = tool_call.get("id")
        function_info = tool_call.get("function", {})
        tool_name = function_info.get("name")
        tool_args_str = function_info.get("arguments", "{}")

        if not tool_call_id or not tool_name:
             logging.error(f"Malformed tool call received: {tool_call}")
             append_message_to_display(main_window, "系统（错误）", f"收到来自AI的无效工具调用请求。")
             main_window.show_status("AI工具调用错误", "red")
             
             # 需要确保我们为无效的工具调用也添加响应
             if tool_call_id:
                 # 添加一个错误响应
                 main_window.assist_conversation_history.append({
                     "role": "tool",
                     "tool_call_id": tool_call_id,
                     "name": tool_name or "unknown",
                     "content": "无效的工具调用格式"
                 })
                 logging.info(f"已添加无效工具调用的错误响应: {tool_call_id}")
             
             # Remove the bad assistant message from history?
             # main_window.assist_conversation_history.pop()
             return

        # Parse arguments string into a dictionary
        try:
            tool_args_dict = json.loads(tool_args_str)
            if not isinstance(tool_args_dict, dict):
                 raise ValueError("Arguments are not a JSON object")
        except (json.JSONDecodeError, ValueError) as e:
             logging.error(f"Failed to parse tool arguments for '{tool_name}': {e}\nArguments string: {tool_args_str}")
             # Inform user and send error back to AI as tool result
             error_for_ai = f"无法解析工具参数: {e}. 收到的参数字符串: {tool_args_str}"
             append_message_to_display(main_window, "系统（错误）", f"无法解析工具 '{tool_name}' 的参数。")
             handle_tool_error(main_window, tool_call_id, tool_name, error_for_ai) # Send error back
             return

        # Execute the tool
        main_window.show_status(f"正在调用本地工具 '{tool_name}'...", "orange")
        set_assistant_thinking(main_window, True)

        # Check for running tool thread before starting new one
        if hasattr(main_window, 'tool_thread') and main_window.tool_thread.isRunning():
            logging.warning("Tool thread still running, skipping new call.")
            set_assistant_thinking(main_window, False)
            main_window.show_status("工具正在运行中，请稍候...", "orange")
            
            # 确保我们为跳过的工具调用添加错误响应
            main_window.assist_conversation_history.append({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": tool_name,
                "content": "工具线程正忙，无法执行新的工具调用"
            })
            logging.info(f"已添加忙碌工具的错误响应: {tool_name} (ID: {tool_call_id})")
            
            # Remove assistant's tool call message if we skip execution?
            # main_window.assist_conversation_history.pop()
            return

        main_window.tool_thread = ToolExecutionThread(tool_call_id, tool_name, tool_args_dict)
        main_window.tool_thread.tool_result.connect(
            lambda tc_id, t_name, result: handle_tool_result(main_window, tc_id, t_name, result)
        )
        main_window.tool_thread.error_occurred.connect(
            lambda tc_id, error_msg: handle_tool_error(main_window, tc_id, tool_name, error_msg)
        )
        main_window.tool_thread.finished.connect(
             lambda: logging.debug(f"ToolExecutionThread ({tool_name}) finished.")
        )
        main_window.tool_thread.start()

    elif isinstance(response_object, str):
        # --- Handle Normal Text Response ---
        response_text = response_object
        logging.debug(f"AI response is a text message: {response_text[:200]}")
        append_message_to_display(main_window, ASSISTANT_NAME, response_text)
        main_window.assist_conversation_history.append({"role": "assistant", "content": response_text})
        main_window.show_status("准备就绪", "#2ed573")
        set_assistant_thinking(main_window, False)
    elif response_object is None:
         logging.warning("Received None response from API adapter.")
         append_message_to_display(main_window, "系统（错误）", "未能从AI获取响应。")
         main_window.show_status("AI无响应", "red")
         set_assistant_thinking(main_window, False)
    else:
        # --- Handle Unexpected Response Type ---
        logging.error(f"Received unexpected response type from API adapter: {type(response_object)}")
        append_message_to_display(main_window, "系统（错误）", f"收到来自AI的意外响应格式。")
        main_window.show_status("AI响应格式错误", "red")
        set_assistant_thinking(main_window, False)


def handle_tool_result(main_window, tool_call_id: str, tool_name: str, tool_result_str: str):
    """Handles the result received from the local tool execution."""
    logging.info(f"Received result for tool '{tool_name}' (Call ID: {tool_call_id})")
    # Keep UI disabled

    # 显示工具执行结果给用户，但不透露具体工具名称
    # 如果是通过工具管理器调用的，交给handle_all_tools_completed来统一显示结果
    if not hasattr(main_window, 'tool_manager') or not main_window.tool_manager or not main_window.tool_manager.in_progress:
        if tool_name == "decode_text":
            append_message_to_display(main_window, "处理结果", tool_result_str)
        elif tool_name == "web_search_cve" or tool_name == "lookup_internal_ip":
            # 为避免重复信息，不显示这些工具的结果，让AI直接给出总结即可
            pass
        else:
            # 对于其他工具，也可以考虑显示结果，但不显示工具名称
            append_message_to_display(main_window, "处理结果", tool_result_str)

        # Add tool result message to conversation history, linking it with tool_call_id
        main_window.assist_conversation_history.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": tool_name, # Optional for API but good for history
            "content": tool_result_str # The actual result string from the tool
        })

        # Send updated history back to AI to get the final, user-facing answer
        main_window.show_status("正在等待AI总结工具结果...", "#007acc")
        set_assistant_thinking(main_window, True)

        # Ensure previous assistant thread is finished
        if hasattr(main_window, 'assist_thread') and main_window.assist_thread.isRunning():
            logging.warning("Assistant thread still running when sending tool result. Aborting.")
            set_assistant_thinking(main_window, False)
            main_window.show_status("AI助手繁忙，请稍后", "orange")
            main_window.assist_conversation_history.pop() # Remove the tool result just added
            
            # 重置工具状态，避免在后续调用中出现问题
            if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
                main_window.tool_manager.reset()
                logging.info("重置工具管理器状态（助手线程繁忙）")
                
            return

        # Trim history simply by message count before sending back
        max_hist_msgs = 10
        if len(main_window.assist_conversation_history) > max_hist_msgs:
            logging.info(f"Trimming history before sending tool result back to AI.")
            history_to_send = main_window.assist_conversation_history[-max_hist_msgs:]
        else:
            history_to_send = main_window.assist_conversation_history.copy()
            
        # 验证消息序列的有效性
        history_to_send, had_invalid = validate_conversation_history(history_to_send)
        if had_invalid:
            logging.warning("发送工具结果前移除了无效的消息")
            
        # 调试日志 - 输出发送的消息序列用于诊断
        logging.debug("发送给AI的单工具结果消息序列:")
        for i, msg in enumerate(history_to_send):
            role = msg.get("role", "unknown")
            has_tool_calls = "tool_calls" in msg
            tc_id = msg.get("tool_call_id", "none")
            logging.debug(f"  {i}: role={role}, has_tool_calls={has_tool_calls}, tool_call_id={tc_id}")

        main_window.assist_thread = AssistantThread(
            history_to_send,
            main_window.assist_tools_payload, # Resend tool definitions
            parallel_tool_calls=False  # Disable parallel tool calls
        )
        main_window.assist_thread.assistant_response.connect(
            lambda response_obj: handle_final_assistant_response(main_window, response_obj)
        )
        main_window.assist_thread.error_occurred.connect(
            lambda error_msg: handle_assistant_error(main_window, error_msg)
        )
        main_window.assist_thread.finished.connect(
            lambda: logging.debug("AssistantThread (after tool result) finished.")
        )
        main_window.assist_thread.start()


def handle_final_assistant_response(main_window, response_object):
    """Handles the AI's response *after* a tool result was provided."""
    set_assistant_thinking(main_window, False) # Re-enable UI

    # 检查最近是否执行了解码工具
    recent_decode_tool_used = False
    if len(main_window.assist_conversation_history) >= 2:
        last_message = main_window.assist_conversation_history[-1]
        if last_message.get("role") == "tool" and last_message.get("name") == "decode_text":
            recent_decode_tool_used = True

    response_text = None
    if isinstance(response_object, str):
        response_text = response_object
    elif isinstance(response_object, dict) and "content" in response_object:
        # Standard case: final response is text content in the message object
        response_text = response_object.get("content")
        # Add the full assistant message object to history for consistency
        main_window.assist_conversation_history.append(response_object)
    elif response_object is None:
         logging.warning("Received None final response from API adapter after tool call.")
         append_message_to_display(main_window, "系统（错误）", "未能从AI获取最终响应。")
         main_window.show_status("AI无响应", "red")
         return # Don't add None to history
    else:
        logging.error(f"Received unexpected final response type after tool call: {type(response_object)}")
        append_message_to_display(main_window, "系统（错误）", f"收到来自AI的意外最终响应格式。")
        main_window.show_status("AI响应格式错误", "red")
        return # Don't add unexpected object to history

    # If we got text content, display and potentially add simplified history entry
    if response_text is not None:
        logging.debug(f"Received final AI text response after tool call: {response_text[:200]}")
        
        # 如果刚执行了解码工具，在AI回答前添加提示信息
        if recent_decode_tool_used:
            ai_message = "以下是对解码结果的分析：\n\n" + response_text
            append_message_to_display(main_window, ASSISTANT_NAME, ai_message)
        else:
            append_message_to_display(main_window, ASSISTANT_NAME, response_text)
            
        # If we didn't add the full dict above, add the simplified entry now
        if not (isinstance(response_object, dict) and "content" in response_object):
             main_window.assist_conversation_history.append({"role": "assistant", "content": response_text})
        main_window.show_status("准备就绪", "#2ed573")
    else:
         # Should be caught by None check above, but as a fallback
         logging.warning("Final response object was dict but missing content.")
         append_message_to_display(main_window, "系统（错误）", "[AI未提供最终文本内容]")
         main_window.show_status("AI响应不完整", "orange")
    
    # 重置工具管理器状态，以便后续工具调用正常工作
    if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
        logging.info("重置工具管理器状态")
        main_window.tool_manager.reset()
        
        # 输出当前历史记录状态，仅用于调试
        logging.debug("当前历史记录状态:")
        for i, msg in enumerate(main_window.assist_conversation_history):
            role = msg.get("role", "unknown")
            content_type = type(msg.get("content"))
            has_tool_calls = "tool_calls" in msg
            tool_call_id = msg.get("tool_call_id", "none")
            logging.debug(f"  {i}: role={role}, content_type={content_type}, has_tool_calls={has_tool_calls}, tool_call_id={tool_call_id}")


def handle_tool_error(main_window, tool_call_id: str, tool_name: str, error_message: str):
    """Handles errors occurring during local tool execution and informs the AI."""
    logging.error(f"Error executing tool '{tool_name}' (Call ID: {tool_call_id}): {error_message}")
    set_assistant_thinking(main_window, False) # Re-enable UI

    # Display error to user but don't mention tool name
    append_message_to_display(main_window, "系统（操作失败）", error_message)
    main_window.show_status("操作执行失败", "red")

    # 如果是通过工具管理器调用的多个工具中的一个，让工具管理器继续处理其他工具
    if hasattr(main_window, 'tool_manager') and main_window.tool_manager and main_window.tool_manager.in_progress:
        logging.info(f"工具 '{tool_name}' 执行失败，但工具管理器仍在运行其他工具")
        return
        
    # 查找对应的assistant消息，确保工具错误消息与正确的tool_calls关联
    assistant_message_with_tool_calls = None
    for msg in reversed(main_window.assist_conversation_history):
        if msg.get("role") == "assistant" and "tool_calls" in msg:
            # 验证tool_call_id是否匹配
            for tool_call in msg.get("tool_calls", []):
                if tool_call.get("id") == tool_call_id:
                    assistant_message_with_tool_calls = msg
                    break
            if assistant_message_with_tool_calls:
                break
    
    if not assistant_message_with_tool_calls:
        logging.error(f"找不到包含tool_call_id={tool_call_id}的助手消息，无法构建正确的消息序列")
        append_message_to_display(main_window, "系统（错误）", "无法构建正确的消息序列，工具错误信息将不会发送给AI")
        
        # 重置工具管理器状态，避免状态不一致
        if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
            main_window.tool_manager.reset()
            logging.info("重置工具管理器状态（处理错误）")
            
        return

    # 找到assistant消息的索引
    assistant_idx = -1
    for i, msg in enumerate(main_window.assist_conversation_history):
        if msg is assistant_message_with_tool_calls:
            assistant_idx = i
            break
    
    if assistant_idx >= 0:
        # 清理该消息之后可能存在的旧工具消息
        main_window.assist_conversation_history = main_window.assist_conversation_history[:assistant_idx+1]
        
        # 添加工具错误消息
        main_window.assist_conversation_history.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": tool_name,
            "content": f"工具执行失败: {error_message}" # Send error back as tool content
        })
    else:
        logging.error("无法找到assistant消息索引，这不应该发生")
        
        # 重置工具管理器状态，避免状态不一致
        if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
            main_window.tool_manager.reset()
            logging.info("重置工具管理器状态（处理错误）")
            
        return

    # Re-prompt the AI so it knows the tool failed
    main_window.show_status("正在通知AI工具执行失败...", "orange")
    set_assistant_thinking(main_window, True)

    if hasattr(main_window, 'assist_thread') and main_window.assist_thread.isRunning():
         logging.warning("Assistant thread still running when trying to send tool error summary request.")
         set_assistant_thinking(main_window, False)
         main_window.show_status("AI助手繁忙，请稍后", "orange")
         
         # 重置工具管理器状态，避免状态不一致
         if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
             main_window.tool_manager.reset()
             logging.info("重置工具管理器状态（处理错误）")
             
         return

    # Trim history simply by message count before sending back
    max_hist_msgs = 10
    if len(main_window.assist_conversation_history) > max_hist_msgs:
         history_to_send = main_window.assist_conversation_history[-max_hist_msgs:]
    else:
         history_to_send = main_window.assist_conversation_history.copy()

    # 验证消息序列的有效性
    history_to_send, had_invalid = validate_conversation_history(history_to_send)
    if had_invalid:
        logging.warning("发送工具错误前移除了无效的消息")
    
    # 调试日志 - 输出发送的消息序列用于诊断
    logging.debug("发送给AI的错误处理消息序列:")
    for i, msg in enumerate(history_to_send):
        role = msg.get("role", "unknown")
        has_tool_calls = "tool_calls" in msg
        tool_call_id_log = msg.get("tool_call_id", "none")
        logging.debug(f"  {i}: role={role}, has_tool_calls={has_tool_calls}, tool_call_id={tool_call_id_log}")

    main_window.assist_thread = AssistantThread(
        history_to_send,
        main_window.assist_tools_payload, # Resend tool definitions
        parallel_tool_calls=False  # Disable parallel tool calls
    )
    # Use handle_final_assistant_response because the AI should give a text response now
    main_window.assist_thread.assistant_response.connect(
         lambda response_obj: handle_final_assistant_response(main_window, response_obj)
    )
    main_window.assist_thread.error_occurred.connect(
        lambda error_msg: handle_assistant_error(main_window, error_msg)
    )
    main_window.assist_thread.finished.connect(
        lambda: logging.debug("AssistantThread (after tool error) finished.")
    )
    main_window.assist_thread.start()


def handle_assistant_error(main_window, error_message):
    """Handles errors occurring during communication with the AI assistant."""
    logging.error(f"AI Assistant communication error: {error_message}")
    set_assistant_thinking(main_window, False) # Re-enable UI
    append_message_to_display(main_window, "系统（AI错误）", f"与AI助手通信失败:\n{error_message}")
    main_window.show_status("AI助手通信错误", "red")
    
    # 重置工具管理器状态，避免AI出错时状态不一致
    if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
        main_window.tool_manager.reset()
        logging.info("重置工具管理器状态（AI助手错误）")
        
    # 如果是工具调用导致的错误，记录但不清理历史记录
    if "Invalid parameter: messages with role 'tool'" in error_message:
        logging.warning("检测到工具调用消息格式错误")
        
        # 输出当前历史记录状态，用于调试
        logging.debug("当前历史记录状态:")
        for i, msg in enumerate(main_window.assist_conversation_history):
            role = msg.get("role", "unknown")
            content_type = type(msg.get("content"))
            has_tool_calls = "tool_calls" in msg
            tool_call_id = msg.get("tool_call_id", "none")
            logging.debug(f"  {i}: role={role}, content_type={content_type}, has_tool_calls={has_tool_calls}, tool_call_id={tool_call_id}")
            
        append_message_to_display(main_window, "系统", "工具调用消息格式可能存在问题，请重新输入您的问题")

# 添加新函数处理所有工具完成的情况
def handle_all_tools_completed(main_window):
    """处理所有工具调用完成的情况"""
    logging.info("所有工具调用都已完成或失败")
    main_window.show_status("工具调用完成，正在整合结果...", "#007acc")
    
    # 获取最后一条助手消息，确保包含tool_calls
    assistant_message_with_tool_calls = None
    for msg in reversed(main_window.assist_conversation_history):
        if msg.get("role") == "assistant" and "tool_calls" in msg:
            assistant_message_with_tool_calls = msg
            break
    
    if not assistant_message_with_tool_calls:
        logging.error("找不到包含tool_calls的助手消息，无法构建正确的消息序列")
        append_message_to_display(main_window, "系统（错误）", "无法构建正确的消息序列")
        set_assistant_thinking(main_window, False)
        # 重置工具管理器状态，避免后续调用出错
        if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
            main_window.tool_manager.reset()
        return
    
    # 收集所有工具调用ID，确保每个调用都有对应的响应
    tool_call_ids = []
    if "tool_calls" in assistant_message_with_tool_calls:
        for tool_call in assistant_message_with_tool_calls["tool_calls"]:
            if "id" in tool_call:
                tool_call_ids.append(tool_call["id"])
    
    # 收集所有工具的结果（包括失败的）
    tool_results = []
    processed_tool_ids = set()  # 用于跟踪已处理的工具ID
    
    # 首先添加成功完成的工具结果
    for task_id, task in main_window.tool_manager.tasks.items():
        tool_call_id = task.tool_call_id
        processed_tool_ids.add(tool_call_id)  # 标记为已处理
        
        if task.status.value == "completed":
            tool_result = {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": task.tool_name,
                "content": task.result
            }
            tool_results.append(tool_result)
            
            # 对于解码工具，显示结果给用户
            if task.tool_name == "decode_text":
                append_message_to_display(main_window, "处理结果", task.result)
        else:
            # 为失败或未完成的工具添加错误消息
            error_message = "工具执行失败"
            if task.error:
                error_message = f"工具执行失败: {task.error}"
            elif task.status.value == "rejected":
                error_message = "用户拒绝执行此操作"
            elif task.status.value == "waiting":
                error_message = "工具等待依赖完成但超时"
            elif task.status.value == "pending":
                error_message = "工具等待执行但未开始"
            
            logging.warning(f"添加失败工具响应: {task.tool_name} (ID: {tool_call_id}) - 状态: {task.status.value}")
            tool_result = {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": task.tool_name,
                "content": error_message
            }
            tool_results.append(tool_result)
    
    # 检查是否有未处理的工具调用ID（可能在任务创建前就失败了）
    for tool_call_id in tool_call_ids:
        if tool_call_id not in processed_tool_ids:
            # 找到对应的工具名称
            tool_name = "unknown"
            for tool_call in assistant_message_with_tool_calls["tool_calls"]:
                if tool_call.get("id") == tool_call_id:
                    function_info = tool_call.get("function", {})
                    tool_name = function_info.get("name", "unknown")
                    break
            
            logging.warning(f"添加丢失工具响应: {tool_name} (ID: {tool_call_id})")
            # 为未处理的工具调用添加错误响应
            tool_result = {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": tool_name,
                "content": "工具调用未被处理或在处理过程中丢失"
            }
            tool_results.append(tool_result)
    
    # 清理原有历史，确保消息顺序正确
    # 1. 找到最后一个assistant消息索引
    assistant_idx = -1
    for i, msg in enumerate(main_window.assist_conversation_history):
        if msg is assistant_message_with_tool_calls:
            assistant_idx = i
            break
    
    if assistant_idx >= 0:
        # 2. 移除该消息之后的所有消息（可能是之前的工具结果）
        main_window.assist_conversation_history = main_window.assist_conversation_history[:assistant_idx+1]
        
        # 3. 添加所有工具结果
        main_window.assist_conversation_history.extend(tool_results)
    
    # 发送更新后的历史回AI获取最终答案
    set_assistant_thinking(main_window, True)
    
    # 确保之前的助手线程已完成
    if hasattr(main_window, 'assist_thread') and main_window.assist_thread.isRunning():
        logging.warning("Assistant thread still running when sending tool results. Aborting.")
        set_assistant_thinking(main_window, False)
        main_window.show_status("AI助手繁忙，请稍后", "orange")
        # 也重置工具管理器，避免状态混乱
        if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
            main_window.tool_manager.reset()
        return
    
    # 简单地按消息数量裁剪历史
    max_hist_msgs = 10
    if len(main_window.assist_conversation_history) > max_hist_msgs:
        logging.info(f"Trimming history before sending tool results back to AI.")
        history_to_send = main_window.assist_conversation_history[-max_hist_msgs:]
    else:
        history_to_send = main_window.assist_conversation_history.copy()
    
    # 验证消息序列的有效性
    history_to_send, had_invalid = validate_conversation_history(history_to_send)
    if had_invalid:
        logging.warning("发送工具结果前移除了无效的消息")
    
    # 调试日志 - 输出发送的消息序列用于诊断
    logging.debug("发送给AI的消息序列:")
    for i, msg in enumerate(history_to_send):
        role = msg.get("role", "unknown")
        has_tool_calls = "tool_calls" in msg
        tool_call_id = msg.get("tool_call_id", "none")
        tool_name = msg.get("name", "none")
        logging.debug(f"  {i}: role={role}, has_tool_calls={has_tool_calls}, tool_call_id={tool_call_id}, name={tool_name}")
    
    main_window.assist_thread = AssistantThread(
        history_to_send,
        main_window.assist_tools_payload, # 重新发送工具定义
        parallel_tool_calls=False  # Disable parallel tool calls
    )
    main_window.assist_thread.assistant_response.connect(
        lambda response_obj: handle_final_assistant_response(main_window, response_obj)
    )
    main_window.assist_thread.error_occurred.connect(
        lambda error_msg: handle_assistant_error(main_window, error_msg)
    )
    main_window.assist_thread.finished.connect(
        lambda: logging.debug("AssistantThread (after all tools) finished.")
    )
    main_window.assist_thread.start()

# 添加查看工具依赖关系的函数
def view_tool_dependencies(main_window):
    """显示工具依赖关系可视化界面"""
    if hasattr(main_window, 'tool_manager') and main_window.tool_manager:
        show_tool_dependency_view(main_window.tool_manager, main_window)
    else:
        logging.warning("工具管理器不可用，无法显示依赖关系")
        main_window.show_status("工具管理器不可用", "orange")

def verify_and_fix_conversation_history(conversation_history):
    """
    验证对话历史是否符合OpenAI API的要求，确保每个tool_call_id都有对应的tool响应
    
    Args:
        conversation_history: 对话历史列表
        
    Returns:
        tuple: (修复后的历史记录, 是否进行了修复)
    """
    if not conversation_history:
        return conversation_history, False
    
    fixed_history = []
    was_fixed = False
    pending_tool_calls = {}  # 跟踪未回复的tool_call_id
    
    # 遍历历史记录
    for msg in conversation_history:
        role = msg.get("role")
        
        # 检查assistant消息中的tool_calls
        if role == "assistant" and "tool_calls" in msg:
            # 记录所有tool_call_id
            for tc in msg.get("tool_calls", []):
                tc_id = tc.get("id")
                function_info = tc.get("function", {})
                tool_name = function_info.get("name", "unknown")
                if tc_id:
                    pending_tool_calls[tc_id] = tool_name
        
        # 检查tool响应
        elif role == "tool" and "tool_call_id" in msg:
            tc_id = msg.get("tool_call_id")
            if tc_id in pending_tool_calls:
                # 找到了对应的响应，从待处理列表中移除
                del pending_tool_calls[tc_id]
        
        # 添加消息到修复历史
        fixed_history.append(msg)
    
    # 检查是否有未回复的tool_call_id
    if pending_tool_calls:
        was_fixed = True
        logging.warning(f"发现{len(pending_tool_calls)}个未回复的tool_call_id，为它们添加占位响应")
        
        for tc_id, tool_name in pending_tool_calls.items():
            # 为每个未回复的tool_call_id添加一个自动响应
            auto_response = {
                "role": "tool",
                "tool_call_id": tc_id,
                "name": tool_name,
                "content": "用户跳过了此工具调用。请继续与用户对话，不要再次调用相同的工具。"
            }
            fixed_history.append(auto_response)
            logging.info(f"为未回复的工具调用 {tc_id} ({tool_name}) 添加了自动响应")
    
    return fixed_history, was_fixed