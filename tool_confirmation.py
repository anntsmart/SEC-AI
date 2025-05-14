import logging
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QMessageBox, QTextEdit)
from PyQt5.QtCore import Qt

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ToolConfirmationDialog(QDialog):
    """工具操作确认对话框"""
    
    def __init__(self, parent=None, title="操作确认", message="请确认是否执行此操作？", details=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(500, 300)
        self.setModal(True)
        self.result_confirmed = False
        
        # 主布局
        layout = QVBoxLayout(self)
        
        # 消息标签
        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_label.setStyleSheet("font-size: 12pt; margin: 10px 0;")
        layout.addWidget(message_label)
        
        # 详情区域（如果提供）
        if details:
            # 详情标签
            details_label = QLabel("操作详情:")
            details_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
            layout.addWidget(details_label)
            
            # 详情文本框
            details_text = QTextEdit()
            details_text.setReadOnly(True)
            details_text.setText(details)
            details_text.setStyleSheet("background-color: #f8f8f8; padding: 5px; border: 1px solid #ddd;")
            layout.addWidget(details_text)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        # 确认按钮
        self.confirm_button = QPushButton("确认执行")
        self.confirm_button.setStyleSheet("""
            QPushButton {
                background-color: #007acc;
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #005999;
            }
        """)
        self.confirm_button.clicked.connect(self.accept_confirmation)
        
        # 取消按钮
        self.cancel_button = QPushButton("取消操作")
        self.cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #d9534f;
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #c9302c;
            }
        """)
        self.cancel_button.clicked.connect(self.reject_confirmation)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.confirm_button)
        
        layout.addLayout(button_layout)
    
    def accept_confirmation(self):
        """用户确认操作"""
        self.result_confirmed = True
        self.accept()
    
    def reject_confirmation(self):
        """用户拒绝操作"""
        self.result_confirmed = False
        self.reject()

def confirm_tool_execution(parent=None, tool_name=None, tool_args=None) -> bool:
    """
    显示工具执行确认对话框
    
    Args:
        parent: 父窗口
        tool_name: 工具名称
        tool_args: 工具参数字典
    
    Returns:
        bool: 用户是否确认执行
    """
    if not tool_name:
        return False
    
    # 特殊处理各种工具的确认信息
    if tool_name == "send_feishu_message":
        title = "确认发送飞书消息"
        user_id = tool_args.get("user_id", "未指定")
        message = tool_args.get("message", "")
        confirm_message = f"AI助手请求发送飞书消息到用户 {user_id}"
        details = f"接收用户: {user_id}\n\n消息内容:\n{message}"
    elif tool_name == "run_terminal_cmd" or tool_name == "run_terminal_powershell":
        title = f"确认执行{'PowerShell' if tool_name == 'run_terminal_powershell' else '终端'}命令"
        command = tool_args.get("command", "未指定")
        is_background = tool_args.get("is_background", False)
        explanation = tool_args.get("explanation", "")
        require_approval = tool_args.get("require_user_approval", True)
        
        # 如果工具设置不需要用户确认但我们的安全策略要求确认
        if not require_approval:
            confirm_message = f"⚠️ 警告: AI助手请求无需确认执行{'PowerShell' if tool_name == 'run_terminal_powershell' else '终端'}命令"
        else:
            confirm_message = f"AI助手请求执行{'PowerShell' if tool_name == 'run_terminal_powershell' else '终端'}命令"
            
        if explanation:
            confirm_message += f"\n\n目的: {explanation}"
            
        execution_mode = "后台" if is_background else "前台"
        details = f"命令内容: {command}\n执行模式: {execution_mode}"
        
        # 添加警告信息
        details += "\n\n⚠️ 安全提示: 请仔细检查命令内容，确认不会对系统造成不良影响"
    else:
        # 通用确认信息
        title = f"确认执行工具 {tool_name}"
        confirm_message = f"AI助手请求执行工具 {tool_name}"
        details = "参数:\n" + "\n".join([f"{k}: {v}" for k, v in tool_args.items()]) if tool_args else None
    
    # 创建并显示确认对话框
    dialog = ToolConfirmationDialog(
        parent=parent,
        title=title,
        message=confirm_message,
        details=details
    )
    
    # 执行对话框并返回用户选择
    dialog.exec_()
    return dialog.result_confirmed

# 测试函数
if __name__ == "__main__":
    from PyQt5.QtWidgets import QApplication
    import sys
    
    app = QApplication(sys.argv)
    
    # 测试数据
    test_args = {
        "user_id": "zhangsan",
        "message": "这是一条测试消息，需要用户确认后才能发送。\n这是第二行内容。"
    }
    
    result = confirm_tool_execution(
        tool_name="send_feishu_message",
        tool_args=test_args
    )
    
    print(f"用户{'确认' if result else '拒绝'}了操作") 