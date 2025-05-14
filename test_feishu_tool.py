import sys
import logging
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit
from PyQt5.QtCore import Qt

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 导入工具管理器
try:
    from tools_manager import ToolManager
    tools_manager_available = True
except ImportError:
    logging.error("tools_manager.py not found")
    tools_manager_available = False

# 导入本地工具
try:
    import local_tools
    local_tools_available = True
except ImportError:
    logging.error("local_tools.py not found")
    local_tools_available = False

class TestWindow(QWidget):
    """测试窗口"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("飞书消息工具测试")
        self.resize(600, 400)
        self.setup_ui()
        
        # 初始化工具管理器
        if tools_manager_available and local_tools_available:
            self.tool_manager = ToolManager(local_tools.execute_tool)
            self.tool_manager.setParent(self)  # 设置父对象，用于对话框
            self.tool_manager.tool_completed.connect(self.handle_tool_completed)
            self.tool_manager.tool_failed.connect(self.handle_tool_failed)
            
            # 加载工具依赖配置
            self.tool_manager.load_dependencies("tools_dependencies.json")
            
            self.status_label.setText("工具管理器初始化成功")
        else:
            self.tool_manager = None
            self.status_label.setText("工具管理器初始化失败")
            self.test_button.setEnabled(False)
        
    def setup_ui(self):
        """设置UI"""
        layout = QVBoxLayout(self)
        
        # 标题
        title = QLabel("飞书消息发送测试")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 18pt; font-weight: bold; margin: 10px 0;")
        layout.addWidget(title)
        
        # 状态标签
        self.status_label = QLabel("准备就绪")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # 测试按钮
        self.test_button = QPushButton("测试飞书消息发送")
        self.test_button.setMinimumHeight(40)
        self.test_button.clicked.connect(self.test_feishu_message)
        layout.addWidget(self.test_button)
        
        # 结果显示
        result_label = QLabel("执行结果:")
        layout.addWidget(result_label)
        
        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)
        layout.addWidget(self.result_display)
    
    def test_feishu_message(self):
        """测试飞书消息发送"""
        if not self.tool_manager:
            self.add_result("错误: 工具管理器不可用")
            return
        
        # 准备测试数据
        test_user = "test_user"  # 使用示例用户ID，实际使用时请更改为有效的用户ID
        test_message = "这是一条来自安全AI助手的测试消息，请忽略。\n发送时间: " + \
                      __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 显示将要发送的消息
        self.add_result(f"准备发送消息到用户: {test_user}")
        self.add_result(f"消息内容: {test_message}")
        
        # 通过工具管理器执行
        success, result = self.tool_manager.execute_single_tool(
            "send_feishu_message", 
            {"user_id": test_user, "message": test_message}
        )
        
        if success:
            self.status_label.setText("消息发送成功")
            self.add_result(f"成功: {result}")
        else:
            self.status_label.setText("消息发送失败")
            self.add_result(f"失败: {result}")
    
    def handle_tool_completed(self, tool_call_id, tool_name, result):
        """处理工具完成回调"""
        self.add_result(f"工具 {tool_name} (ID: {tool_call_id}) 执行完成")
        self.add_result(f"结果: {result}")
    
    def handle_tool_failed(self, tool_call_id, tool_name, error):
        """处理工具失败回调"""
        self.add_result(f"工具 {tool_name} (ID: {tool_call_id}) 执行失败")
        self.add_result(f"错误: {error}")
    
    def add_result(self, text):
        """添加结果到显示区域"""
        self.result_display.append(text)
        self.result_display.append("")  # 空行
        # 滚动到底部
        scrollbar = self.result_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TestWindow()
    window.show()
    sys.exit(app.exec_()) 