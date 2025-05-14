import sys
import logging
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                           QLabel, QPushButton, QDialog, QTableWidget, 
                           QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor

class ToolDependencyViewer(QDialog):
    """工具依赖关系可视化对话框"""
    
    STATUS_COLORS = {
        "pending": QColor(200, 200, 200),    # 灰色
        "waiting": QColor(255, 255, 200),    # 浅黄色
        "running": QColor(100, 100, 255),    # 蓝色
        "completed": QColor(100, 255, 100),  # 绿色
        "failed": QColor(255, 100, 100),     # 红色
        "retrying": QColor(255, 165, 0)      # 橙色
    }
    
    def __init__(self, tool_manager, parent=None):
        super().__init__(parent)
        self.tool_manager = tool_manager
        self.setWindowTitle("工具依赖关系查看器")
        self.resize(800, 400)
        self.setup_ui()
        
        # 设置定时器定期更新状态
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_task_status)
        self.update_timer.start(1000)  # 每秒更新一次
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # 标题
        title_label = QLabel("工具调用依赖关系及执行状态")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        layout.addWidget(title_label)
        
        # 工具任务表格
        self.task_table = QTableWidget()
        self.task_table.setColumnCount(6)
        self.task_table.setHorizontalHeaderLabels([
            "任务ID", "工具名称", "状态", "重试次数", "依赖于", "被依赖于"
        ])
        self.task_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.task_table.verticalHeader().setVisible(False)
        layout.addWidget(self.task_table)
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.update_task_status)
        
        self.close_btn = QPushButton("关闭")
        self.close_btn.clicked.connect(self.accept)
        
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)
        
        # 初始加载任务状态
        self.update_task_status()
        
    def update_task_status(self):
        """更新任务状态表格"""
        if not self.tool_manager or not hasattr(self.tool_manager, 'get_task_statuses'):
            return
            
        # 获取最新任务状态
        statuses = self.tool_manager.get_task_statuses()
        
        # 更新表格
        self.task_table.setRowCount(len(statuses))
        
        for row, (task_id, status) in enumerate(statuses.items()):
            # 任务ID
            id_item = QTableWidgetItem(task_id)
            id_item.setFlags(id_item.flags() & ~Qt.ItemIsEditable)
            self.task_table.setItem(row, 0, id_item)
            
            # 工具名称
            name_item = QTableWidgetItem(status.get("tool_name", "未知"))
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
            self.task_table.setItem(row, 1, name_item)
            
            # 状态
            status_str = status.get("status", "unknown")
            status_item = QTableWidgetItem(status_str)
            status_item.setFlags(status_item.flags() & ~Qt.ItemIsEditable)
            # 设置状态对应的背景色
            if status_str in self.STATUS_COLORS:
                status_item.setBackground(self.STATUS_COLORS[status_str])
            self.task_table.setItem(row, 2, status_item)
            
            # 重试次数
            retry_item = QTableWidgetItem(str(status.get("retry_count", 0)))
            retry_item.setFlags(retry_item.flags() & ~Qt.ItemIsEditable)
            self.task_table.setItem(row, 3, retry_item)
            
            # 依赖于
            deps = status.get("dependencies", [])
            deps_str = ", ".join(deps) if deps else "无"
            deps_item = QTableWidgetItem(deps_str)
            deps_item.setFlags(deps_item.flags() & ~Qt.ItemIsEditable)
            self.task_table.setItem(row, 4, deps_item)
            
            # 被依赖于
            dependents = status.get("dependents", [])
            deps_str = ", ".join(dependents) if dependents else "无"
            deps_item = QTableWidgetItem(deps_str)
            deps_item.setFlags(deps_item.flags() & ~Qt.ItemIsEditable)
            self.task_table.setItem(row, 5, deps_item)

def show_tool_dependency_view(tool_manager, parent=None):
    """显示工具依赖关系可视化对话框"""
    dialog = ToolDependencyViewer(tool_manager, parent)
    dialog.exec_()
    
if __name__ == "__main__":
    # 测试代码，仅用于单独运行时
    app = QApplication(sys.argv)
    
    # 创建模拟数据
    class MockToolManager:
        def get_task_statuses(self):
            return {
                "call_1": {
                    "tool_name": "web_search_cve",
                    "status": "completed",
                    "retry_count": 0,
                    "dependencies": [],
                    "dependents": ["call_3"]
                },
                "call_2": {
                    "tool_name": "lookup_internal_ip",
                    "status": "running",
                    "retry_count": 0,
                    "dependencies": [],
                    "dependents": ["call_3"]
                },
                "call_3": {
                    "tool_name": "comprehensive_security_analysis",
                    "status": "waiting",
                    "retry_count": 0,
                    "dependencies": ["call_1", "call_2"],
                    "dependents": []
                }
            }
    
    mock_manager = MockToolManager()
    dialog = ToolDependencyViewer(mock_manager)
    dialog.show()
    
    sys.exit(app.exec_()) 