import logging
import time
import json
from typing import Dict, List, Any, Callable, Optional, Set, Tuple
from enum import Enum
from PyQt5.QtCore import QObject, pyqtSignal, QTimer

# 尝试导入工具确认模块
try:
    from tool_confirmation import confirm_tool_execution
    confirmation_available = True
except ImportError:
    logging.error("tool_confirmation.py module not found. Tool confirmation will be unavailable.")
    confirmation_available = False
    # 创建一个假的确认函数
    def confirm_tool_execution(parent=None, tool_name=None, tool_args=None) -> bool:
        logging.warning(f"工具确认功能不可用，自动确认执行工具 {tool_name}")
        return True

# 尝试导入local_tools模块
try:
    import local_tools
    local_tools_available = True
except ImportError:
    logging.error("local_tools.py module not found. Local tools will be unavailable.")
    local_tools_available = False

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 需要用户确认的工具列表
TOOLS_REQUIRING_CONFIRMATION = [
    "send_feishu_message",  # 飞书消息发送工具
    "run_terminal_cmd",     # 终端命令执行工具
    "run_terminal_powershell",  # PowerShell命令执行工具
    # 可以添加其他需要确认的工具
]

# 如果local_tools可用，将其中需要确认的工具添加到TOOLS_REQUIRING_CONFIRMATION
if local_tools_available:
    # 添加可能需要确认的工具
    dangerous_tools = ["run_terminal_cmd", "run_terminal_powershell", "edit_file", "delete_file"]
    for tool_name in dangerous_tools:
        if tool_name in local_tools.AVAILABLE_TOOLS and tool_name not in TOOLS_REQUIRING_CONFIRMATION:
            TOOLS_REQUIRING_CONFIRMATION.append(tool_name)
    logger.info(f"从local_tools中加载了需要确认的工具: {TOOLS_REQUIRING_CONFIRMATION}")

class ToolStatus(Enum):
    """工具执行状态枚举"""
    PENDING = "pending"       # 等待执行
    WAITING = "waiting"       # 等待依赖完成
    RUNNING = "running"       # 正在执行
    COMPLETED = "completed"   # 执行完成
    FAILED = "failed"         # 执行失败
    RETRYING = "retrying"     # 正在重试
    REJECTED = "rejected"     # 用户拒绝执行

class ToolTask:
    """工具调用任务"""
    def __init__(self, 
                 tool_call_id: str, 
                 tool_name: str, 
                 tool_args: Dict[str, Any],
                 dependencies: List[str] = None,
                 max_retries: int = 2,
                 retry_delay: int = 3000):  # 延迟时间，单位毫秒
        self.tool_call_id = tool_call_id
        self.tool_name = tool_name
        self.tool_args = tool_args
        self.dependencies = dependencies or []
        self.status = ToolStatus.PENDING
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.retry_count = 0
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.dependent_tasks: Set[str] = set()  # 依赖于该任务的其他任务
        self.execution_time: Optional[float] = None
        
    def add_dependent(self, tool_call_id: str):
        """添加依赖于此任务的其他任务"""
        self.dependent_tasks.add(tool_call_id)
        
    def can_execute(self, completed_tasks: Set[str]) -> bool:
        """检查是否可以执行此任务"""
        if self.status != ToolStatus.PENDING and self.status != ToolStatus.WAITING:
            return False
            
        # 检查所有依赖是否已完成
        for dep in self.dependencies:
            if dep not in completed_tasks:
                self.status = ToolStatus.WAITING
                return False
                
        return True
        
    def mark_running(self):
        """标记任务为正在执行"""
        self.status = ToolStatus.RUNNING
        self.execution_time = time.time()
        
    def mark_completed(self, result: str):
        """标记任务为已完成"""
        self.status = ToolStatus.COMPLETED
        self.result = result
        self.execution_time = time.time() - (self.execution_time or time.time())
        
    def mark_failed(self, error: str):
        """标记任务为失败"""
        if self.retry_count < self.max_retries:
            self.status = ToolStatus.RETRYING
            self.retry_count += 1
            self.error = error
            logger.info(f"任务 {self.tool_name} (ID: {self.tool_call_id}) 失败, 将尝试第 {self.retry_count} 次重试")
        else:
            self.status = ToolStatus.FAILED
            self.error = error
            logger.error(f"任务 {self.tool_name} (ID: {self.tool_call_id}) 失败, 已达到最大重试次数: {error}")
            
    def should_retry(self) -> bool:
        """检查是否应该重试"""
        return self.status == ToolStatus.RETRYING
            
    def reset_for_retry(self):
        """重置任务状态以进行重试"""
        self.status = ToolStatus.PENDING
        self.execution_time = None

class ToolManager(QObject):
    """工具调用管理器，管理工具间依赖关系和执行流程"""
    # 信号定义
    tool_started = pyqtSignal(str, str, dict)  # tool_call_id, tool_name, args
    tool_completed = pyqtSignal(str, str, str)  # tool_call_id, tool_name, result
    tool_failed = pyqtSignal(str, str, str)  # tool_call_id, tool_name, error
    all_tasks_completed = pyqtSignal()  # 所有任务完成信号
    
    def __init__(self, execute_tool_func: Callable[[str, Dict[str, Any]], str] = None, sequential_execution: bool = False):
        """
        初始化工具管理器
        
        Args:
            execute_tool_func: 实际执行工具的函数，接收工具名和参数，返回结果字符串
            sequential_execution: 是否按顺序执行工具（禁用并行执行）
        """
        super().__init__()
        
        # 如果未提供execute_tool_func，但local_tools可用，则使用其中的execute_tool
        if execute_tool_func is None and local_tools_available:
            self.execute_tool_func = local_tools.execute_tool
            logger.info("使用local_tools.execute_tool作为默认工具执行函数")
        else:
            self.execute_tool_func = execute_tool_func
            
        self.tasks: Dict[str, ToolTask] = {}  # 所有任务
        self.completed_tasks: Set[str] = set()  # 已完成任务的ID集合
        self.scheduled_retries: Dict[str, QTimer] = {}  # 计划重试的任务
        self.tool_dependencies: Dict[str, List[str]] = {}  # 工具间依赖关系配置
        self.in_progress = False
        self.default_max_retries = 2
        self.default_retry_delay = 3000  # 3秒
        self.sequential_execution = sequential_execution  # 是否按顺序执行工具
        
        # 如果local_tools可用，记录可用工具
        self.available_tools = {}
        if local_tools_available:
            self.available_tools = local_tools.AVAILABLE_TOOLS.copy()
            logger.info(f"从local_tools中加载了{len(self.available_tools)}个工具")
        
    def load_dependencies(self, config_file: str = None):
        """从配置文件加载工具依赖关系"""
        # 默认依赖关系，如果没有配置文件则使用这些
        default_dependencies = {
            # 例如：decode_text可能依赖于web_search_cve
            # "dependent_tool": ["dependency1", "dependency2"]
        }
        
        if config_file:
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.tool_dependencies = json.load(f)
                logger.info(f"从 {config_file} 加载了工具依赖配置")
            except Exception as e:
                logger.error(f"加载工具依赖配置失败: {e}")
                self.tool_dependencies = default_dependencies
        else:
            self.tool_dependencies = default_dependencies
            
    def build_dependency_graph(self, tool_calls: List[Dict[str, Any]]):
        """
        构建工具调用的依赖图
        
        Args:
            tool_calls: AI返回的工具调用列表
        """
        # 清除之前的任务
        self.reset()
        
        # 验证工具调用格式
        if not tool_calls or not isinstance(tool_calls, list):
            logger.error("工具调用列表无效或为空")
            return
        
        # 创建所有任务
        for tool_call in tool_calls:
            # 验证工具调用结构
            if not isinstance(tool_call, dict):
                logger.error(f"无效的工具调用格式: {tool_call}")
                continue
            
            # 检查必要字段
            if "id" not in tool_call:
                logger.error(f"工具调用缺少id字段: {tool_call}")
                continue
            
            function = tool_call.get("function", {})
            if not isinstance(function, dict):
                logger.error(f"工具调用缺少有效的function字段: {tool_call}")
                continue
            
            tool_name = function.get("name", "")
            if not tool_name:
                logger.error(f"工具调用缺少名称: {tool_call}")
                continue
            
            args_str = function.get("arguments", "{}")
            
            try:
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                logger.error(f"无法解析工具参数: {args_str}")
                args = {}
            
            tool_call_id = tool_call.get("id")
            
            # 获取此工具的依赖
            dependencies = self.tool_dependencies.get(tool_name, [])
            
            # 创建任务对象并添加到管理器
            task = ToolTask(
                tool_call_id=tool_call_id,
                tool_name=tool_name,
                tool_args=args,
                dependencies=dependencies,
                max_retries=self.default_max_retries,
                retry_delay=self.default_retry_delay
            )
            
            self.tasks[tool_call_id] = task
            
        # 构建依赖关系
        for task_id, task in self.tasks.items():
            for dep_id in task.dependencies:
                # 检查依赖的任务是否存在
                if dep_id in self.tasks:
                    # 将当前任务添加为依赖任务的依赖者
                    self.tasks[dep_id].add_dependent(task_id)
                else:
                    # 依赖的任务不在当前批次中，视为已完成
                    logger.warning(f"任务 {task_id} 的依赖 {dep_id} 不在当前批次中，将视为已完成")
                    # 从依赖列表中移除
                    task.dependencies.remove(dep_id)
                    
        logger.info(f"构建了包含 {len(self.tasks)} 个任务的依赖图")
        
    def start_execution(self):
        """开始执行任务"""
        if not self.tasks:
            logger.warning("没有任务需要执行")
            self.all_tasks_completed.emit()
            return
            
        self.in_progress = True
        self._process_pending_tasks()
        
    def _process_pending_tasks(self):
        """处理待执行的任务"""
        any_executed = False
        
        for task_id, task in self.tasks.items():
            if task.can_execute(self.completed_tasks):
                any_executed = True
                task.mark_running()
                logger.info(f"开始执行任务 {task.tool_name} (ID: {task.tool_call_id})")
                
                # 通知监听器任务开始
                self.tool_started.emit(task.tool_call_id, task.tool_name, task.tool_args)
                
                # 检查是否需要用户确认
                needs_confirmation = task.tool_name in TOOLS_REQUIRING_CONFIRMATION
                allowed = True
                
                if needs_confirmation and confirmation_available:
                    # 请求用户确认
                    allowed = confirm_tool_execution(None, task.tool_name, task.tool_args)
                    
                if not allowed:
                    # 用户拒绝执行此工具
                    error_msg = "用户拒绝执行此工具"
                    task.status = ToolStatus.REJECTED
                    task.error = error_msg
                    logger.warning(f"任务 {task.tool_name} (ID: {task.tool_call_id}) 被用户拒绝")
                    self.tool_failed.emit(task.tool_call_id, task.tool_name, error_msg)
                    
                    # 不在这里将任务标记为已完成，而是继续处理其他任务
                    continue
                
                # 执行工具
                try:
                    result = self.execute_tool_func(task.tool_name, task.tool_args)
                    task.mark_completed(result)
                    logger.info(f"任务 {task.tool_name} (ID: {task.tool_call_id}) 执行完成")
                    self.completed_tasks.add(task_id)
                    
                    # 通知监听器任务完成
                    self.tool_completed.emit(task.tool_call_id, task.tool_name, result)
                    
                except Exception as e:
                    error_msg = f"执行失败: {str(e)}"
                    task.mark_failed(error_msg)
                    logger.error(f"任务 {task.tool_name} (ID: {task.tool_call_id}) 执行失败: {e}")
                    
                    if task.should_retry():
                        # 调度重试
                        self._schedule_retry(task_id)
                    else:
                        # 通知监听器任务失败
                        self.tool_failed.emit(task.tool_call_id, task.tool_name, error_msg)
                
                # 如果是顺序执行模式，一次只处理一个任务
                if self.sequential_execution:
                    break
        
        if not any_executed and not self._check_all_completed():
            # 没有任务可以执行，但仍有任务待处理，检查是否有待重试的
            has_retrying = any(task.status == ToolStatus.RETRYING for task in self.tasks.values())
            if not has_retrying:
                # 如果没有待重试的任务，可能存在循环依赖
                logger.error("检测到可能的循环依赖，无法继续执行")
                # 将所有等待中的任务标记为失败
                for task_id, task in self.tasks.items():
                    if task.status == ToolStatus.WAITING:
                        task.status = ToolStatus.FAILED
                        task.error = "检测到循环依赖，任务无法执行"
                        self.tool_failed.emit(task.tool_call_id, task.tool_name, task.error)
        
        # 检查是否所有任务都已完成
        if self._check_all_completed():
            logger.info("所有任务执行完成")
            self.in_progress = False
            self.all_tasks_completed.emit()
        
    def _schedule_retry(self, task_id: str):
        """调度任务重试"""
        task = self.tasks.get(task_id)
        if not task:
            return
            
        # 创建定时器
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: self._retry_task(task_id))
        
        # 存储定时器
        self.scheduled_retries[task_id] = timer
        
        # 启动定时器
        timer.start(task.retry_delay)
        logger.info(f"计划在 {task.retry_delay}ms 后重试任务 {task.tool_name} (ID: {task_id})")
        
    def _retry_task(self, task_id: str):
        """重试指定任务"""
        task = self.tasks.get(task_id)
        if not task:
            return
            
        # 移除定时器
        if task_id in self.scheduled_retries:
            self.scheduled_retries.pop(task_id)
            
        logger.info(f"开始重试任务 {task.tool_name} (ID: {task_id})")
        
        # 重置任务状态
        task.reset_for_retry()
        
        # 如果还在执行过程中，重新检查待执行任务
        if self.in_progress:
            self._process_pending_tasks()
            
    def _check_all_completed(self) -> bool:
        """检查是否所有任务都已完成或失败"""
        for task in self.tasks.values():
            # 如果任务还在等待、待处理、执行中或重试中，则未完成
            if task.status in (ToolStatus.PENDING, ToolStatus.WAITING, 
                              ToolStatus.RUNNING, ToolStatus.RETRYING):
                return False
        return True
        
    def reset(self):
        """重置管理器状态"""
        # 取消所有重试定时器
        for timer in self.scheduled_retries.values():
            timer.stop()
            
        self.tasks.clear()
        self.completed_tasks.clear()
        self.scheduled_retries.clear()
        self.in_progress = False
        
    def get_task_statuses(self) -> Dict[str, Dict[str, Any]]:
        """获取所有任务的状态"""
        statuses = {}
        for task_id, task in self.tasks.items():
            statuses[task_id] = {
                "tool_name": task.tool_name,
                "status": task.status.value,
                "retry_count": task.retry_count,
                "dependencies": task.dependencies,
                "dependents": list(task.dependent_tasks),
                "execution_time": task.execution_time
            }
        return statuses

    def execute_single_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> Tuple[bool, str]:
        """
        执行单个工具，不涉及依赖关系
        
        Args:
            tool_name: 工具名称
            tool_args: 工具参数
            
        Returns:
            (成功标志, 结果/错误信息)
        """
        # 检查工具是否存在
        if local_tools_available and tool_name not in self.available_tools:
            logger.error(f"工具 '{tool_name}' 不存在")
            return False, f"错误：未知的工具名称 '{tool_name}'。"
            
        # 检查是否需要用户确认
        needs_confirmation = tool_name in TOOLS_REQUIRING_CONFIRMATION
        
        # 如果需要确认且确认功能可用
        if needs_confirmation and confirmation_available:
            # 获取父窗口对象（如果有）
            parent = self.parent() if hasattr(self, 'parent') else None
            
            # 请求用户确认
            confirmed = confirm_tool_execution(
                parent=parent,
                tool_name=tool_name, 
                tool_args=tool_args
            )
            
            # 如果用户拒绝
            if not confirmed:
                logger.info(f"用户拒绝执行单个工具 '{tool_name}'")
                return False, "用户拒绝执行此操作"
        
        try:
            result = self.execute_tool_func(tool_name, tool_args)
            return True, result
        except Exception as e:
            logger.error(f"执行工具 {tool_name} 失败: {e}")
            return False, str(e)

    def get_available_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有可用工具的信息
        
        Returns:
            Dict[str, Dict[str, Any]]: 工具名称到工具信息的映射
        """
        if local_tools_available:
            return self.available_tools
        return {} 