import os
import sys
import logging

# 设置基本日志记录
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('runtime_hook')

def setup_frozen_environment():
    """为冻结环境设置正确的路径和环境变量"""
    logger.info("正在设置PyInstaller冻结环境")
    
    # 获取应用程序的真实路径（不是temp目录中解压的路径）
    if getattr(sys, 'frozen', False):
        # 我们在打包的应用程序中
        application_path = os.path.dirname(sys.executable)
        logger.info(f"应用程序正在以冻结模式运行，路径: {application_path}")
        
        # 将应用程序路径添加到sys.path的开头，确保首先从这里加载模块
        if application_path not in sys.path:
            sys.path.insert(0, application_path)
            
        # 环境变量中设置应用程序路径，以便子进程可以找到它
        os.environ['APP_PATH'] = application_path
        
        # 还要将tools目录添加到PATH中，如果存在的话
        tools_dir = os.path.join(application_path, 'tools')
        if os.path.exists(tools_dir):
            # 将tools目录添加到PATH环境变量
            if tools_dir not in os.environ['PATH']:
                os.environ['PATH'] = tools_dir + os.pathsep + os.environ['PATH']
            logger.info(f"已将tools目录添加到PATH: {tools_dir}")
    else:
        logger.info("应用程序在非冻结模式下运行")

    # 输出设置好的sys.path以便调试
    logger.info("当前sys.path:")
    for p in sys.path:
        logger.info(f"  {p}")

# 执行环境设置
setup_frozen_environment()

# 尝试加载并运行本地工具钩子脚本
try:
    # 如果运行于冻结环境中，特别处理本地工具
    if getattr(sys, 'frozen', False):
        # 尝试导入工具钩子模块
        try:
            import local_tools_hook
            # 调用修补函数
            success = local_tools_hook.patch_local_tools()
            logger.info(f"local_tools修补{'成功' if success else '失败'}")
        except ImportError:
            logger.error("找不到local_tools_hook模块，尝试从文件加载")
            # 如果模块导入失败，则尝试从文件直接执行
            app_path = os.path.dirname(sys.executable)
            hook_path = os.path.join(app_path, 'local_tools_hook.py')
            if os.path.exists(hook_path):
                logger.info(f"从文件执行工具钩子: {hook_path}")
                try:
                    with open(hook_path, 'r', encoding='utf-8') as f:
                        hook_code = f.read()
                    # 在当前上下文中执行钩子代码
                    exec(hook_code)
                    # 假设钩子代码定义了patch_local_tools函数
                    if 'patch_local_tools' in locals():
                        success = patch_local_tools()
                        logger.info(f"通过exec执行local_tools修补{'成功' if success else '失败'}")
                except Exception as e:
                    logger.error(f"执行工具钩子脚本时出错: {str(e)}", exc_info=True)
            else:
                logger.error(f"找不到工具钩子文件: {hook_path}")
    else:
        logger.info("非冻结模式，跳过工具修补")
except Exception as e:
    logger.error(f"工具钩子处理过程中发生错误: {str(e)}", exc_info=True)

# 特别处理本地工具模块
try:
    # 尝试预加载本地工具模块
    import local_tools
    import tool_confirmation
    import tools_manager
    logger.info("成功预加载工具模块")
except Exception as e:
    logger.error(f"预加载工具模块时出错: {e}")

# 输出环境变量信息，以便调试
logger.info("环境变量PATH:")
logger.info(os.environ.get('PATH', '未设置')) 