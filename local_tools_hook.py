import sys
import os
import logging
import importlib
import importlib.util

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('local_tools_hook')

# 尝试导入duckduckgo补丁
try:
    from duckduckgo_patch import patch_duckduckgo_search
    logger.info("成功导入duckduckgo补丁模块")
except ImportError:
    logger.warning("无法直接导入duckduckgo补丁模块，尝试从文件加载")
    
    # 定义一个加载脚本文件的函数
    def load_script_from_file(file_path):
        """从文件路径加载Python脚本"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
            # 创建一个局部命名空间
            script_namespace = {}
            # 执行脚本内容
            exec(script_content, script_namespace)
            return script_namespace
        except Exception as e:
            logger.error(f"加载脚本 {file_path} 失败: {e}", exc_info=True)
            return None
    
    # 在多个可能的位置查找duckduckgo_patch.py
    app_path = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd()
    patch_locations = [
        os.path.join(app_path, 'duckduckgo_patch.py'),
        os.path.join(os.path.dirname(app_path), 'duckduckgo_patch.py'),
        os.path.join(app_path, 'backup', 'duckduckgo_patch.py')
    ]
    
    # 尝试加载补丁脚本
    patch_namespace = None
    for loc in patch_locations:
        if os.path.exists(loc):
            logger.info(f"找到duckduckgo补丁脚本: {loc}")
            patch_namespace = load_script_from_file(loc)
            if patch_namespace and 'patch_duckduckgo_search' in patch_namespace:
                logger.info("成功从文件加载duckduckgo补丁")
                patch_duckduckgo_search = patch_namespace['patch_duckduckgo_search']
                break
    
    if patch_namespace is None:
        logger.warning("无法找到duckduckgo补丁脚本，将创建简单补丁函数")
        
        # 如果找不到补丁文件，创建一个简单的补丁函数
        def patch_duckduckgo_search():
            """简单的替代补丁函数"""
            try:
                # 尝试创建最基本的模块架构
                if 'duckduckgo_search' not in sys.modules:
                    import types
                    logger.info("创建基本的duckduckgo_search模块结构")
                    
                    # 创建主模块
                    duckduckgo_module = types.ModuleType('duckduckgo_search')
                    sys.modules['duckduckgo_search'] = duckduckgo_module
                    
                    # 创建libs子模块
                    libs_module = types.ModuleType('duckduckgo_search.libs')
                    sys.modules['duckduckgo_search.libs'] = libs_module
                    duckduckgo_module.libs = libs_module
                    
                    # 创建缺失的mypyc模块
                    utils_module = types.ModuleType('duckduckgo_search.libs.utils_chat__mypyc')
                    sys.modules['duckduckgo_search.libs.utils_chat__mypyc'] = utils_module
                    libs_module.utils_chat__mypyc = utils_module
                    
                    # 添加简单的函数
                    def simple_headers(headers=None):
                        return headers or {}
                    
                    utils_module.session_headers = simple_headers
                    utils_module.chat_headers = simple_headers
                    
                    logger.info("已创建基本的模块结构")
                    return True
                return False
            except Exception as e:
                logger.error(f"创建简单补丁时出错: {e}")
                return False

def fix_duckduckgo_search():
    """
    修复duckduckgo_search导入问题
    """
    # 首先应用专门的补丁
    logger.info("尝试应用duckduckgo_search补丁...")
    patch_result = patch_duckduckgo_search()
    if patch_result:
        logger.info("duckduckgo_search补丁应用成功")
    else:
        logger.warning("duckduckgo_search补丁应用失败，尝试使用备用方法")
    
    try:
        # 无论补丁是否成功，都尝试导入，看是否能正常工作
        import duckduckgo_search
        logger.info("成功导入duckduckgo_search库")
        return True
    except ImportError as e:
        logger.error(f"导入duckduckgo_search时出错: {e}")
        
        # 尝试重定向导入到可能的替代路径
        try:
            app_path = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd()
            
            # 尝试找到库的可能位置
            search_paths = [
                os.path.join(app_path, 'duckduckgo_search'),
                os.path.join(app_path, 'lib', 'duckduckgo_search'),
                os.path.join(app_path, 'lib', 'site-packages', 'duckduckgo_search'),
            ]
            
            # 在_MEI临时目录中搜索
            for path in sys.path:
                if '_MEI' in path and os.path.exists(path):
                    search_paths.append(os.path.join(path, 'duckduckgo_search'))
            
            # 尝试各种可能的路径
            for search_path in search_paths:
                if os.path.exists(search_path) and os.path.isdir(search_path):
                    logger.info(f"找到可能的duckduckgo_search库位置: {search_path}")
                    
                    # 添加到sys.path
                    if search_path not in sys.path:
                        sys.path.insert(0, os.path.dirname(search_path))
                        logger.info(f"已添加 {os.path.dirname(search_path)} 到sys.path")
                    
                    # 尝试再次导入
                    try:
                        import duckduckgo_search
                        logger.info("成功导入duckduckgo_search库")
                        return True
                    except ImportError as e2:
                        logger.error(f"尝试从 {search_path} 导入duckduckgo_search失败: {e2}")
            
            logger.warning("无法找到有效的duckduckgo_search库位置")
            return False
        except Exception as e:
            logger.error(f"修复duckduckgo_search时出错: {e}", exc_info=True)
            return False

def patch_local_tools():
    """
    尝试修补local_tools导入问题
    """
    # 首先尝试修复duckduckgo_search
    fix_duckduckgo_search()
    
    try:
        # 第一步：检查local_tools是否已经导入成功
        import local_tools
        if hasattr(local_tools, 'AVAILABLE_TOOLS') and hasattr(local_tools, 'execute_tool'):
            logger.info("local_tools模块已正确加载")
            return True
    except ImportError:
        logger.error("无法直接导入local_tools模块，尝试修复...")
    
    # 获取应用程序根目录
    app_path = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd()
    logger.info(f"应用程序路径: {app_path}")
    
    # 同时搜索上一级目录
    parent_dir = os.path.dirname(app_path)
    
    # 尝试在多个位置搜索local_tools.py
    search_locations = [
        app_path,
        parent_dir,
        os.path.join(app_path, 'backup'),
        os.path.join(app_path, 'modules')
    ]
    
    # 在_MEI临时目录中也搜索
    for path in sys.path:
        if '_MEI' in path and os.path.exists(path):
            search_locations.append(path)
    
    local_tools_path = None
    for location in search_locations:
        path = os.path.join(location, 'local_tools.py')
        if os.path.exists(path):
            local_tools_path = path
            logger.info(f"在 {location} 中找到local_tools.py")
            break
            
    if not local_tools_path:
        logger.error(f"在所有搜索位置中均未找到local_tools.py文件")
        return False
    
    try:
        logger.info(f"尝试从路径加载local_tools模块: {local_tools_path}")
        spec = importlib.util.spec_from_file_location("local_tools", local_tools_path)
        local_tools_module = importlib.util.module_from_spec(spec)
        sys.modules["local_tools"] = local_tools_module
        spec.loader.exec_module(local_tools_module)
        
        # 检查模块是否包含必要的属性
        if hasattr(local_tools_module, 'AVAILABLE_TOOLS') and hasattr(local_tools_module, 'execute_tool'):
            logger.info("成功加载local_tools模块及其功能")
            
            # 尝试加载其他工具相关的模块
            try:
                # 加载其他工具模块
                tool_modules = {
                    'decode_tools': 'decode_tools.py',
                    'tool_confirmation': 'tool_confirmation.py',
                    'tools_manager': 'tools_manager.py', 
                    'feishu_send_message': 'feishu_send_message.py',
                    'local_tools_decode': 'local_tools_decode.py'
                }
                
                for module_name, file_name in tool_modules.items():
                    # 在各个可能的位置搜索模块
                    module_path = None
                    for location in search_locations:
                        path = os.path.join(location, file_name)
                        if os.path.exists(path):
                            module_path = path
                            break
                    
                    if module_path:
                        logger.info(f"找到 {module_name} 模块: {module_path}")
                        spec = importlib.util.spec_from_file_location(module_name, module_path)
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[module_name] = module
                        spec.loader.exec_module(module)
                        logger.info(f"成功加载 {module_name} 模块")
                    else:
                        logger.warning(f"未找到 {module_name} 模块文件")
                
            except Exception as e:
                logger.error(f"加载附加工具模块时出错: {str(e)}", exc_info=True)
            
            return True
        else:
            logger.error("local_tools模块缺少AVAILABLE_TOOLS或execute_tool")
            return False
    except Exception as e:
        logger.error(f"加载local_tools模块时出错: {str(e)}", exc_info=True)
        return False

if __name__ == "__main__":
    # 可以直接执行此脚本进行测试
    success = patch_local_tools()
    logger.info(f"修补工具模块{'成功' if success else '失败'}")
    
    # 测试导入是否成功
    if success:
        try:
            import local_tools
            logger.info(f"可用工具: {', '.join(local_tools.AVAILABLE_TOOLS.keys())}")
        except Exception as e:
            logger.error(f"导入工具后测试失败: {str(e)}", exc_info=True) 