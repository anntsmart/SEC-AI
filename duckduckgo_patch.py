"""
补丁文件，用于修复 duckduckgo_search 库中缺失的 mypyc 模块问题
"""
import sys
import os
import importlib
import logging
import types

logger = logging.getLogger('duckduckgo_patch')

def patch_duckduckgo_search():
    """
    创建缺失的 duckduckgo_search.libs.utils_chat__mypyc 模块
    """
    try:
        # 首先检查是否已经可以导入
        try:
            import duckduckgo_search
            logger.info("duckduckgo_search 已经可以正常导入")
            # 检查更深层次的模块是否存在问题
            try:
                from duckduckgo_search.libs import utils_chat__mypyc
                logger.info("utils_chat__mypyc 模块也可以正常导入")
                return True
            except ImportError:
                logger.warning("utils_chat__mypyc 模块导入失败，尝试修复")
        except ImportError as e:
            logger.warning(f"导入 duckduckgo_search 失败: {e}")

        # 创建缺失的模块架构
        # 1. 检查是否已经有 duckduckgo_search 模块
        if 'duckduckgo_search' not in sys.modules:
            logger.info("创建 duckduckgo_search 模块")
            duckduckgo_search_module = types.ModuleType('duckduckgo_search')
            sys.modules['duckduckgo_search'] = duckduckgo_search_module
        else:
            duckduckgo_search_module = sys.modules['duckduckgo_search']
            
        # 2. 确保有 libs 子模块
        if not hasattr(duckduckgo_search_module, 'libs'):
            logger.info("创建 duckduckgo_search.libs 子模块")
            libs_module = types.ModuleType('duckduckgo_search.libs')
            sys.modules['duckduckgo_search.libs'] = libs_module
            duckduckgo_search_module.libs = libs_module
        
        # 3. 创建 utils_chat__mypyc 模块
        logger.info("创建 utils_chat__mypyc 模块")
        utils_chat_module = types.ModuleType('duckduckgo_search.libs.utils_chat__mypyc')
        sys.modules['duckduckgo_search.libs.utils_chat__mypyc'] = utils_chat_module
        sys.modules['duckduckgo_search.libs'].utils_chat__mypyc = utils_chat_module
        
        # 4. 为模块添加必要的函数和变量
        # 这些函数是模拟的，根据实际情况可能需要调整
        def session_headers(headers=None):
            headers = headers or {}
            default_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
            for key, value in default_headers.items():
                headers.setdefault(key, value)
            return headers
            
        def chat_headers(headers=None):
            headers = headers or {}
            default_headers = session_headers(headers)
            default_headers.update({
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': 'https://duckduckgo.com/',
                'Content-Type': 'application/x-www-form-urlencoded',
            })
            return default_headers

        # 将模拟函数添加到模块
        utils_chat_module.session_headers = session_headers
        utils_chat_module.chat_headers = chat_headers
        
        logger.info("已成功创建并注入 duckduckgo_search.libs.utils_chat__mypyc 模块")
        
        # 尝试导入，验证修复是否成功
        try:
            from duckduckgo_search.libs import utils_chat__mypyc
            logger.info("验证: utils_chat__mypyc 模块已可正常导入")
            return True
        except ImportError as e:
            logger.error(f"修复失败，仍然无法导入 utils_chat__mypyc: {e}")
            return False
        
    except Exception as e:
        logger.error(f"修复 duckduckgo_search 时出错: {e}", exc_info=True)
        return False

# 可以直接运行此脚本进行测试
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, 
                       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    success = patch_duckduckgo_search()
    logger.info(f"补丁应用{'成功' if success else '失败'}") 