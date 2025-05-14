#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
打包前准备脚本 - 清理敏感信息并准备打包环境
"""

import os
import sys
import shutil
import subprocess
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """主函数"""
    logger.info("开始打包前准备工作...")
    
    # 当前工作目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)
    
    # 1. 备份当前config.py (如果存在)
    if os.path.exists('config.py'):
        logger.info("备份当前config.py文件...")
        backup_dir = os.path.join(current_dir, 'backup')
        os.makedirs(backup_dir, exist_ok=True)
        shutil.copy2('config.py', os.path.join(backup_dir, 'config.py.bak'))
    
    # 2. 使用config.py.default创建干净的config.py
    if os.path.exists('config.py.default'):
        logger.info("使用config.py.default创建干净的config.py...")
        with open('config.py.default', 'r', encoding='utf-8') as f:
            default_content = f.read()
        
        # 写入config.py
        with open('config.py', 'w', encoding='utf-8') as f:
            f.write(default_content)
    else:
        logger.error("找不到config.py.default文件！无法创建干净的配置。")
        return False
    
    # 3. 确认config.py不含敏感信息
    with open('config.py', 'r', encoding='utf-8') as f:
        config_content = f.read()
    
    # 检查API密钥是否为空
    api_keys = [
        'DEEPSEEK_API_KEY=""', 
        'AZURE_API_KEY=""', 
        'QWEN_API_KEY=""', 
        'GEMINI_API_KEY=""'
    ]
    
    for key in api_keys:
        if key not in config_content:
            logger.warning(f"配置文件中的{key.split('=')[0]}不为空，可能包含敏感信息！")
            return False
    
    logger.info("配置文件检查通过，不包含敏感API密钥。")
    
    # 4. 执行PyInstaller打包
    logger.info("开始执行PyInstaller打包...")
    try:
        subprocess.run(['pyinstaller', 'sec-ai.spec'], check=True)
        logger.info("PyInstaller打包成功完成!")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"PyInstaller打包失败: {e}")
        return False
    except FileNotFoundError:
        logger.error("找不到PyInstaller。请确保已安装: pip install pyinstaller")
        return False
    finally:
        # 5. 恢复备份的config.py (可选，取决于你的需求)
        backup_file = os.path.join(backup_dir, 'config.py.bak')
        if os.path.exists(backup_file):
            logger.info("恢复之前备份的config.py...")
            shutil.copy2(backup_file, 'config.py')

if __name__ == "__main__":
    success = main()
    if success:
        logger.info("打包前准备工作和打包过程全部完成!")
        sys.exit(0)
    else:
        logger.error("打包准备工作或打包过程失败!")
        sys.exit(1) 