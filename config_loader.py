import sys
import os
import importlib.util
import shutil
import logging

# 默认配置内容 (保持与原文件一致)
DEFAULT_CONFIG = """# API配置
API_TYPE="qwen"  # 可选值: "deepseek", "ollama", "azure", "qwen" 或 "gemini"

# DeepSeek API配置
# 官方默认API地址: "https://api.deepseek.com/v1/chat/completions"
# 硅基流动：https://api.siliconflow.cn/v1/chat/completions
DEEPSEEK_API_URL=""  # 请填写您的DeepSeek API URL
DEEPSEEK_API_KEY=""  # 请填写您的DeepSeek API密钥
# DeepSeek模型名称，官方默认模型: "deepseek-chat"
# 硅基流动：deepseek-ai/DeepSeek-V3
DEEPSEEK_MODEL=""  # 请填写您想使用的DeepSeek模型名称

# Azure OpenAI API配置
AZURE_API_URL=""  # 请填写您的Azure OpenAI API端点
AZURE_API_KEY=""  # 请填写您的Azure OpenAI API密钥
AZURE_API_VERSION="2024-10-21"
AZURE_MODEL="gpt-4o"

# 通义千问 API配置
QWEN_API_URL="https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
QWEN_API_KEY=""  # 请填写您的通义千问API密钥
QWEN_MODEL="qwen-plus"

# Ollama API配置
OLLAMA_API_URL="http://localhost:11434/api/chat"  # Ollama API地址
OLLAMA_MODEL="qwen2.5-coder:14b"  # Ollama模型名称

# Google Gemini API配置
GEMINI_API_URL="https://generativelanguage.googleapis.com/v1beta"
GEMINI_API_KEY=""  # 请填写您的Gemini API密钥
GEMINI_MODEL="gemini-2.0-flash"

# 主题配色方案
THEMES = {
    "深色主题": {
        "main_bg": "#1e1e1e",
        "secondary_bg": "#2d2d2d",
        "text_color": "#ffffff",
        "accent_color": "#007acc",
        "border_color": "#404040",
        "button_hover": "#005999",
        "button_pressed": "#004c80"
    },
    "浅色主题": {
        "main_bg": "#f5f5f5",
        "secondary_bg": "#ffffff",
        "text_color": "#333333",
        "accent_color": "#2196f3",
        "border_color": "#e0e0e0",
        "button_hover": "#1976d2",
        "button_pressed": "#1565c0"
    },
    "科技感主题": {
        "main_bg": "#0a192f",
        "secondary_bg": "#172a45",
        "text_color": "#ccd6f6",
        "accent_color": "#64ffda",
        "border_color": "#233554",
        "button_hover": "#52dbbf",
        "button_pressed": "#3ebca6"
    },
    "黑客粉嫩主题": {
        "main_bg": "#FFEDED",
        "secondary_bg": "#FFD9D9",
        "text_color": "#222222",
        "accent_color": "#FF1493",
        "border_color": "#FF9AA2",
        "button_hover": "#FF007F",
        "button_pressed": "#DB7093"
},
    "护眼主题": {
        "main_bg": "#e0f0e0",
        "secondary_bg": "#f0f8f0",
        "text_color": "#333333",
        "accent_color": "#4caf50",
        "border_color": "#c8e6c9",
        "button_hover": "#388e3c",
        "button_pressed": "#2e7d32"
    }
}
"""

def get_config_dir():
    """获取配置文件目录"""
    if getattr(sys, 'frozen', False):  # 判断是否为打包后的环境
        # 如果是打包环境，使用用户文档目录
        if os.name == 'nt':  # Windows系统
            config_dir = os.path.join(os.path.expanduser("~"), "Documents", "安全分析工具-AI版")
        else:  # Linux/Mac系统
            config_dir = os.path.join(os.path.expanduser("~"), ".config", "sec-ai") # Use .config standard
    else:
        # 如果是开发环境，使用当前目录
        config_dir = os.path.dirname(os.path.abspath(__file__))

    # 确保目录存在
    os.makedirs(config_dir, exist_ok=True)
    logging.info(f"Configuration directory: {config_dir}")
    return config_dir

def get_config_path():
    """获取配置文件路径"""
    return os.path.join(get_config_dir(), "config.py")

def load_config():
    """加载配置"""
    config_path = get_config_path()
    logging.info(f"Loading configuration from: {config_path}")

    # 如果配置文件不存在，从资源中复制
    if not os.path.exists(config_path):
        logging.warning(f"Configuration file not found at {config_path}. Creating default.")
        try:
            default_config_content = DEFAULT_CONFIG
            # 检查是否存在config.py.default文件
            default_config_file = None
            
            # 检查当前目录是否有config.py.default
            if os.path.exists("config.py.default"):
                default_config_file = "config.py.default"
                logging.info(f"Found config.py.default in current directory")
            
            # 如果运行在打包环境中，检查打包路径中是否有config.py.default
            elif getattr(sys, 'frozen', False):
                bundle_dir = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(sys.executable)))
                bundled_config_path = os.path.join(bundle_dir, "config.py.default")
                if os.path.exists(bundled_config_path):
                    default_config_file = bundled_config_path
                    logging.info(f"Found config.py.default in bundle: {bundled_config_path}")
            
            # 如果找到了config.py.default，则从中读取内容作为默认配置
            if default_config_file:
                with open(default_config_file, 'r', encoding='utf-8') as f:
                    default_config_content = f.read()
                    logging.info(f"Using content from {default_config_file} as default configuration")
            
            # 使用读取到的内容创建config.py
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(default_config_content)
            logging.info(f"Created new configuration file at {config_path}")
                
        except Exception as e:
            logging.error(f"Failed to create configuration file: {e}", exc_info=True)
            # Fallback to writing default content anyway
            try:
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.write(DEFAULT_CONFIG)
            except Exception as e_write:
                 logging.error(f"FATAL: Could not even write default config: {e_write}", exc_info=True)
                 # In a real app, you might want to raise this or show an error dialog
                 # For simplicity here, we'll try to proceed with a dummy config object

    # Dynamically import the configuration
    try:
        spec = importlib.util.spec_from_file_location("config", config_path)
        if spec is None:
            raise ImportError(f"Could not create spec for config file: {config_path}")
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        logging.info("Configuration loaded successfully.")
        return config
    except Exception as e:
        logging.error(f"Failed to load configuration from {config_path}: {e}", exc_info=True)
        # Return a default config object or raise an error
        # For robustness, let's try creating a dummy config from the default string
        try:
            from types import ModuleType
            config = ModuleType("config")
            exec(DEFAULT_CONFIG, config.__dict__)
            logging.warning("Loaded default configuration due to loading error.")
            return config
        except Exception as e_fallback:
             logging.error(f"FATAL: Could not load fallback default config: {e_fallback}", exc_info=True)
             # Critical error, maybe raise or exit
             raise RuntimeError("Could not load any configuration.") from e


def update_config_value(content, key, value):
    """Helper function to update a value in the config file content string."""
    import re
    # Ensure value is properly quoted if it's a string
    if isinstance(value, str):
        # Escape backslashes and quotes within the string
        escaped_value = value.replace('\\', '\\\\').replace('"', '\\"')
        replacement_value = f'"{escaped_value}"'
    else: # Handle numbers, booleans etc. (though config seems string-focused)
        replacement_value = repr(value)

    # Regex to find the key and its value (supports single/double quotes or no quotes)
    # It captures the key, equals sign, and potential whitespace
    pattern = re.compile(rf'^({key}\s*=\s*)(".*?"|\'.*?\'|[^#\n]*)', re.MULTILINE)
    replacement = rf'\1{replacement_value}'

    # Perform the substitution
    new_content, num_subs = pattern.subn(replacement, content)

    if num_subs > 0:
        logging.info(f"Updated config key '{key}'")
        return new_content
    else:
        # Key not found, maybe append it? Or log a warning.
        # For simplicity, we'll just return the original content if key not found.
        logging.warning(f"Config key '{key}' not found for update.")
        # Optionally, append the new key-value pair
        # return content.rstrip() + f'\n{key} = {replacement_value}\n'
        return content

def save_config_content(content):
    """Saves the modified config content back to the file."""
    config_path = get_config_path()
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(content)
        logging.info(f"Configuration saved to {config_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save configuration to {config_path}: {e}", exc_info=True)
        return False

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')