import requests
import logging
import json
import re
import os
from typing import Dict, Optional, Tuple

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
APP_ID = os.getenv('FEISHU_APP_ID', '')  # 请设置环境变量FEISHU_APP_ID或在此处填入您的飞书APP_ID
APP_SECRET = os.getenv('FEISHU_APP_SECRET', '')  # 请设置环境变量FEISHU_APP_SECRET或在此处填入您的飞书APP_SECRET

# 飞书API配置
FEISHU_API_BASE = os.getenv('FEISHU_API_BASE', 'https://open.feishu.cn/open-apis')  # 默认使用飞书公共API地址，私有部署请修改

def get_tenant_access_token() -> Optional[str]:
    """获取飞书API访问令牌"""
    url = f"{FEISHU_API_BASE}/auth/v3/tenant_access_token/internal/"
    headers = {"Content-Type": "application/json"}
    req_body = {"app_id": APP_ID, "app_secret": APP_SECRET}

    try:
        response = requests.post(url, json=req_body, headers=headers, timeout=10)

        if response.status_code != 200:
            logger.error("Failed to get tenant access token: HTTP %d", response.status_code)
            return None

        content = response.json()
        return content.get("tenant_access_token", None)
    except Exception as e:
        logger.error(f"获取飞书Token时出错: {str(e)}")
        return None

def send_card_message(user_id: str, text: str) -> Tuple[bool, str]:
    """
    发送飞书卡片消息给指定用户
    
    Args:
        user_id: 用户ID
        text: 消息内容
    
    Returns:
        (是否成功, 结果消息)
    """
    token = get_tenant_access_token()
    if not token:
        logger.error("无法发送消息，token为空")
        return False, "获取飞书API授权失败"
    
    url = f"{FEISHU_API_BASE}/im/v1/messages?receive_id_type=user_id"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": "Bearer " + token
    }

    # 将富文本卡片内容转换为Markdown格式
    markdown_content = f"**信息安全告警:**\n\n{text}"
    
    req_body = {
        "receive_id": user_id,
        "msg_type": "interactive",
        "content": json.dumps({
            "elements": [
                {
                    "tag": "div",
                    "text": {
                        "tag": "lark_md",
                        "content": markdown_content
                    }
                }
            ]
        }, ensure_ascii=False)
    }

    try:
        response = requests.post(url, json=req_body, headers=headers, timeout=10)
        
        if response.status_code != 200:
            logger.error(f"Failed to send message: HTTP {response.status_code}, {response.content}")
            return False, f"消息发送失败: HTTP {response.status_code}"
            
        result = response.json()
        if result.get("code", -1) != 0:
            logger.error(f"Failed to send message: {result.get('msg', 'Unknown error')}")
            return False, f"消息发送失败: {result.get('msg', '未知错误')}"
            
        return True, "消息发送成功"
    except Exception as e:
        logger.error(f"发送飞书消息时出错: {str(e)}")
        return False, f"发送消息发生异常: {str(e)}"

def validate_domain_account(user_id: str) -> Tuple[bool, Optional[str]]:
    """
    验证用户域账号是否有效
    
    Args:
        user_id: 用户的域账号，例如"zhangsan"
    
    Returns:
        (是否有效, 错误信息/用户ID)
    """
    # 域账号格式验证 - 假设域账号格式为纯英文字母或数字组合
    if not re.match(r'^[a-zA-Z0-9_]+$', user_id):
        return False, "域账号格式不正确，应为英文字母和数字组合"
    
    # 在开源版本中，我们直接返回用户ID
    # 注意：如果需要验证用户存在性，请根据实际API调整此部分
    return True, user_id

# 工具调用接口
def send_feishu_message(user_id: str, message: str) -> str:
    """
    发送飞书消息工具函数
    
    Args:
        user_id: 用户域账号
        message: 消息内容
    
    Returns:
        执行结果描述
    """
    # 验证域账号
    valid, result = validate_domain_account(user_id)
    if not valid:
        return f"发送飞书消息失败: {result}"
    
    # 执行发送
    success, send_result = send_card_message(result, message)
    
    if success:
        return f"成功发送飞书消息给用户 {user_id}: \n{message}"
    else:
        return f"发送飞书消息失败: {send_result}"

def get_feishu_tool():
    """获取飞书消息发送工具定义"""
    return {
        "send_feishu_message": {
            "function": send_feishu_message,
            "description": "发送飞书消息给指定的用户（仅支持域账号）",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "接收者的域账号，例如'zhangsan'"
                    },
                    "message": {
                        "type": "string",
                        "description": "要发送的消息内容"
                    }
                },
                "required": ["user_id", "message"]
            }
        }
    }

# 如果直接运行此文件，执行测试
if __name__ == "__main__":
    # 测试发送消息
    test_user = "your_test_user"  # 替换为实际测试用户
    test_message = "这是一条测试消息，来自飞书API测试"
    print(send_feishu_message(test_user, test_message))
    
