import os
import json
import logging
import requests


# Load environment variables
APP_ID = os.getenv('FEISHU_APP_ID', '')  # 请设置环境变量FEISHU_APP_ID或在此处填入您的飞书APP_ID
APP_SECRET = os.getenv('FEISHU_APP_SECRET', '')  # 请设置环境变量FEISHU_APP_SECRET或在此处填入您的飞书APP_SECRET
FEISHU_API_BASE = os.getenv('FEISHU_API_BASE', 'https://open.feishu.cn/open-apis')  # 默认使用飞书公共API地址，私有部署请修改

def get_tenant_access_token():
    url = f"{FEISHU_API_BASE}/auth/v3/tenant_access_token/internal/"
    headers = {"Content-Type": "application/json"}
    req_body = {"app_id": APP_ID, "app_secret": APP_SECRET}

    try:
        response = requests.post(url, json=req_body, headers=headers, timeout=10)

        if response.status_code != 200:
            logging.error("Failed to get tenant access token: HTTP %d", response.status_code)
            return ""

        content = response.json()
        return content.get("tenant_access_token", "")
    except Exception as e:
        logging.error(f"获取飞书Token时出错: {str(e)}")
        return ""

def send_card_message(token, text, user_id):
    if not token:
        logging.error("无法发送消息，token为空")
        return False
    
    url = f"{FEISHU_API_BASE}/im/v1/messages?receive_id_type=user_id"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": "Bearer " + token
    }

    # 将富文本卡片内容转换为Markdown格式
    markdown_content = f"**信息安全告警:**\n\n{text}"
    
    
    receive_id = user_id
    
    req_body = {
        "receive_id": receive_id,
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
            logging.error(f"Failed to send message: HTTP {response.status_code}, {response.content}")
            return False
            
        result = response.json()
        if result.get("code", -1) != 0:
            logging.error(f"Failed to send message: {result.get('msg', 'Unknown error')}")
            return False
            
        return True
    except Exception as e:
        logging.error(f"发送飞书消息时出错: {str(e)}")
        return False


if __name__ == "__main__":
    token = get_tenant_access_token()
    send_card_message(token, "测试", "your_test_user")
    
