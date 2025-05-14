import logging
import json
import requests
import re
import base64
import urllib.parse
import binascii

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义可用工具
AVAILABLE_TOOLS = {
    "web_search_cve": {
        "function": "search_cve",
        "description": "根据CVE编号在线搜索漏洞信息",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE编号，格式为CVE-YYYY-NNNNN"
                }
            },
            "required": ["cve_id"]
        }
    },
    "lookup_internal_ip": {
        "function": "lookup_ip",
        "description": "查询IP地址关联的CMDB资产信息（如主机、应用配置、F5等）。支持内网和部分已知外网IP",
        "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "要查询的IPv4地址"
                }
            },
            "required": ["ip_address"]
        }
    },
    "decode_encodings": {
        "function": "decode_encodings",
        "description": "识别并自动递归解码文本中的各种编码(Base64, URL编码, 十六进制等)",
        "parameters": {
            "type": "object",
            "properties": {
                "encoded_text": {
                    "type": "string",
                    "description": "可能包含编码内容的文本"
                },
                "encoding_type": {
                    "type": "string",
                    "enum": ["auto", "base64", "url", "hex", "powershell"],
                    "description": "指定编码类型，auto表示自动检测"
                },
                "max_recursion_depth": {
                    "type": "integer",
                    "description": "最大递归深度，防止无限循环",
                    "default": 5
                }
            },
            "required": ["encoded_text"]
        }
    }
}

def search_cve(args):
    """搜索CVE漏洞信息"""
    cve_id = args.get("cve_id", "").strip()
    
    # 验证CVE ID格式
    if not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
        return f"无效的CVE ID格式: {cve_id}。正确格式应为: CVE-YYYY-NNNNN"
    
    try:
        # 使用国内可访问的CVE查询API
        url = f"https://www.cvedetails.com/cve-details.php?cve_id={cve_id}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            # 简单返回查询成功信息，实际应用中应解析网页内容提取结构化信息
            return f"CVE查询成功，信息如下：\n- CVE ID: {cve_id}\n- 查询源: CVE Details\n- 详情页: {url}\n\n请注意：受网络限制，仅返回链接，未能提取详细内容。请通过链接查看完整信息。"
        else:
            return f"查询失败，HTTP状态码: {response.status_code}。请检查网络连接或稍后再试。"
    except Exception as e:
        logger.error(f"CVE查询错误: {e}")
        return f"查询CVE信息时发生错误: {str(e)}"

def lookup_ip(args):
    """查询IP地址关联的CMDB资产信息"""
    ip_address = args.get("ip_address", "").strip()
    
    # 验证IP地址格式
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        return f"无效的IP地址格式: {ip_address}"
    
    try:
        # 导入并使用CMDB查询功能
        import cmdb
        result = cmdb.queryIpInfo(ip_address)
        
        # 如果结果为空，返回未找到信息的提示
        if not result or result.strip() == "":
            logger.warning(f"CMDB查询返回空结果: {ip_address}")
            return f"CMDB没有该IP {ip_address} 信息"
        
        return result
    except ImportError:
        logger.error("无法导入CMDB模块")
        return f"CMDB没有该IP {ip_address} 信息"
    except Exception as e:
        logger.error(f"CMDB查询发生错误: {str(e)}")
        return f"查询IP {ip_address} 时发生错误: {str(e)}"

def decode_encodings(args):
    """识别并解码文本中的各种编码"""
    encoded_text = args.get("encoded_text", "").strip()
    encoding_type = args.get("encoding_type", "auto").lower()
    
    if not encoded_text:
        return "错误：未提供需要解码的文本"
    
    # 如果文本过长，截断处理
    if len(encoded_text) > 10000:
        logger.warning(f"输入文本过长 ({len(encoded_text)} 字符)，将截断处理")
        encoded_text = encoded_text[:10000] + "... (文本已截断)"
    
    # 根据指定的编码类型调用对应的解码函数
    if encoding_type == "auto":
        # 自动检测模式下，仍然使用check_encodings函数
        result = check_encodings(encoded_text)
        if not result:
            return "未检测到任何已知编码格式"
        return result
    
    elif encoding_type == "base64":
        # 直接尝试Base64解码整个文本
        return decode_base64(encoded_text)
    
    elif encoding_type == "url":
        # 直接尝试URL解码
        return decode_url(encoded_text)
    
    elif encoding_type == "hex":
        # 直接尝试十六进制解码
        return decode_hex(encoded_text)
    
    elif encoding_type == "powershell":
        # 直接尝试PowerShell编码解码
        # PowerShell编码实质上是UTF-16LE编码的Base64
        try:
            # 添加Base64填充(如果需要)
            padding_needed = len(encoded_text) % 4
            if padding_needed != 0:
                encoded_text += '=' * (4 - padding_needed)
                
            # 直接使用UTF-16LE解码（PowerShell标准）
            decoded = base64.b64decode(encoded_text).decode('utf-16le')
            return f"PowerShell编码解码结果:\n{decoded}"
        except Exception as e:
            logger.error(f"PowerShell解码失败: {e}")
            # 如果特定的PowerShell解码失败，尝试其他Base64解码方法
            return decode_base64(encoded_text)
    
    else:
        return f"不支持的编码类型: {encoding_type}"

def extract_powershell_encoded(text):
    """提取PowerShell中的EncodedCommand参数值"""
    # 匹配 -EncodedCommand/-enc/-e 后面的Base64字符串
    patterns = [
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*(?:-e(?:nc(?:odedCommand)?)?)\s+([A-Za-z0-9+/=]+)',
        r'(?:-e(?:nc(?:odedCommand)?)?)\s+([A-Za-z0-9+/=]+)',
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*-e(?:nc(?:odedCommand)?)([A-Za-z0-9+/=]+)',
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*-e(?:nc(?:odedCommand)?)\s+["\']([A-Za-z0-9+/=]+)["\']'
    ]
    
    extracted = []
    for pattern in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            encoded = match.group(1).strip()
            # 检查是否为有效的Base64，如果不是则跳过
            if is_valid_base64(encoded):
                extracted.append(encoded)
    
    return extracted

def extract_base64(text):
    """提取文本中可能的Base64编码"""
    # 寻找可能的Base64编码片段（至少16字符长）
    # 更严格的模式：必须只包含Base64字符，可以包含=作为填充
    pattern = r'[A-Za-z0-9+/]{16,}={0,3}'
    
    results = []
    matches = re.finditer(pattern, text)
    for match in matches:
        b64_candidate = match.group(0)
        if is_valid_base64(b64_candidate):
            results.append(b64_candidate)
    
    # 特殊处理：检测整个字符串是否为Base64
    if re.match(r'^[A-Za-z0-9+/]+={0,3}$', text) and len(text) >= 16:
        if text not in results and is_valid_base64(text):
            results.append(text)
    
    return results

def extract_url_encoded(text):
    """从文本中提取URL编码内容"""
    # 匹配%后跟两位十六进制数的模式
    pattern = r'(?:%[0-9A-Fa-f]{2})+'
    
    results = []
    matches = re.finditer(pattern, text)
    for match in matches:
        url_encoded = match.group(0)
        # 确保提取的内容足够长才认为是有效的URL编码（至少包含2个编码字符）
        if len(url_encoded) >= 6:  # %XX%XX 最少6个字符
            results.append(url_encoded)
    
    return results

def extract_hex(text):
    """提取文本中的十六进制编码"""
    # 匹配0x开头的十六进制或连续的十六进制字符
    patterns = [
        r'0x[0-9A-Fa-f]{6,}',  # 0x开头
        r'(?:[^0-9A-Fa-f]|^)([0-9A-Fa-f]{8,})(?:[^0-9A-Fa-f]|$)'  # 连续的十六进制字符
    ]
    
    results = []
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            # 根据不同的模式获取匹配组
            hex_str = match.group(0) if pattern.startswith('0x') else match.group(1)
            
            # 检查是否可能是Base64而不是十六进制
            if is_valid_base64(hex_str) and re.search(r'[a-zA-Z]', hex_str):
                continue  # 如果可能是Base64，则跳过
                
            if len(hex_str) % 2 == 0 or hex_str.startswith('0x'):  # 确保字节数为偶数
                results.append(hex_str)
    
    return results

def find_encodings_in_text(text):
    """在文本中递归查找各种编码"""
    results = []
    
    # 检查PowerShell编码
    ps_encoded = extract_powershell_encoded(text)
    if ps_encoded:
        results.append("发现PowerShell编码命令")
        for cmd in ps_encoded:
            results.append(f"PowerShell编码: {cmd}")
    
    # 检查Base64
    base64_encoded = extract_base64(text)
    if base64_encoded:
        results.append("发现Base64编码")
        for b64 in base64_encoded:
            results.append(f"Base64: {b64}")
    
    # 检查URL编码
    url_encoded = extract_url_encoded(text)
    if url_encoded:
        results.append("发现URL编码")
        for url_enc in url_encoded:
            results.append(f"URL编码: {url_enc}")
    
    # 检查十六进制编码
    hex_encoded = extract_hex(text)
    if hex_encoded:
        results.append("发现十六进制编码")
        for hex_enc in hex_encoded:
            results.append(f"十六进制: {hex_enc}")
    
    return results

def is_valid_base64(text):
    """检查文本是否为有效的Base64编码"""
    # 移除空格和换行
    text = text.strip()
    
    # 检查长度是否合理（至少需要4个字符才有意义）
    if len(text) < 4:
        return False
    
    # 检查是否只包含Base64字符
    if not re.match(r'^[A-Za-z0-9+/=]+$', text):
        return False
    
    # 检查padding，如果需要则添加
    padding_needed = len(text) % 4
    if padding_needed != 0:
        text += '=' * (4 - padding_needed)
    
    # 尝试解码
    try:
        base64.b64decode(text)
        return True
    except Exception:
        return False

def is_printable(s):
    """检查字符串是否主要包含可打印字符"""
    # 计算可打印字符的比例
    printable_count = sum(c.isprintable() for c in s)
    return printable_count > len(s) * 0.7  # 如果超过70%是可打印字符，则认为是有效的

def has_mostly_printable(s):
    """检查字符串是否主要包含可打印字符"""
    # 计算可打印字符的比例
    printable_count = sum(c.isprintable() for c in s)
    return printable_count > len(s) * 0.7  # 如果超过70%是可打印字符，则认为是有效的

def execute_tool(tool_name, args):
    """执行指定的工具函数"""
    if tool_name not in AVAILABLE_TOOLS:
        return f"错误：未找到工具 '{tool_name}'"
    
    function_name = AVAILABLE_TOOLS[tool_name]["function"]
    
    # 查找对应的函数并执行
    if function_name == "search_cve":
        return search_cve(args)
    elif function_name == "lookup_ip":
        return lookup_ip(args)
    elif function_name == "decode_encodings":
        return decode_encodings(args)
    else:
        return f"错误：未实现的工具函数 '{function_name}'"

def check_powershell_encoded(text):
    """检查是否包含PowerShell编码命令"""
    # 增强的PowerShell编码命令检测模式
    patterns = [
        # 标准格式: powershell -enc xxx 或 powershell.exe -EncodedCommand xxx
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*(?:-e(?:nc(?:odedCommand)?)?)\s+([A-Za-z0-9+/=]+)',
        
        # 直接带有-EncodedCommand参数但没有明确的powershell.exe
        r'(?:-e(?:nc(?:odedCommand)?)?)\s+([A-Za-z0-9+/=]+)',
        
        # 连在一起的格式: powershell -enc[base64data]
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*-e(?:nc(?:odedCommand)?)([A-Za-z0-9+/=]+)',
        
        # 带有双引号或单引号的变体
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*-e(?:nc(?:odedCommand)?)\s+["\']([A-Za-z0-9+/=]+)["\']'
    ]
    
    for pattern in patterns:
        matches = re.search(pattern, text, re.IGNORECASE)
        if matches:
            encoded_part = matches.group(1)
            return True
    
    # 检查是否包含[Reflection.Assembly]::Load, [Convert]::FromBase64String等常见PowerShell编码技术
    ps_encoding_techniques = [
        r'\[Convert\]::FromBase64String',
        r'\[Reflection\.Assembly\]::Load.+FromBase64String',
        r'\[System\.Text\.Encoding\]::Unicode\.GetString',
        r'\[System\.Text\.Encoding\]::UTF8\.GetString'
    ]
    
    for technique in ps_encoding_techniques:
        if re.search(technique, text, re.IGNORECASE):
            return True
    
    return False

def decode_base64(text):
    """
    尝试解码Base64字符串
    """
    # 清理输入：移除空格、换行等
    text = text.strip()
    
    # 添加Base64字符串可能缺少的padding
    padding_needed = len(text) % 4
    if padding_needed != 0:
        text += '=' * (4 - padding_needed)
    
    results = []
    
    # 尝试多种解码方法
    decode_attempts = [
        # PowerShell通常使用UTF-16LE
        ('UTF-16LE (PowerShell)', lambda: base64.b64decode(text).decode('utf-16le')),
        # 标准UTF-8
        ('UTF-8', lambda: base64.b64decode(text).decode('utf-8')),
        # ASCII
        ('ASCII', lambda: base64.b64decode(text).decode('ascii', errors='replace'))
    ]
    
    for method_name, decode_func in decode_attempts:
        try:
            decoded = decode_func()
            # 过滤掉大部分为乱码的结果
            if has_mostly_printable(decoded):
                results.append(f"Base64解码 ({method_name}):\n{decoded}")
        except Exception:
            continue
    
    # 如果所有尝试都失败，尝试作为原始字节解码
    if not results:
        try:
            decoded = str(base64.b64decode(text))
            results.append(f"Base64解码 (二进制):\n{decoded}")
        except Exception as e:
            return f"Base64解码失败: {str(e)}"
    
    return "\n".join(results)

def check_encodings(text):
    """检查并解码文本中可能包含的各种编码"""
    if not text or len(text) < 4:  # 太短的文本不可能包含有效编码
        return ""
    
    results = []
    
    # 检查PowerShell编码
    if check_powershell_encoded(text):
        results.append("发现PowerShell编码命令")
        ps_encoded = extract_powershell_encoded(text)
        if ps_encoded:
            for cmd in ps_encoded:
                results.append(f"提取的PowerShell编码命令: {cmd[:50]}..." if len(cmd) > 50 else cmd)
                # 使用新的decode_base64函数处理
                decoded = decode_base64(cmd)
                results.append(decoded)
    
    # 检查Base64编码
    base64_parts = extract_base64(text)
    if base64_parts:
        for part in base64_parts:
            results.append(f"发现疑似Base64编码: {part[:50]}..." if len(part) > 50 else part)
            # 使用新的decode_base64函数处理
            decoded = decode_base64(part)
            results.append(decoded)
    
    # 检查URL编码
    if check_url_encoding(text):
        results.append("发现URL编码")
        decoded = decode_url(text)
        results.append(decoded)
    
    # 检查十六进制编码
    if check_hex_encoding(text):
        results.append("发现十六进制编码")
        decoded = decode_hex(text)
        results.append(decoded)
    
    return "\n".join(results)

def decode_url(text):
    """解码URL编码内容"""
    try:
        decoded = urllib.parse.unquote(text)
        # 只返回解码结果，不做额外判断
        return f"URL解码结果:\n{decoded}"
    except Exception as e:
        return f"URL解码失败: {str(e)}"

def decode_hex(text):
    """解码十六进制编码内容"""
    try:
        # 如果是0x开头，移除它
        if text.startswith('0x'):
            text = text[2:]
        
        # 确保十六进制字符串长度为偶数
        if len(text) % 2 != 0:
            text = text[:-1]
        
        # 解码十六进制
        decoded = binascii.unhexlify(text).decode('utf-8', errors='replace')
        return f"十六进制解码结果:\n{decoded}"
    except Exception as e:
        try:
            # 尝试UTF-16LE解码
            decoded = binascii.unhexlify(text).decode('utf-16le', errors='replace')
            return f"十六进制解码结果 (UTF-16LE):\n{decoded}"
        except Exception:
            return f"十六进制解码失败: {str(e)}"

def check_url_encoding(text):
    """检查是否包含URL编码"""
    # URL编码标志：%加两位十六进制数字
    return bool(re.search(r'%[0-9A-Fa-f]{2}', text))

def check_hex_encoding(text):
    """检查是否包含十六进制编码"""
    # 检查0x开头的十六进制或连续的十六进制字符
    patterns = [
        r'0x[0-9A-Fa-f]{6,}',  # 0x开头
        r'(?:[^0-9A-Fa-f]|^)([0-9A-Fa-f]{8,})(?:[^0-9A-Fa-f]|$)'  # 连续的十六进制字符
    ]
    
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    
    return False 