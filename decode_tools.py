import logging
import json
import re
import base64
import urllib.parse
import binascii
import html
import quopri
from typing import Dict, List, Any, Tuple, Optional

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 定义函数
def decode_text(encoded_text: str, encoding_type: str = "auto", max_recursion_depth: int = 5) -> str:
    """
    识别并解码文本中的各种编码，支持递归解码
    
    参数:
        encoded_text: 要解码的文本
        encoding_type: 编码类型 (auto, base64, url, hex, html, quoted_printable, powershell)
        max_recursion_depth: 最大递归深度
    
    返回:
        解码结果的字符串
    """
    if not encoded_text:
        return "错误：未提供需要解码的文本"
    
    encoded_text = encoded_text.strip()
    encoding_type = encoding_type.lower()
    max_depth = max_recursion_depth
    
    # 如果文本过长，截断处理
    if len(encoded_text) > 50000:
        logger.warning(f"输入文本过长 ({len(encoded_text)} 字符)，将截断处理")
        encoded_text = encoded_text[:50000] + "... (文本已截断)"
    
    # 检查是否为特定的编码类型
    if encoding_type != "auto":
        return decode_specific_type(encoded_text, encoding_type)
    
    # 自动检测并解码
    result = auto_decode_text(encoded_text, max_depth)
    
    if not result:
        return "未检测到任何已知编码格式，或无法成功解码"
    
    return result

def decode_specific_type(text: str, encoding_type: str) -> str:
    """根据指定的编码类型解码文本"""
    if encoding_type == "base64":
        return decode_base64(text)
    elif encoding_type == "url":
        return decode_url(text)
    elif encoding_type == "hex":
        return decode_hex(text)
    elif encoding_type == "html":
        return decode_html(text)
    elif encoding_type == "quoted_printable":
        return decode_quoted_printable(text)
    elif encoding_type == "powershell":
        return decode_powershell(text)
    else:
        return f"不支持的编码类型: {encoding_type}"

def auto_decode_text(text: str, max_depth: int, current_depth: int = 0) -> str:
    """
    自动递归解码文本中可能包含的各种编码
    
    Args:
        text: 要解码的文本
        max_depth: 最大递归深度
        current_depth: 当前递归深度
    
    Returns:
        解码结果和检测到的编码类型
    """
    if current_depth >= max_depth:
        return f"已达到最大递归深度 ({max_depth})，停止解码:\n{text}"
    
    # 跟踪检测到的编码和解码结果
    results = []
    decoded_text = text
    
    # 第1步: 检测文本中的编码类型
    encoding_types = detect_encodings(text)
    
    if not encoding_types:
        if current_depth == 0:
            return "未检测到任何已知编码格式"
        else:
            return text  # 返回当前文本，因为没检测到进一步的编码
    
    # 第2步: 对每种检测到的编码类型尝试解码
    for enc_type, enc_text in encoding_types:
        # 记录检测到的编码类型和片段
        snippet = enc_text[:50] + "..." if len(enc_text) > 50 else enc_text
        result_entry = f"检测到 {enc_type} 编码: {snippet}"
        results.append(result_entry)
        
        # 尝试解码
        decoded = None
        if enc_type == "base64":
            decoded = try_base64_decode(enc_text)
        elif enc_type == "url":
            decoded = try_url_decode(enc_text)
        elif enc_type == "hex":
            decoded = try_hex_decode(enc_text)
        elif enc_type == "html":
            decoded = try_html_decode(enc_text)
        elif enc_type == "quoted_printable":
            decoded = try_quoted_printable_decode(enc_text)
        elif enc_type == "powershell":
            decoded = try_powershell_decode(enc_text)
        
        # 如果解码成功，递归检查是否还有更深层的编码
        if decoded and decoded != enc_text:
            results.append(f"{enc_type} 解码结果:\n{decoded}")
            
            # 递归检查解码后的文本是否还包含编码
            deeper_result = auto_decode_text(decoded, max_depth, current_depth + 1)
            if deeper_result and deeper_result != decoded:
                results.append("进一步解码:")
                results.append(deeper_result)
    
    # 返回所有解码结果
    return "\n".join(results)

def detect_encodings(text: str) -> List[Tuple[str, str]]:
    """
    检测文本中可能包含的各种编码
    
    Returns:
        编码类型和对应文本的列表
    """
    encodings = []
    
    # 检查是否包含PowerShell编码命令
    ps_encoded = extract_powershell_encoded(text)
    if ps_encoded:
        for cmd in ps_encoded:
            encodings.append(("powershell", cmd))
    
    # 检查Base64编码
    base64_encoded = extract_base64(text)
    if base64_encoded:
        for b64 in base64_encoded:
            encodings.append(("base64", b64))
    
    # 检查URL编码
    if contains_url_encoding(text):
        encodings.append(("url", text))
    
    # 检查HTML实体编码
    if contains_html_entities(text):
        encodings.append(("html", text))
    
    # 检查十六进制编码
    hex_encoded = extract_hex(text)
    if hex_encoded:
        for hex_enc in hex_encoded:
            encodings.append(("hex", hex_enc))
    
    # 检查Quoted-Printable编码
    if contains_quoted_printable(text):
        encodings.append(("quoted_printable", text))
    
    return encodings

# 提取函数
def extract_powershell_encoded(text: str) -> List[str]:
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

def extract_base64(text: str) -> List[str]:
    """提取文本中可能的Base64编码"""
    # 寻找可能的Base64编码片段（至少16字符长）
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

def extract_hex(text: str) -> List[str]:
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

# 检测函数
def is_valid_base64(text: str) -> bool:
    """检查文本是否为有效的Base64编码"""
    # 移除空格和换行
    text = text.strip()
    
    # 检查长度是否合理（至少需要4个字符才有意义）
    if len(text) < 4:
        return False
    
    # 检查是否只包含Base64字符
    if not re.match(r'^[A-Za-z0-9+/=]+$', text):
        return False
    
    # 检查padding
    padding_needed = len(text) % 4
    if padding_needed != 0:
        text += '=' * (4 - padding_needed)
    
    # 尝试解码
    try:
        base64.b64decode(text)
        return True
    except Exception:
        return False

def contains_url_encoding(text: str) -> bool:
    """检查文本是否包含URL编码"""
    # 至少包含一个%XX格式的URL编码
    return bool(re.search(r'%[0-9A-Fa-f]{2}', text))

def contains_html_entities(text: str) -> bool:
    """检查文本是否包含HTML实体编码"""
    # 检查数字实体 (&#123;) 或命名实体 (&quot;)
    return bool(re.search(r'&(#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z]+);', text))

def contains_quoted_printable(text: str) -> bool:
    """检查文本是否包含Quoted-Printable编码"""
    # Quoted-Printable编码使用=后跟两个十六进制数字表示字符
    return bool(re.search(r'=[0-9A-F]{2}', text)) and '=\r\n' not in text

def has_mostly_printable(s: str) -> bool:
    """检查字符串是否主要包含可打印字符"""
    # 计算可打印字符的比例
    printable_count = sum(c.isprintable() for c in s)
    return printable_count > len(s) * 0.7  # 如果超过70%是可打印字符，则认为是有效的

# 解码函数
def try_base64_decode(text: str) -> Optional[str]:
    """尝试解码Base64字符串"""
    try:
        # 添加必要的padding
        padding_needed = len(text) % 4
        if padding_needed != 0:
            text += '=' * (4 - padding_needed)
        
        # 尝试不同的编码方式
        for encoding in ['utf-8', 'utf-16le', 'ascii', 'latin1']:
            try:
                decoded = base64.b64decode(text).decode(encoding, errors='replace')
                if has_mostly_printable(decoded):
                    return decoded
            except Exception:
                continue
        
        # 如果所有尝试都失败，返回原始字节的字符串表示
        return str(base64.b64decode(text))
    except Exception as e:
        logger.debug(f"Base64解码失败: {str(e)}")
        return None

def try_url_decode(text: str) -> Optional[str]:
    """尝试解码URL编码字符串"""
    try:
        return urllib.parse.unquote(text)
    except Exception as e:
        logger.debug(f"URL解码失败: {str(e)}")
        return None

def try_hex_decode(text: str) -> Optional[str]:
    """尝试解码十六进制编码字符串"""
    try:
        # 如果是0x开头，移除它
        if text.startswith('0x'):
            text = text[2:]
        
        # 确保十六进制字符串长度为偶数
        if len(text) % 2 != 0:
            text = text[:-1]
        
        # 尝试不同的编码方式解码
        for encoding in ['utf-8', 'utf-16le', 'ascii', 'latin1']:
            try:
                decoded = binascii.unhexlify(text).decode(encoding, errors='replace')
                if has_mostly_printable(decoded):
                    return decoded
            except Exception:
                continue
        
        return None
    except Exception as e:
        logger.debug(f"十六进制解码失败: {str(e)}")
        return None

def try_html_decode(text: str) -> Optional[str]:
    """尝试解码HTML实体编码字符串"""
    try:
        return html.unescape(text)
    except Exception as e:
        logger.debug(f"HTML实体解码失败: {str(e)}")
        return None

def try_quoted_printable_decode(text: str) -> Optional[str]:
    """尝试解码Quoted-Printable编码字符串"""
    try:
        # 确保文本是字节类型
        if isinstance(text, str):
            text_bytes = text.encode('utf-8')
        else:
            text_bytes = text
        
        decoded = quopri.decodestring(text_bytes)
        return decoded.decode('utf-8', errors='replace')
    except Exception as e:
        logger.debug(f"Quoted-Printable解码失败: {str(e)}")
        return None

def try_powershell_decode(text: str) -> Optional[str]:
    """尝试解码PowerShell编码命令"""
    try:
        # PowerShell编码实质上是UTF-16LE编码的Base64
        # 添加Base64填充(如果需要)
        padding_needed = len(text) % 4
        if padding_needed != 0:
            text += '=' * (4 - padding_needed)
            
        # 直接使用UTF-16LE解码（PowerShell标准）
        decoded = base64.b64decode(text).decode('utf-16le')
        return decoded
    except Exception as e:
        logger.debug(f"PowerShell解码失败: {str(e)}")
        return None

# 具体解码实现
def decode_base64(text: str) -> str:
    """解码Base64字符串"""
    result = try_base64_decode(text)
    if result:
        return f"Base64解码结果:\n{result}"
    else:
        return "Base64解码失败，无法得到有效结果"

def decode_url(text: str) -> str:
    """解码URL编码字符串"""
    result = try_url_decode(text)
    if result and result != text:
        return f"URL解码结果:\n{result}"
    else:
        return "URL解码失败，无法得到有效结果"

def decode_hex(text: str) -> str:
    """解码十六进制编码字符串"""
    result = try_hex_decode(text)
    if result:
        return f"十六进制解码结果:\n{result}"
    else:
        return "十六进制解码失败，无法得到有效结果"

def decode_html(text: str) -> str:
    """解码HTML实体编码字符串"""
    result = try_html_decode(text)
    if result and result != text:
        return f"HTML实体解码结果:\n{result}"
    else:
        return "HTML实体解码失败，无法得到有效结果"

def decode_quoted_printable(text: str) -> str:
    """解码Quoted-Printable编码字符串"""
    result = try_quoted_printable_decode(text)
    if result and result != text:
        return f"Quoted-Printable解码结果:\n{result}"
    else:
        return "Quoted-Printable解码失败，无法得到有效结果"

def decode_powershell(text: str) -> str:
    """解码PowerShell编码字符串"""
    result = try_powershell_decode(text)
    if result:
        return f"PowerShell编码解码结果:\n{result}"
    else:
        return "PowerShell解码失败，无法得到有效结果"

# 定义工具信息 - 移到函数定义之后
DECODE_TOOL = {
    "decode_text": {
        "function": decode_text,
        "description": "识别并自动递归解码文本中的各种编码(Base64, URL编码, HTML实体, 十六进制, 引用可打印等)",
        "parameters": {
            "type": "object",
            "properties": {
                "encoded_text": {
                    "type": "string",
                    "description": "可能包含编码内容的文本"
                },
                "encoding_type": {
                    "type": "string",
                    "enum": ["auto", "base64", "url", "hex", "html", "quoted_printable", "powershell"],
                    "description": "指定编码类型，auto表示自动检测多种编码"
                },
                "max_recursion_depth": {
                    "type": "integer",
                    "description": "最大递归解码深度，防止无限循环",
                    "default": 5
                }
            },
            "required": ["encoded_text"]
        }
    }
}

# 导出函数，供local_tools.py调用
def get_decode_tool():
    """返回解码工具的定义"""
    return DECODE_TOOL 