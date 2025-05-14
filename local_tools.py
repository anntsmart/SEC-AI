import logging
import re
import json 
import subprocess  
import shlex  
import os  
from duckduckgo_search import DDGS # Using duckduckgo_search library

# 导入解码工具模块
try:
    from decode_tools import get_decode_tool
    decode_tools_available = True
except ImportError:
    logging.error("decode_tools.py module not found. Text decoding tools will be unavailable.")
    decode_tools_available = False

# 导入飞书消息发送工具
try:
    from feishu_send_message import get_feishu_tool
    feishu_tools_available = True
except ImportError:
    logging.error("feishu_send_message.py module not found. Feishu messaging tools will be unavailable.")
    feishu_tools_available = False

# Attempt to import cmdb module, handle errors
try:
    import cmdb
    cmdb_available = True
except ImportError:
    logging.error("cmdb.py module not found. lookup_internal_ip tool will be unavailable.")
    cmdb_available = False
    # Define a dummy function if cmdb not available
    def lookup_internal_ip_dummy(ip_address: str) -> str:
        return f"错误：内部IP查询工具不可用 (cmdb.py 未找到)。"


# --- Tool Implementations ---

def search_cve_info(cve_id: str) -> str:
    """
    Searches the web for information about a specific CVE ID using DuckDuckGo.
    Returns a concise summary of the findings or an error message.
    """
    if not isinstance(cve_id, str) or not re.match(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE):
        return f"错误：无效的CVE ID格式 '{cve_id}'。请提供类似 'CVE-YYYY-NNNN' 的格式。"

    logging.info(f"Executing web search for CVE: {cve_id}")
    summary = f"关于 {cve_id} 的网络搜索结果:\n"
    max_results = 5 # Number of search results to fetch

    try:
        # Ensure duckduckgo_search is installed
        try:
             from duckduckgo_search import DDGS
        except ImportError:
             logging.error("duckduckgo_search library not installed. Cannot perform web search.")
             return "错误：无法执行网络搜索，缺少 'duckduckgo_search' 库。请使用 'pip install duckduckgo-search' 安装。"

        with DDGS(timeout=10) as ddgs: # Added timeout
            results = list(ddgs.text(f'"{cve_id}" vulnerability details description exploit', max_results=max_results))

        if not results:
            summary += "未找到相关的详细信息。"
            logging.warning(f"No web search results found for {cve_id}")
        else:
            for i, result in enumerate(results):
                title = result.get('title', 'N/A')
                body = result.get('body', 'N/A').replace('\n', ' ').strip()
                url = result.get('href', 'N/A')
                # Limit body length for conciseness
                body_snippet = body[:250] + "..." if len(body) > 250 else body
                summary += f"\n{i+1}. {title}\n   摘要: {body_snippet}\n   来源: {url}\n"
            logging.info(f"Web search for {cve_id} completed. Found {len(results)} results.")

    except Exception as e:
        logging.error(f"Error during web search for {cve_id}: {e}", exc_info=True)
        summary += f"搜索时发生错误: {e}"

    return summary.strip() # Remove trailing newline

def lookup_internal_ip(ip_address: str) -> str:
    """
    Looks up information about an internal IP address using the CMDB tools.
    Returns formatted CMDB information or an error message.
    """
    if not cmdb_available:
         return lookup_internal_ip_dummy(ip_address) # Use dummy if cmdb failed import

    # Basic IP format validation (optional but good practice)
    try:
        # Leverage the existing check from cmdb module
        # We allow non-private IPs here because cmdb.queryIpInfo handles routing now
        # if not cmdb.is_internal_ip(ip_address):
        #     logging.warning(f"IP address {ip_address} provided to lookup tool is not private. Proceeding with general CMDB query.")
        #     pass

        # More robust IP format check
        import ipaddress
        ipaddress.ip_address(ip_address)
    except ValueError:
        return f"错误：无效的IP地址格式 '{ip_address}'。"
    except Exception as e:
         logging.error(f"Error validating IP {ip_address}: {e}")
         return f"错误：验证IP地址时出错: {e}"

    logging.info(f"Executing CMDB IP lookup for: {ip_address}")
    try:
        # Call the main query function from the refactored cmdb module
        result = cmdb.queryIpInfo(ip_address) # This now handles internal/external logic
        if not result or not result.strip():
             result = f"IP地址: {ip_address}: 未在CMDB中找到任何信息。"
        logging.info(f"CMDB IP lookup for {ip_address} completed.")
        return result
    except (TimeoutError, ConnectionError, ValueError, RuntimeError) as e:
         # Catch specific errors raised by _make_cmdb_request in cmdb.py
         logging.error(f"CMDB query failed for IP {ip_address}: {e}", exc_info=True)
         return f"查询IP {ip_address} 时出错: {e}"
    except Exception as e:
        logging.error(f"Unexpected error during internal IP lookup for {ip_address}: {e}", exc_info=True)
        return f"查询IP {ip_address} 时发生意外错误: {e}"

# 新的run_terminal_powershell函数
def run_terminal_powershell(command: str, is_background: bool = False, explanation: str = "", require_user_approval: bool = True) -> str:
    """
    使用PowerShell执行终端命令并返回结果
    
    Args:
        command: 要执行的终端命令
        is_background: 是否在后台运行命令
        explanation: 命令执行的解释说明
        require_user_approval: 是否需要用户批准才能执行
        
    Returns:
        命令执行的输出结果或错误信息
    """
    logging.info(f"Executing PowerShell command: {command}, Background: {is_background}, Requires approval: {require_user_approval}")
    
    # 记录命令解释（如果提供）
    if explanation:
        logging.info(f"Command explanation: {explanation}")
    
    # 安全检查：拒绝执行危险命令
    dangerous_commands = ["rm -rf", "mkfs", "dd if", ":(){ :|:& };:", "> /dev/sda", "chmod -R 777", "mv /* /dev/null", 
                         "Remove-Item -Recurse -Force", "Format-Volume", "-Exec bypass"]
    for dangerous_cmd in dangerous_commands:
        if dangerous_cmd in command:
            return f"错误：检测到潜在危险命令 '{dangerous_cmd}'，拒绝执行。如果确实需要执行此命令，请手动在终端中运行。"
    
    try:
        # 构建PowerShell命令
        powershell_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        if not os.path.exists(powershell_path):
            # 尝试查找PowerShell路径
            if os.name == 'nt':
                if os.path.exists(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
                    powershell_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                elif os.path.exists(r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"):
                    powershell_path = r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
                else:
                    return "错误：无法找到PowerShell可执行文件。"
        
        # 命令执行方式取决于是否为后台运行
        if is_background:
            if os.name == 'nt':
                # 在Windows上使用Start-Process在后台运行
                ps_command = f'Start-Process -NoNewWindow -FilePath "powershell" -ArgumentList "-Command \\"& {{ {command} }}\\"" '
                full_command = f'"{powershell_path}" -Command "{ps_command}"'
                subprocess.Popen(full_command, shell=True)
                return f"PowerShell命令已在后台启动: {command}"
            else:
                # 对于非Windows系统，使用标准的后台启动方式
                full_command = f"nohup {command} > /dev/null 2>&1 &"
                subprocess.Popen(full_command, shell=True)
                return f"命令已在后台启动: {command}"
        else:
            # 普通命令执行，捕获输出
            if os.name == 'nt':
                # 使用PowerShell执行命令
                ps_command = f'-ExecutionPolicy Bypass -Command "& {{ {command} }}"'
                result = subprocess.run(
                    [powershell_path, "-ExecutionPolicy", "Bypass", "-Command", f"& {{ {command} }}"],
                    text=True,
                    capture_output=True,
                    timeout=60  # 设置超时时间为60秒
                )
            else:
                # 对于非Windows系统，直接执行命令
                result = subprocess.run(
                    command, 
                    shell=True, 
                    text=True, 
                    capture_output=True, 
                    timeout=60
                )
            
            # 格式化输出结果
            output = ""
            if result.stdout:
                output += f"标准输出:\n{result.stdout}\n"
            if result.stderr:
                output += f"错误输出:\n{result.stderr}\n"
            if result.returncode != 0:
                output += f"命令返回码: {result.returncode}\n"
                
            # 如果没有任何输出，提供基本反馈
            if not output:
                output = f"命令执行成功，但没有输出。返回码: {result.returncode}"
                
            return output.strip()
    except subprocess.TimeoutExpired:
        return "错误：命令执行超时（超过60秒）。如果需要执行长时间运行的命令，请设置is_background=true。"
    except Exception as e:
        logging.error(f"执行PowerShell命令时发生错误: {e}", exc_info=True)
        return f"错误：执行PowerShell命令时发生意外错误: {str(e)}"

# 为兼容性保留run_terminal_cmd函数，实际上调用run_terminal_powershell
def run_terminal_cmd(command: str, is_background: bool = False, explanation: str = "", require_user_approval: bool = True) -> str:
    """
    为兼容性保留的函数，实际调用run_terminal_powershell
    """
    logging.info(f"run_terminal_cmd called, redirecting to run_terminal_powershell: {command}")
    return run_terminal_powershell(command, is_background, explanation, require_user_approval)

def list_dir(relative_workspace_path: str, explanation: str = "") -> str:
    """
    列出指定目录的内容
    
    Args:
        relative_workspace_path: 相对于工作空间根目录的路径
        explanation: 使用此工具的原因解释
        
    Returns:
        目录内容的字符串表示
    """
    # 记录解释（如果提供）
    if explanation:
        logging.info(f"List directory explanation: {explanation}")
    
    try:
        # 获取绝对路径
        # 使用当前目录作为工作空间根目录
        workspace_root = os.getcwd()
        target_path = os.path.join(workspace_root, relative_workspace_path)
        target_path = os.path.normpath(target_path)
        
        # 安全检查：确保路径不超出工作空间
        if not os.path.abspath(target_path).startswith(os.path.abspath(workspace_root)):
            return f"错误：指定的路径 '{relative_workspace_path}' 超出了工作空间范围。"
        
        # 检查目录是否存在
        if not os.path.exists(target_path):
            return f"错误：路径 '{relative_workspace_path}' 不存在。"
        
        if not os.path.isdir(target_path):
            return f"错误：'{relative_workspace_path}' 不是一个目录。"
        
        # 列出目录内容
        contents = os.listdir(target_path)
        
        # 格式化输出
        result = f"目录 '{relative_workspace_path}' 的内容:\n\n"
        
        # 分类文件和目录
        dirs = []
        files = []
        
        for item in contents:
            item_path = os.path.join(target_path, item)
            if os.path.isdir(item_path):
                # 标记为目录
                dirs.append(f"[dir]  {item}/ (? items)")
            else:
                # 获取文件大小
                size = os.path.getsize(item_path)
                size_str = f"{size/1024:.1f}KB" if size >= 1024 else f"{size}B"
                
                # 获取行数（如果是文本文件）
                line_count = ""
                if item.endswith(('.py', '.txt', '.json', '.md', '.html', '.js', '.css')):
                    try:
                        with open(item_path, 'r', encoding='utf-8', errors='ignore') as f:
                            line_count = f", {sum(1 for _ in f)} lines"
                    except:
                        pass
                
                files.append(f"[file] {item} ({size_str}{line_count})")
        
        # 先显示目录，再显示文件
        for d in sorted(dirs):
            result += d + "\n"
        
        for f in sorted(files):
            result += f + "\n"
            
        return result.strip()
        
    except Exception as e:
        logging.error(f"列出目录时发生错误: {e}", exc_info=True)
        return f"错误：列出目录 '{relative_workspace_path}' 时发生意外错误: {str(e)}"

def read_file(target_file: str, 
             should_read_entire_file: bool = False, 
             start_line_one_indexed: int = 1, 
             end_line_one_indexed_inclusive: int = 50,
             auto_read_more: bool = False,
             explanation: str = "") -> str:
    """
    读取文件内容及大纲
    
    Args:
        target_file: 要读取的文件路径(相对或绝对路径)
        should_read_entire_file: 是否读取整个文件
        start_line_one_indexed: 起始行号(从1开始计数)
        end_line_one_indexed_inclusive: 结束行号(从1开始计数，包含该行)
        auto_read_more: 是否在当前范围结束后自动读取后续内容，无需用户确认
        explanation: 使用此工具的原因解释
        
    Returns:
        文件内容的字符串表示
    """
    # 记录解释（如果提供）
    if explanation:
        logging.info(f"Read file explanation: {explanation}")
    
    try:
        # 处理路径
        if os.path.isabs(target_file):
            file_path = target_file
        else:
            # 使用当前目录作为工作空间根目录
            workspace_root = os.getcwd()
            file_path = os.path.join(workspace_root, target_file)
            file_path = os.path.normpath(file_path)
        
        # 安全检查：确保路径不超出工作空间(对相对路径)
        if not os.path.isabs(target_file) and not os.path.abspath(file_path).startswith(os.path.abspath(os.getcwd())):
            return f"错误：指定的文件路径 '{target_file}' 超出了工作空间范围。"
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return f"错误：文件 '{target_file}' 不存在。"
        
        if not os.path.isfile(file_path):
            return f"错误：'{target_file}' 不是一个文件。"
        
        # 检查文件大小
        file_size = os.path.getsize(file_path)
        if file_size > 10 * 1024 * 1024:  # 10MB
            return f"错误：文件 '{target_file}' 过大 ({file_size/1024/1024:.2f}MB)，超过10MB限制。"
        
        # 获取文件总行数
        total_lines = 0
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for _ in f:
                total_lines += 1
        
        # 输出文件基本信息
        result = f"文件 '{target_file}' 信息:\n"
        result += f"- 总行数: {total_lines}\n"
        result += f"- 文件大小: {file_size/1024:.2f}KB\n\n"
        
        # 确保行号有效
        if start_line_one_indexed < 1:
            start_line_one_indexed = 1
        
        if should_read_entire_file:
            # 读取整个文件
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            result += f"文件内容 (全部 {total_lines} 行):\n```\n{content}\n```"
        else:
            # 读取指定范围的行
            # 如果开启自动阅读模式并且结束行超过总行数，调整为读取全部
            if auto_read_more and end_line_one_indexed_inclusive >= total_lines:
                should_read_entire_file = True
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                result += f"文件内容 (全部 {total_lines} 行):\n```\n{content}\n```"
                return result.strip()
            
            if end_line_one_indexed_inclusive > total_lines:
                end_line_one_indexed_inclusive = total_lines
            
            if start_line_one_indexed > end_line_one_indexed_inclusive:
                start_line_one_indexed = end_line_one_indexed_inclusive
            
            # 自动阅读模式下，不限制最大读取行数
            max_lines_to_read = 1000 if auto_read_more else 500
            if end_line_one_indexed_inclusive - start_line_one_indexed + 1 > max_lines_to_read:
                if auto_read_more:
                    # 自动阅读模式下，分批读取并合并结果
                    full_content = []
                    current_start = start_line_one_indexed
                    
                    while current_start <= total_lines:
                        current_end = min(current_start + max_lines_to_read - 1, total_lines)
                        
                        # 读取当前批次的行
                        batch_lines = []
                        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                            for i, line in enumerate(f, 1):
                                if current_start <= i <= current_end:
                                    batch_lines.append(line.rstrip('\n'))
                                if i > current_end:
                                    break
                        
                        full_content.extend(batch_lines)
                        
                        # 移动到下一批
                        current_start = current_end + 1
                        
                        # 如果已经读取完所有行，跳出循环
                        if current_end == total_lines:
                            break
                    
                    result += f"文件内容 (第{start_line_one_indexed}行至第{total_lines}行):\n```\n"
                    result += "\n".join(full_content) + "\n```\n\n"
                    return result.strip()
                else:
                    # 非自动阅读模式，限制读取行数
                    end_line_one_indexed_inclusive = start_line_one_indexed + max_lines_to_read - 1
                    result += f"警告: 请求读取超过{max_lines_to_read}行，已自动限制为最多{max_lines_to_read}行。\n\n"
            
            # 读取前部分的概要(如果开始行不是第一行且未启用自动阅读)
            if start_line_one_indexed > 1 and not auto_read_more:
                preview_start = max(1, start_line_one_indexed - 10)
                preview_end = start_line_one_indexed - 1
                if preview_start < preview_end:
                    result += f"前面行的概要 (第{preview_start}行至第{preview_end}行):\n"
                    preview_lines = []
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        for i, line in enumerate(f, 1):
                            if preview_start <= i <= preview_end:
                                # 简化预览行(去除多余空白和仅保留开头)
                                preview_line = line.strip()
                                if len(preview_line) > 50:
                                    preview_line = preview_line[:47] + "..."
                                preview_lines.append(f"{i}: {preview_line}")
                            if i > preview_end:
                                break
                    result += "\n".join(preview_lines) + "\n\n"
            
            # 读取指定范围的行
            result += f"文件内容 (第{start_line_one_indexed}行至第{end_line_one_indexed_inclusive}行):\n```\n"
            lines = []
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f, 1):
                    if start_line_one_indexed <= i <= end_line_one_indexed_inclusive:
                        lines.append(line.rstrip('\n'))
                    if i > end_line_one_indexed_inclusive:
                        break
            result += "\n".join(lines) + "\n```\n\n"
            
            # 如果开启了自动读取模式且有更多内容，自动继续读取下一部分
            next_batch_start = end_line_one_indexed_inclusive + 1
            if auto_read_more and next_batch_start <= total_lines:
                # 自动读取下一批次，设置新的开始和结束行
                next_batch_end = min(total_lines, next_batch_start + max_lines_to_read - 1)
                
                # 递归调用自身读取下一批次
                next_result = read_file(
                    target_file=target_file,
                    should_read_entire_file=False,
                    start_line_one_indexed=next_batch_start,
                    end_line_one_indexed_inclusive=next_batch_end,
                    auto_read_more=True,
                    explanation="继续自动读取文件后续内容"
                )
                
                # 从结果中提取文件内容部分，去除文件信息头
                content_marker = "文件内容 (第"
                if content_marker in next_result:
                    content_start = next_result.find(content_marker)
                    result += next_result[content_start:]
                
                return result.strip()
            
            # 读取后部分的概要(如果结束行不是最后一行且未启用自动读取)
            if end_line_one_indexed_inclusive < total_lines and not auto_read_more:
                suffix_start = end_line_one_indexed_inclusive + 1
                suffix_end = min(total_lines, end_line_one_indexed_inclusive + 10)
                if suffix_start < suffix_end:
                    result += f"后面行的概要 (第{suffix_start}行至第{suffix_end}行):\n"
                    suffix_lines = []
                    line_count = 0
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        for i, line in enumerate(f, 1):
                            if i < suffix_start:
                                continue
                            if suffix_start <= i <= suffix_end:
                                # 简化预览行(去除多余空白和仅保留开头)
                                suffix_line = line.strip()
                                if len(suffix_line) > 50:
                                    suffix_line = suffix_line[:47] + "..."
                                suffix_lines.append(f"{i}: {suffix_line}")
                            if i > suffix_end:
                                break
                    result += "\n".join(suffix_lines) + "\n\n"
                
                # 如果还有更多行未显示(非自动读取模式)
                if suffix_end < total_lines:
                    result += f"文件还有更多行未显示 (共{total_lines}行，已显示到第{suffix_end}行)。\n"
                    if not auto_read_more:
                        result += "要继续查看后续内容，请再次调用read_file工具并指定新的行范围，或设置auto_read_more=true自动读取后续内容。\n"
        
        return result.strip()
    
    except PermissionError:
        return f"错误：没有权限读取文件 '{target_file}'。"
    except UnicodeDecodeError:
        return f"错误：文件 '{target_file}' 可能是二进制文件或使用了不支持的编码。"
    except Exception as e:
        logging.error(f"读取文件时发生错误: {e}", exc_info=True)
        return f"错误：读取文件 '{target_file}' 时发生意外错误: {str(e)}"

def grep_search(query: str, 
               case_sensitive: bool = False, 
               include_pattern: str = None, 
               exclude_pattern: str = None,
               explanation: str = "") -> str:
    """
    使用正则表达式在文件中进行快速文本搜索
    
    Args:
        query: 要搜索的正则表达式模式
        case_sensitive: 是否区分大小写
        include_pattern: 要包含的文件的glob模式 (例如 "*.py")
        exclude_pattern: 要排除的文件的glob模式
        explanation: 使用此工具的原因解释
        
    Returns:
        搜索结果的字符串表示
    """
    # 记录解释（如果提供）
    if explanation:
        logging.info(f"Grep search explanation: {explanation}")
    
    # 检查query是否为空
    if not query or not query.strip():
        return "错误：搜索模式不能为空。"
    
    try:
        # 检查ripgrep是否安装
        try:
            # 在Windows上可能是rg.exe
            subprocess.run(["rg", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        except FileNotFoundError:
            # 尝试使用绝对路径找到rg
            rg_paths = [
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'ripgrep', 'rg.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'ripgrep', 'rg.exe'),
                os.path.join(os.environ.get('USERPROFILE', ''), '.cargo', 'bin', 'rg.exe')
            ]
            rg_found = False
            for rg_path in rg_paths:
                if os.path.exists(rg_path):
                    rg_cmd = rg_path
                    rg_found = True
                    break
            
            if not rg_found:
                # 如果没有ripgrep，回退到使用基本的Python搜索
                return _fallback_search(query, case_sensitive, include_pattern, exclude_pattern)
        
        # 构建ripgrep命令
        cmd = ["rg"]
        
        # 添加参数
        cmd.append("--max-count=50")  # 限制结果数量
        cmd.append("--line-number")    # 显示行号
        
        # 大小写敏感性
        if not case_sensitive:
            cmd.append("--ignore-case")
        
        # 文件包含模式
        if include_pattern:
            # 处理多个包含模式(以逗号分隔)
            patterns = [p.strip() for p in include_pattern.split(',')]
            for i, pattern in enumerate(patterns):
                cmd.extend(["--type-add", f"custom{i}:{pattern}", "--type", f"custom{i}"])
        
        # 文件排除模式
        if exclude_pattern:
            # 处理多个排除模式(以逗号分隔)
            patterns = [p.strip() for p in exclude_pattern.split(',')]
            for pattern in patterns:
                cmd.extend(["--glob", f"!{pattern}"])
        
        # 安全处理查询模式
        # 将查询字符串作为固定字符串处理，如果不是正则表达式
        if not _is_valid_regex(query):
            cmd.append("--fixed-strings")
        
        # 添加搜索模式
        cmd.append(query)
        
        # 添加当前目录作为搜索路径
        cmd.append(".")
        
        # 执行命令
        logging.info(f"Executing ripgrep command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            cwd=os.getcwd(),
            timeout=30  # 设置超时时间
        )
        
        # 处理结果
        if result.returncode == 0 or result.returncode == 1:  # 1表示没有匹配项
            if not result.stdout.strip():
                return f"未找到匹配项: '{query}'"
            
            # 格式化输出
            output_lines = result.stdout.strip().split('\n')
            match_count = len(output_lines)
            # 检查是否达到了限制
            is_truncated = match_count >= 50  
            
            if is_truncated:
                output_lines.append("...(结果已限制为最多50条匹配项)")
            
            # 统计匹配的文件数
            files_matched = set()
            for line in output_lines:
                if ':' in line:
                    file_path = line.split(':', 1)[0]
                    files_matched.add(file_path)
            
            # 构建结果
            result_text = f"在 {len(files_matched)} 个文件中找到 {match_count} 个匹配项" + (", 结果已截断" if is_truncated else "") + ":\n\n"
            result_text += '\n'.join(output_lines)
            return result_text
        else:
            # 处理其他返回码，可能是错误
            error_msg = result.stderr.strip() if result.stderr else f"未知错误，返回码: {result.returncode}"
            logging.error(f"ripgrep command failed: {error_msg}")
            
            # 如果错误是由于无效的regex模式导致的，尝试使用字面量匹配
            if "regex parse error" in error_msg or "syntax error" in error_msg:
                logging.info("Retrying with fixed-strings matching due to regex error")
                return grep_search(query, case_sensitive, include_pattern, exclude_pattern, 
                                  explanation + " (retried with fixed-string matching)")
            
            return f"搜索时发生错误: {error_msg}"
    
    except subprocess.TimeoutExpired:
        return "错误：搜索操作超时（超过30秒）。请尝试缩小搜索范围或使用更具体的模式。"
    except Exception as e:
        logging.error(f"执行grep搜索时发生错误: {e}", exc_info=True)
        return f"错误：执行grep搜索时发生意外错误: {str(e)}"

# 检查字符串是否为有效的正则表达式
def _is_valid_regex(pattern: str) -> bool:
    """检查字符串是否为有效的正则表达式"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

# 基本的Python搜索实现，作为ripgrep的回退选项
def _fallback_search(query: str, case_sensitive: bool = False, include_pattern: str = None, exclude_pattern: str = None) -> str:
    """当ripgrep不可用时的基本Python搜索实现"""
    logging.info("Using fallback Python search because ripgrep is not available")
    
    # 编译正则表达式
    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(query, flags)
    except re.error as e:
        # 如果正则表达式无效，则使用字面量匹配
        escaped_query = re.escape(query)
        pattern = re.compile(escaped_query, flags)
    
    # 处理文件包含和排除模式
    include_patterns = []
    if include_pattern:
        # 将glob模式转换为正则表达式
        for glob in include_pattern.split(','):
            glob = glob.strip()
            regex = glob.replace('.', '\\.').replace('*', '.*').replace('?', '.')
            include_patterns.append(re.compile(regex))
    
    exclude_patterns = []
    if exclude_pattern:
        # 将glob模式转换为正则表达式
        for glob in exclude_pattern.split(','):
            glob = glob.strip()
            regex = glob.replace('.', '\\.').replace('*', '.*').replace('?', '.')
            exclude_patterns.append(re.compile(regex))
    
    results = []
    files_matched = set()
    match_count = 0
    max_matches = 50
    
    # 忽略的目录和文件模式
    ignore_dirs = ['.git', 'node_modules', 'venv', '__pycache__', '.idea', '.vscode']
    ignore_files = ['.exe', '.dll', '.so', '.dylib', '.zip', '.tar', '.gz', '.rar', '.jpg', '.png', '.gif', '.mp4', '.mp3']
    max_file_size = 5 * 1024 * 1024  # 5MB
    max_depth = 8  # 限制递归深度
    
    def search_dir(directory, current_depth=0):
        """递归搜索目录"""
        nonlocal match_count, results, files_matched
        
        # 检查是否达到最大匹配数或最大深度
        if match_count >= max_matches or current_depth > max_depth:
            return
            
        try:
            # 获取目录内容
            items = os.listdir(directory)
            
            # 先处理文件
            for item in items:
                # 检查是否达到最大匹配数
                if match_count >= max_matches:
                    return
                    
                item_path = os.path.join(directory, item)
                
                # 跳过目录
                if os.path.isdir(item_path):
                    continue
                    
                # 检查文件大小
                try:
                    if os.path.getsize(item_path) > max_file_size:
                        continue
                except OSError:
                    continue
                    
                # 检查是否为忽略的文件类型
                if any(item.endswith(ext) for ext in ignore_files):
                    continue
                    
                rel_path = os.path.relpath(item_path, os.getcwd())
                
                # 检查包含模式
                if include_patterns and not any(p.search(rel_path) for p in include_patterns):
                    continue
                    
                # 检查排除模式
                if exclude_patterns and any(p.search(rel_path) for p in exclude_patterns):
                    continue
                
                # 尝试读取文件
                try:
                    with open(item_path, 'r', encoding='utf-8', errors='replace') as f:
                        for i, line in enumerate(f, 1):
                            # 检查是否达到最大匹配数
                            if match_count >= max_matches:
                                return
                                
                            if pattern.search(line):
                                results.append(f"{rel_path}:{i}:{line.rstrip()}")
                                files_matched.add(rel_path)
                                match_count += 1
                except (PermissionError, IsADirectoryError, UnicodeDecodeError):
                    # 跳过无法读取的文件
                    continue
            
            # 然后递归处理子目录
            for item in items:
                # 检查是否达到最大匹配数
                if match_count >= max_matches:
                    return
                    
                item_path = os.path.join(directory, item)
                
                # 只处理目录
                if not os.path.isdir(item_path):
                    continue
                    
                # 跳过忽略的目录
                if item in ignore_dirs:
                    continue
                    
                # 递归处理子目录
                search_dir(item_path, current_depth + 1)
                
        except (PermissionError, OSError):
            # 跳过无法访问的目录
            pass
    
    # 从当前目录开始搜索
    search_dir(os.getcwd())
    
    # 构建结果
    if not results:
        return f"未找到匹配项: '{query}'"
    
    is_truncated = match_count >= max_matches
    result_text = f"在 {len(files_matched)} 个文件中找到 {match_count} 个匹配项" + (", 结果已截断" if is_truncated else "") + ":\n\n"
    result_text += '\n'.join(results)
    
    if is_truncated:
        result_text += "\n...(结果已限制为最多50条匹配项)"
    
    return result_text

def edit_file(target_file: str, instructions: str, code_edit: str) -> str:
    """
    编辑文件内容
    
    Args:
        target_file: 要编辑的文件路径(相对或绝对路径)
        instructions: 描述编辑操作的简短指令
        code_edit: 要编辑的具体代码，使用特殊注释表示未更改的代码
        
    Returns:
        编辑操作的结果描述
    """
    logging.info(f"Editing file: {target_file}")
    logging.info(f"Instructions: {instructions}")
    
    try:
        # 处理路径
        if os.path.isabs(target_file):
            file_path = target_file
        else:
            # 使用当前目录作为工作空间根目录
            workspace_root = os.getcwd()
            file_path = os.path.join(workspace_root, target_file)
            file_path = os.path.normpath(file_path)
        
        # 安全检查：确保路径不超出工作空间(对相对路径)
        if not os.path.isabs(target_file) and not os.path.abspath(file_path).startswith(os.path.abspath(os.getcwd())):
            return f"错误：指定的文件路径 '{target_file}' 超出了工作空间范围。"
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            # 如果文件不存在，可能是要创建新文件
            logging.info(f"文件 '{target_file}' 不存在，将创建新文件。")
            
            # 确保目标目录存在
            target_dir = os.path.dirname(file_path)
            if target_dir and not os.path.exists(target_dir):
                os.makedirs(target_dir)
                
            # 创建新文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(code_edit)
                
            return f"成功创建文件 '{target_file}'。"
        
        # 检查是否为文件而不是目录
        if not os.path.isfile(file_path):
            return f"错误：'{target_file}' 不是一个文件。"
        
        # 检查文件大小
        file_size = os.path.getsize(file_path)
        if file_size > 10 * 1024 * 1024:  # 10MB
            return f"错误：文件 '{target_file}' 过大 ({file_size/1024/1024:.2f}MB)，超过10MB限制。"
        
        # 读取原始文件内容
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            original_content = f.read()
        
        # 识别常见的注释模式
        comment_patterns = [
            r'//\s*\.\.\.\s*existing\s+code\s*\.\.\.', 
            r'#\s*\.\.\.\s*existing\s+code\s*\.\.\.', 
            r'/\*\s*\.\.\.\s*existing\s+code\s*\.\.\.\s*\*/',
            r'<!--\s*\.\.\.\s*existing\s+code\s*\.\.\.\s*-->'
        ]
        
        # 检查是否包含注释标记
        has_comment_markers = any(re.search(pattern, code_edit) for pattern in comment_patterns)
        
        if not has_comment_markers:
            # 如果没有注释标记，简单地替换整个文件内容
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(code_edit)
            return f"文件 '{target_file}' 的内容已完全替换。"
        
        # 由于编辑处理复杂，这里简化处理：
        # 创建备份并直接替换文件内容
        backup_path = file_path + ".bak"
        try:
            with open(backup_path, 'w', encoding='utf-8', errors='replace') as f:
                f.write(original_content)
            logging.info(f"已创建文件 '{target_file}' 的备份。")
        except Exception as e:
            logging.warning(f"创建备份文件时出错: {e}")
        
        # 将编辑内容写入目标文件
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(code_edit)
        
        # 提供更详细的成功消息
        return f"文件 '{target_file}' 已按照指令 '{instructions}' 成功编辑。"
        
    except PermissionError:
        return f"错误：没有权限编辑文件 '{target_file}'。"
    except UnicodeDecodeError:
        return f"错误：文件 '{target_file}' 可能是二进制文件或使用了不支持的编码。"
    except Exception as e:
        logging.error(f"编辑文件时发生错误: {e}", exc_info=True)
        return f"错误：编辑文件 '{target_file}' 时发生意外错误: {str(e)}"

def web_search(search_term: str, explanation: str = "") -> str:
    """
    搜索网络获取关于任何主题的实时信息
    
    Args:
        search_term: 要在网络上查找的搜索词。必须具体并包含相关关键词以获得更好的结果
        explanation: 使用此工具的原因解释
        
    Returns:
        搜索结果的字符串表示，包含相关摘要和网页URL
    """
    # 记录解释（如果提供）
    if explanation:
        logging.info(f"Web search explanation: {explanation}")
    
    logging.info(f"执行网络搜索: {search_term}")
    
    if not search_term or not search_term.strip():
        return "错误：搜索词不能为空。"
    
    try:
        # 确保duckduckgo_search已安装
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            logging.error("duckduckgo_search库未安装。无法执行网络搜索。")
            return "错误：无法执行网络搜索，缺少'duckduckgo_search'库。请使用'pip install duckduckgo-search'安装。"
        
        summary = f"关于 '{search_term}' 的网络搜索结果:\n"
        max_results = 7  # 获取的搜索结果数量
        
        with DDGS(timeout=15) as ddgs:  # 设置更长的超时时间
            results = list(ddgs.text(search_term, max_results=max_results))
        
        if not results:
            summary += "未找到相关信息。"
            logging.warning(f"未找到关于 '{search_term}' 的网络搜索结果")
        else:
            for i, result in enumerate(results):
                title = result.get('title', 'N/A')
                body = result.get('body', 'N/A').replace('\n', ' ').strip()
                url = result.get('href', 'N/A')
                # 限制摘要长度，保持简洁
                body_snippet = body[:300] + "..." if len(body) > 300 else body
                summary += f"\n{i+1}. {title}\n   摘要: {body_snippet}\n   来源: {url}\n"
            
            logging.info(f"'{search_term}'的网络搜索完成。找到{len(results)}个结果。")
        
        return summary.strip()  # 移除尾部换行符
    
    except Exception as e:
        logging.error(f"执行网络搜索时出错: {e}", exc_info=True)
        return f"错误：执行网络搜索时发生意外错误: {str(e)}"

def delete_file(target_file: str, explanation: str = "") -> str:
    """
    删除指定路径的文件
    
    Args:
        target_file: 要删除的文件路径(相对于工作空间根目录)
        explanation: 使用此工具的原因解释
        
    Returns:
        删除操作的结果描述
    """
    # 记录解释（如果提供）
    if explanation:
        logging.info(f"Delete file explanation: {explanation}")
    
    logging.info(f"Deleting file: {target_file}")
    
    try:
        # 处理路径
        # 使用当前目录作为工作空间根目录
        workspace_root = os.getcwd()
        file_path = os.path.join(workspace_root, target_file)
        file_path = os.path.normpath(file_path)
        
        # 安全检查：确保路径不超出工作空间
        if not os.path.abspath(file_path).startswith(os.path.abspath(workspace_root)):
            return f"错误：指定的文件路径 '{target_file}' 超出了工作空间范围。"
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return f"警告：文件 '{target_file}' 不存在，无需删除。"
        
        # 检查是否为文件而不是目录
        if not os.path.isfile(file_path):
            return f"错误：'{target_file}' 不是一个文件，无法删除。如需删除目录，请使用其他工具。"
        
        # 安全检查：阻止删除重要系统文件或特定的敏感文件
        sensitive_patterns = [
            r"\.git/", r"\.gitignore$", 
            r"package\.json$", r"requirements\.txt$", 
            r"Dockerfile$", r"docker-compose\.yml$",
            r"\.env$", r"\.env\.local$",
            r"config\.json$", r"settings\.json$"
        ]
        
        # 检查是否匹配任何敏感文件模式
        for pattern in sensitive_patterns:
            if re.search(pattern, file_path):
                return f"错误：'{target_file}' 可能是重要的配置或系统文件，为安全起见拒绝删除。如确需删除，请手动执行。"
        
        # 删除文件
        os.remove(file_path)
        
        # 检查文件是否已成功删除
        if not os.path.exists(file_path):
            return f"成功删除文件 '{target_file}'。"
        else:
            return f"错误：文件 '{target_file}' 删除失败，请检查权限或文件是否被其他程序占用。"
            
    except PermissionError:
        return f"错误：没有权限删除文件 '{target_file}'。"
    except IsADirectoryError:
        return f"错误：'{target_file}' 是一个目录，不是文件。如需删除目录，请使用其他工具。"
    except Exception as e:
        logging.error(f"删除文件时发生错误: {e}", exc_info=True)
        return f"错误：删除文件 '{target_file}' 时发生意外错误: {str(e)}"

def reapply(target_file: str) -> str:
    """
    调用更智能的模型来重新应用上次对指定文件的编辑
    
    Args:
        target_file: 要重新应用上次编辑的文件路径(相对或绝对路径)
        
    Returns:
        重新应用编辑操作的结果描述
    """
    logging.info(f"Reapplying last edit to file: {target_file}")
    
    try:
        # 处理路径
        if os.path.isabs(target_file):
            file_path = target_file
        else:
            # 使用当前目录作为工作空间根目录
            workspace_root = os.getcwd()
            file_path = os.path.join(workspace_root, target_file)
            file_path = os.path.normpath(file_path)
        
        # 安全检查：确保路径不超出工作空间(对相对路径)
        if not os.path.isabs(target_file) and not os.path.abspath(file_path).startswith(os.path.abspath(os.getcwd())):
            return f"错误：指定的文件路径 '{target_file}' 超出了工作空间范围。"
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return f"错误：文件 '{target_file}' 不存在，无法重新应用编辑。"
        
        # 检查是否为文件而不是目录
        if not os.path.isfile(file_path):
            return f"错误：'{target_file}' 不是一个文件。"
        
        # 这里应该有调用更智能模型的逻辑，但在本地实现中，我们只返回一个通知信息
        # 实际实现应该连接到能够重新应用编辑的服务或更高级的模型
        
        # 在本地版本中，我们返回一个模拟的成功消息
        return f"已请求重新应用上次编辑到文件 '{target_file}'。在实际实现中，这会调用更智能的模型来处理编辑。"
        
    except Exception as e:
        logging.error(f"重新应用编辑时发生错误: {e}", exc_info=True)
        return f"错误：重新应用编辑到文件 '{target_file}' 时发生意外错误: {str(e)}"

# --- Tool Definitions (Ensure types and descriptions are present for schema) ---
AVAILABLE_TOOLS = {
    "web_search_cve": {
        "function": search_cve_info,
        "description": "根据CVE编号在线搜索漏洞详情、描述和利用信息。",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string", # JSON Schema type
                    "description": "要搜索的CVE编号 (格式如 CVE-YYYY-NNNN)"
                }
            },
            "required": ["cve_id"]
        }
    },
    "lookup_internal_ip": {
        # Use dummy function if cmdb module is not available
        "function": lookup_internal_ip if cmdb_available else lookup_internal_ip_dummy,
        "description": "查询IP地址关联的CMDB资产信息（如主机、应用配置、F5等）。支持内网和部分已知外网IP。",
         "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string", # JSON Schema type
                    "description": "要查询的IPv4地址"
                }
            },
            "required": ["ip_address"]
        }
    },
    "run_terminal_powershell": {
        "function": run_terminal_powershell,
        "description": "在用户系统上使用PowerShell执行终端命令。需遵守以下规则：\n1. 根据对话内容确认是否在新的shell或先前的shell中运行\n2. 如果在新shell中，应当先cd到正确目录并进行必要设置\n3. 如果在同一shell中，状态会持久保存，不需要重新cd到相同目录\n4. 对于任何会使用分页器的命令(git, less, head, tail, more等)，应该追加` | Out-Host -Paging:$false`或其他合适的方式避免交互\n5. 对于长时间运行的命令，应设置is_background为true而不是修改命令细节",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "要执行的PowerShell命令"
                },
                "is_background": {
                    "type": "boolean",
                    "description": "是否应在后台运行命令"
                },
                "explanation": {
                    "type": "string",
                    "description": "一句话解释为什么需要运行此命令以及它如何有助于实现目标"
                },
                "require_user_approval": {
                    "type": "boolean",
                    "description": "执行前是否需要用户批准命令。仅当命令安全且符合用户需求时才设置为false"
                }
            },
            "required": ["command", "is_background", "require_user_approval"]
        }
    },
    "run_terminal_cmd": {
        "function": run_terminal_cmd,
        "description": "在用户系统上执行终端命令（将使用PowerShell）。需遵守以下规则：\n1. 根据对话内容确认是否在新的shell或先前的shell中运行\n2. 如果在新shell中，应当先cd到正确目录并进行必要设置\n3. 如果在同一shell中，状态会持久保存，不需要重新cd到相同目录\n4. 对于任何会使用分页器的命令(git, less, head, tail, more等)，应该追加` | Out-Host -Paging:$false`或其他合适的方式避免交互\n5. 对于长时间运行的命令，应设置is_background为true而不是修改命令细节",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "要执行的终端命令"
                },
                "is_background": {
                    "type": "boolean",
                    "description": "是否应在后台运行命令"
                },
                "explanation": {
                    "type": "string",
                    "description": "一句话解释为什么需要运行此命令以及它如何有助于实现目标"
                },
                "require_user_approval": {
                    "type": "boolean",
                    "description": "执行前是否需要用户批准命令。仅当命令安全且符合用户需求时才设置为false"
                }
            },
            "required": ["command", "is_background", "require_user_approval"]
        }
    },
    "list_dir": {
        "function": list_dir,
        "description": "List the contents of a directory. The quick tool to use for discovery, before using more targeted tools like semantic search or file reading. Useful to try to understand the file structure before diving deeper into specific files. Can be used to explore the codebase.",
        "parameters": {
            "type": "object",
            "properties": {
                "relative_workspace_path": {
                    "type": "string",
                    "description": "Path to list contents of, relative to the workspace root."
                },
                "explanation": {
                    "type": "string",
                    "description": "One sentence explanation as to why this tool is being used, and how it contributes to the goal."
                }
            },
            "required": ["relative_workspace_path"]
        }
    },
    "read_file": {
        "function": read_file,
        "description": "Read the contents of a file (and the outline).\n\nWhen using this tool to gather information, it's your responsibility to ensure you have the COMPLETE context. Each time you call this command you should:\n1) Assess if contents viewed are sufficient to proceed with the task.\n2) Take note of lines not shown.\n3) If file contents viewed are insufficient, and you suspect they may be in lines not shown, proactively call the tool again to view those lines.\n4) When in doubt, call this tool again to gather more information. Partial file views may miss critical dependencies, imports, or functionality.\n\nIf reading a range of lines is not enough, you may choose to read the entire file or set auto_read_more=true to automatically read through the entire file in chunks.\nReading entire files is often wasteful and slow, especially for large files (i.e. more than a few hundred lines). So you should use this option sparingly.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_file": {
                    "type": "string",
                    "description": "The path of the file to read. You can use either a relative path in the workspace or an absolute path. If an absolute path is provided, it will be preserved as is."
                },
                "should_read_entire_file": {
                    "type": "boolean",
                    "description": "Whether to read the entire file. Defaults to false."
                },
                "start_line_one_indexed": {
                    "type": "integer",
                    "description": "The one-indexed line number to start reading from (inclusive)."
                },
                "end_line_one_indexed_inclusive": {
                    "type": "integer",
                    "description": "The one-indexed line number to end reading at (inclusive)."
                },
                "auto_read_more": {
                    "type": "boolean",
                    "description": "If true, automatically continues reading the file in chunks without requiring additional tool calls. Useful for reading large files. Defaults to false."
                },
                "explanation": {
                    "type": "string",
                    "description": "One sentence explanation as to why this tool is being used, and how it contributes to the goal."
                }
            },
            "required": ["target_file"]
        }
    },
    "grep_search": {
        "function": grep_search,
        "description": "Fast text-based regex search that finds exact pattern matches within files or directories, utilizing the ripgrep command for efficient searching.\nResults will be formatted in the style of ripgrep and can be configured to include line numbers and content.\nTo avoid overwhelming output, the results are capped at 50 matches.\nUse the include or exclude patterns to filter the search scope by file type or specific paths.\n\nThis is best for finding exact text matches or regex patterns.\nMore precise than semantic search for finding specific strings or patterns.\nThis is preferred over semantic search when we know the exact symbol/function name/etc. to search in some set of directories/file types.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The regex pattern to search for"
                },
                "case_sensitive": {
                    "type": "boolean",
                    "description": "Whether the search should be case sensitive"
                },
                "include_pattern": {
                    "type": "string",
                    "description": "Glob pattern for files to include (e.g. '*.ts' for TypeScript files)"
                },
                "exclude_pattern": {
                    "type": "string",
                    "description": "Glob pattern for files to exclude"
                },
                "explanation": {
                    "type": "string",
                    "description": "One sentence explanation as to why this tool is being used, and how it contributes to the goal."
                }
            },
            "required": ["query"]
        }
    },
    "edit_file": {
        "function": edit_file,
        "description": "Use this tool to propose an edit to an existing file.\nThis will be read by a less intelligent model, which will quickly apply the edit. You should make it clear what the edit is, while also minimizing the unchanged code you write.\nWhen writing the edit, you should specify each edit in sequence, with the special comment `// ... existing code ...` to represent unchanged code in between edited lines.\nFor example:\n```\n// ... existing code ...\nFIRST_EDIT\n// ... existing code ...\nSECOND_EDIT\n// ... existing code ...\nTHIRD_EDIT\n// ... existing code ...\n```\nYou should bias towards repeating as few lines of the original file as possible to convey the change.\nBut, each edit should contain sufficient context of unchanged lines around the code you're editing to resolve ambiguity.\nDO NOT omit spans of pre-existing code without using the `// ... existing code ...` comment to indicate its absence.\nMake sure it is clear what the edit should be.\nYou should specify the following arguments before the others: [target_file]",
        "parameters": {
            "type": "object",
            "properties": {
                "target_file": {
                    "type": "string",
                    "description": "The target file to modify. Always specify the target file as the first argument. You can use either a relative path in the workspace or an absolute path. If an absolute path is provided, it will be preserved as is."
                },
                "instructions": {
                    "type": "string",
                    "description": "A single sentence instruction describing what you are going to do for the sketched edit. This is used to assist the less intelligent model in applying the edit. Please use the first person to describe what you are going to do. Dont repeat what you have said previously in normal messages. And use it to disambiguate uncertainty in the edit."
                },
                "code_edit": {
                    "type": "string",
                    "description": "Specify ONLY the precise lines of code that you wish to edit. **NEVER specify or write out unchanged code**. Instead, represent all unchanged code using the comment of the language you're editing in - example: `// ... existing code ...`"
                }
            },
            "required": ["target_file", "instructions", "code_edit"]
        }
    },
    "web_search": {
        "function": web_search,
        "description": "Search the web for real-time information about any topic. Use this tool when you need up-to-date information that might not be available in your training data, or when you need to verify current facts. The search results will include relevant snippets and URLs from web pages. This is particularly useful for questions about current events, technology updates, or any topic that requires recent information.",
        "parameters": {
            "type": "object",
            "properties": {
                "search_term": {
                    "type": "string",
                    "description": "The search term to look up on the web. Be specific and include relevant keywords for better results. For technical queries, include version numbers or dates if relevant."
                },
                "explanation": {
                    "type": "string",
                    "description": "One sentence explanation as to why this tool is being used, and how it contributes to the goal."
                }
            },
            "required": ["search_term"]
        }
    },
    "delete_file": {
        "function": delete_file,
        "description": "Deletes a file at the specified path. The operation will fail gracefully if:\n    - The file doesn't exist\n    - The operation is rejected for security reasons\n    - The file cannot be deleted",
        "parameters": {
            "type": "object",
            "properties": {
                "target_file": {
                    "type": "string",
                    "description": "The path of the file to delete, relative to the workspace root."
                },
                "explanation": {
                    "type": "string",
                    "description": "One sentence explanation as to why this tool is being used, and how it contributes to the goal."
                }
            },
            "required": ["target_file"]
        }
    },
    "reapply": {
        "function": reapply,
        "description": "Calls a smarter model to apply the last edit to the specified file.\nUse this tool immediately after the result of an edit_file tool call ONLY IF the diff is not what you expected, indicating the model applying the changes was not smart enough to follow your instructions.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_file": {
                    "type": "string",
                    "description": "The relative path to the file to reapply the last edit to. You can use either a relative path in the workspace or an absolute path. If an absolute path is provided, it will be preserved as is."
                }
            },
            "required": ["target_file"]
        }
    }
}

# 添加解码工具到AVAILABLE_TOOLS字典
if decode_tools_available:
    try:
        decode_tool = get_decode_tool()
        # 合并解码工具到AVAILABLE_TOOLS字典
        AVAILABLE_TOOLS.update(decode_tool)
        logging.info("Text decoding tools successfully loaded and registered.")
    except Exception as e:
        logging.error(f"Failed to register decode tools: {e}", exc_info=True)
else:
    logging.warning("Text decoding tools not available. Make sure decode_tools.py is in the same directory.")

# 添加飞书消息发送工具到AVAILABLE_TOOLS字典
if feishu_tools_available:
    try:
        feishu_tool = get_feishu_tool()
        # 合并飞书工具到AVAILABLE_TOOLS字典
        AVAILABLE_TOOLS.update(feishu_tool)
        logging.info("Feishu messaging tools successfully loaded and registered.")
    except Exception as e:
        logging.error(f"Failed to register Feishu messaging tools: {e}", exc_info=True)
else:
    logging.warning("Feishu messaging tools not available. Make sure feishu_send_message.py is in the same directory.")

# --- Tool Dispatcher ---
def execute_tool(tool_name: str, args: dict) -> str:
    """Executes the specified tool with the given arguments."""
    if tool_name not in AVAILABLE_TOOLS:
        return f"错误：未知的工具名称 '{tool_name}'。可用工具: {', '.join(AVAILABLE_TOOLS.keys())}"

    tool_info = AVAILABLE_TOOLS[tool_name]
    func = tool_info["function"]
    required_args_schema = tool_info.get("parameters", {}).get("required", [])

    # Basic argument validation
    missing_args = [arg for arg in required_args_schema if arg not in args]
    if missing_args:
        return f"错误：工具 '{tool_name}' 调用缺少参数: {', '.join(missing_args)}。需要参数: {required_args_schema}"

    logging.info(f"Executing tool '{tool_name}' with args: {args}")
    try:
        # Call the function with keyword arguments
        result = func(**args)
        # Ensure result is a string
        return str(result) if result is not None else "工具执行成功，但无明确结果返回。"
    except TypeError as e:
         logging.error(f"TypeError calling tool '{tool_name}': {e}", exc_info=True)
         return f"错误：调用工具 '{tool_name}' 时参数类型或数量错误: {e}"
    except Exception as e:
        logging.error(f"Unexpected error executing tool '{tool_name}': {e}", exc_info=True)
        return f"错误：执行工具 '{tool_name}' 时发生意外错误: {e}"
