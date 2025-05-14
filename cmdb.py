#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ipaddress # Moved import to top
from dotenv import find_dotenv, load_dotenv
import requests
import logging # Added logging
import json # 添加json导入，之前缺失

# --- Configuration and Setup ---

# Try to find .env file relative to this script OR potentially parent dirs
# This makes it slightly more robust when imported
dotenv_path = find_dotenv(filename=".env", raise_error_if_not_found=False)
if not dotenv_path:
    # Fallback: Check one level up from the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    dotenv_path_alt = os.path.join(parent_dir, ".env")
    if os.path.exists(dotenv_path_alt):
        dotenv_path = dotenv_path_alt

if dotenv_path:
    logging.info(f"Loading environment variables from: {dotenv_path}")
    load_dotenv(dotenv_path)
else:
    logging.warning("'.env' file not found. CMDB functions might fail if authKey is needed.")

# Get Auth Key - Ensure it's retrieved, handle missing case
IPASS_AUTHKEY = os.getenv("IPASS_AUTHKEY")
if not IPASS_AUTHKEY:
    logging.warning("IPASS_AUTHKEY not found in environment variables.")
    # Decide on fallback: raise error, use None, use empty string?
    # Using None might be safer to indicate failure clearly later.
    IPASS_AUTHKEY = None

# Common Headers (if needed globally, otherwise pass specifically)
# Headers might vary per request, better to define them within functions if needed
# COMMON_HEADERS = { "authKey": IPASS_AUTHKEY } if IPASS_AUTHKEY else {}

# --- Constants ---
# Define URLs and API keys as constants for clarity and easier updates
CMDB_BASE_URL = os.getenv("CMDB_BASE_URL", "https://cmdb.example.com")  # 请在环境变量中设置CMDB_BASE_URL或直接修改此处
CMDB_API_KEY = os.getenv("CMDB_API_KEY", "")  # 请在环境变量中设置CMDB_API_KEY或直接修改此处
DESKTOP_IP_URL_TEMPLATE = os.getenv("DESKTOP_IP_URL_TEMPLATE", "https://cmdb-auto.example.com/api/v1/automation/desktop-ips/{}?apikey=") + os.getenv("DESKTOP_API_KEY", "")  # 请设置环境变量
STORE_QUERY_URL = f"{CMDB_BASE_URL}/store/openapi/v2/resources/query?apikey={CMDB_API_KEY}" 
RELATIONS_URL_TEMPLATE = f"{CMDB_BASE_URL}/cmdb/api/v3/ci/histories/relations/cis/get?apikey={CMDB_API_KEY}" 
USER_URL_TEMPLATE = f"{CMDB_BASE_URL}/tenant/openapi/v2/users/get?apikey={CMDB_API_KEY}" 

# --- Helper Functions ---

def is_internal_ip(ip):
    """判断是否为内部IP地址"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError: # Catch specific error for invalid IP format
        logging.warning(f"Invalid IP address format for internal check: {ip}")
        return False
    except Exception as e: # Catch other potential errors
        logging.error(f"Error checking internal IP status for {ip}: {e}")
        return False

def _make_cmdb_request(url, method="GET", json_data=None, headers=None, timeout=15):
    """Makes a request to a CMDB endpoint with error handling."""
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=timeout, verify=False) # Added verify=False if needed for internal HTTPS
        elif method.upper() == "POST":
            response = requests.post(url, json=json_data, headers=headers, timeout=timeout, verify=False)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # Handle potentially empty response body which causes req.json() to fail
        if response.text:
             return response.json()
        else:
             logging.warning(f"Empty response body received from URL: {url}")
             return None # Return None for empty responses

    except requests.exceptions.Timeout:
        logging.error(f"Request timed out for URL: {url}")
        raise TimeoutError(f"CMDB请求超时: {url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for URL {url}: {e}", exc_info=True)
        raise ConnectionError(f"CMDB请求失败 ({url}): {e}")
    except json.JSONDecodeError as e:
         logging.error(f"Failed to decode JSON response from {url}: {e} - Response text: {response.text[:200]}")
         raise ValueError(f"CMDB响应格式错误 (非JSON): {url}")
    except Exception as e:
         logging.error(f"An unexpected error occurred during CMDB request to {url}: {e}", exc_info=True)
         raise RuntimeError(f"CMDB请求时发生未知错误 ({url}): {e}")


# --- Core Query Functions (Refactored for clarity) ---

def queryF5PoolIdsByF5VSId(F5VSId):
    """根据F5VSId查询F5池Id列表"""
    url = f"{RELATIONS_URL_TEMPLATE}&pageSize=300&pageNum=1&targetClassCode=F5Pool&ciId={F5VSId}&typeCode=Links&isTemplate=false&fields=state_available%2Cstate_alert"
    try:
        data = _make_cmdb_request(url)
        if data and "dataList" in data:
            ids = [item["id"] for item in data["dataList"] if "id" in item]
            logging.info(f"Found {len(ids)} Pool IDs for F5VS ID {F5VSId}")
            return ids
        else:
            logging.warning(f"No dataList found for F5VS ID {F5VSId}")
            return []
    except Exception as e:
        logging.error(f"Error in queryF5PoolIdsByF5VSId for {F5VSId}: {e}")
        return [] # Return empty list on error

def queryOutPoolMembersByF5PoolId(F5PoolId):
    """根据F5池Id查询服务池成员"""
    url = f"{RELATIONS_URL_TEMPLATE}&pageSize=300&pageNum=1&targetClassCode=OutPoolMember&ciId={F5PoolId}&typeCode=Contains&isTemplate=false&fields=state_available%2Cstate_alert,ip,port" # Added ip, port fields
    try:
        data = _make_cmdb_request(url)
        members = []
        if data and "dataList" in data:
            for item in data["dataList"]:
                # Ensure ip and port exist
                ip = item.get("ip")
                port = item.get("port")
                if ip and port is not None: # Port could be 0
                    members.append(f"{ip}:{port}")
                else:
                     logging.warning(f"Missing ip or port for pool member in F5Pool ID {F5PoolId}: {item.get('id', 'N/A')}")
            logging.info(f"Found {len(members)} members for F5Pool ID {F5PoolId}")
        else:
             logging.warning(f"No dataList found for F5Pool ID {F5PoolId}")
        return members
    except Exception as e:
        logging.error(f"Error in queryOutPoolMembersByF5PoolId for {F5PoolId}: {e}")
        return []

def queryVIPByPoolMemberId(memberId):
    """根据F5服务池成员Id查询其F5VS的VIP"""
    url = f"{RELATIONS_URL_TEMPLATE}&pageSize=300&pageNum=1&ciId={memberId}" # Query relations for the member
    try:
        data = _make_cmdb_request(url)
        pools = []
        if data and "dataList" in data:
            for item in data["dataList"]:
                if item.get("classCode") == "F5Pool" and "id" in item:
                    # For each pool the member belongs to, find the VIPs associated with that pool
                    logging.debug(f"Member {memberId} found in Pool {item['id']}, querying VIPs for pool...")
                    pools.extend(queryVIPByPoolId(item["id"]))
                # else: Class is not F5Pool or ID missing
            # Remove duplicates that might arise if member is in multiple pools leading to same VS
            unique_pools = sorted(list(set(pools)))
            logging.info(f"Found {len(unique_pools)} unique VIPs for Member ID {memberId}")
            return unique_pools
        else:
            logging.warning(f"No relations found for Member ID {memberId}")
            return []
    except Exception as e:
        logging.error(f"Error in queryVIPByPoolMemberId for {memberId}: {e}")
        return []


def queryVIPByPoolId(poolId):
    """根据F5服务池Id查询其F5VS的VIP"""
    url = f"{RELATIONS_URL_TEMPLATE}&pageSize=300&pageNum=1&ciId={poolId}" # Query relations for the pool
    try:
        data = _make_cmdb_request(url)
        vips = []
        if data and "dataList" in data:
            for item in data["dataList"]:
                # Check if the related item is an F5VS
                if item.get("classCode") == "F5VS":
                    ip = item.get("ip")
                    port = item.get("port")
                    if ip and port is not None:
                        vips.append(f"{ip}:{port}")
                    else:
                         logging.warning(f"F5VS related to Pool {poolId} missing ip or port: {item.get('id', 'N/A')}")
            logging.info(f"Found {len(vips)} VIPs for Pool ID {poolId}")
        else:
             logging.warning(f"No relations found for Pool ID {poolId}")
        return vips
    except Exception as e:
        logging.error(f"Error in queryVIPByPoolId for {poolId}: {e}")
        return []


def queryUserById(userId=""):
    """根据用户ID查询用户真实姓名/账号"""
    if not userId: return ""
    url = USER_URL_TEMPLATE + f"&user_id={userId}"
    try:
        data = _make_cmdb_request(url)
        # Check if response is valid and contains expected fields
        if data and "realname" in data and "account" in data:
            return f"{data['realname']}/{data['account']}"
        else:
            logging.warning(f"Could not find user details for ID {userId}. Response: {data}")
            return ""
    except Exception as e:
        logging.error(f"Error in queryUserById for {userId}: {e}")
        return ""


def queryDesktopIpInfo(ip=""):
    """查询桌面云IP信息"""
    if not ip: return ""
    url = DESKTOP_IP_URL_TEMPLATE.format(ip)
    # Define specific headers if needed, otherwise defaults might work
    headers = { "User-Agent": "SecAI-Tool/1.0" }
    try:
        data = _make_cmdb_request(url, headers=headers)
        info = ""
        if data and "result" in data and isinstance(data["result"], dict):
            i = data["result"]
            # Use .get() with defaults for safety
            info = "桌面云: IP:{}, 域:{}, 用户/组:{}, 主机名:{}, OS:{}, 状态:{}".format(
                i.get("ip", "N/A"),
                i.get("domain", "N/A"),
                i.get("user_or_group_name", "N/A"),
                i.get("computer_name", "N/A"),
                i.get("os_type", "N/A"),
                i.get("instance_state", "N/A")
            )
            logging.info(f"Found Desktop IP info for {ip}")
        else:
             logging.info(f"No Desktop IP info found for {ip} or invalid response format.")
        return info
    except Exception as e:
        logging.error(f"Error querying Desktop IP info for {ip}: {e}")
        return "" # Return empty on error


def queryExternalIpInfo(ip=""):
    """查询外网IP应用端口发布配置信息"""
    if not ip: return ""
    data_payload = {
        "needCount": 1,
        "conditions": [
            { "field": "classCode", "value": "app_port_config", "operator": "EQ" },
            { "field": "outerNetAddr", "value": ip, "operator": "EQ" }
        ],
        "pageSize": 300,
        "pageNum": 0 # API uses 0-based pageNum
    }
    try:
        data = _make_cmdb_request(STORE_QUERY_URL, method="POST", json_data=data_payload)
        info = ""
        infoAppPorts = []

        if data and data.get("totalRecords", 0) > 0 and "dataList" in data:
            logging.info(f"Found {data['totalRecords']} external IP configurations for {ip}")
            info += f"公网IP:{ip} 的应用端口发布配置信息 (共 {data['totalRecords']} 条):\n"
            info += "=" * 50 + "\n"
            for item in data["dataList"]:
                infoAppPort = f"配置名称: {item.get('name', 'N/A')}\n"

                # Safely get system name
                system_name = "N/A"
                if "user_biz_system" in item: system_name = item["user_biz_system"]
                elif "biz_system" in item and isinstance(item["biz_system"], dict): system_name = item["biz_system"].get("name", "N/A")
                elif "biz_system_ips" in item and isinstance(item["biz_system_ips"], dict): system_name = item["biz_system_ips"].get("name", "N/A")
                infoAppPort += f"所属系统: {system_name}\n"

                # Safely get other fields
                if "domain_name" in item: infoAppPort += f"域名: {item['domain_name']}; "
                if "domain_port" in item: infoAppPort += f"入端口: {item['domain_port']}\n"
                else: infoAppPort += "\n" # Ensure newline if port missing

                if "outerNetAddr" in item and item["outerNetAddr"]: infoAppPort += f"外网IP: {','.join(item['outerNetAddr'])}; "
                if "ips" in item and item["ips"]: infoAppPort += f"应用IP: {','.join(item['ips'])}; "
                if "nginxIp" in item and item["nginxIp"]: infoAppPort += f"NginxIP: {','.join(item['nginxIp'])}; "
                if "vip" in item: infoAppPort += f"VIP: {item['vip']}; "
                if "app_port" in item: infoAppPort += f"应用端口: {item['app_port']}\n"
                else: infoAppPort += "\n"

                infoAppPorts.append(infoAppPort.strip()) # Remove trailing newline/space

            info += ("\n" + "-" * 50 + "\n").join(infoAppPorts)
            info += "\n" + "="*50 + "\n"
        else:
            logging.info(f"No external IP configurations found for {ip}")
            info = f"公网IP:{ip}: 未查询到相关的应用端口发布配置。\n"
        return info.strip()
    except Exception as e:
        logging.error(f"Error querying external IP {ip}: {e}")
        return f"查询公网IP {ip} 时出错: {e}"


def queryInternalIpInfo(ip=""):
    """查询内网IP在CMDB中的各类信息"""
    if not ip: return ""
    logging.info(f"Querying internal IP info for {ip}...")

    # Define payloads for different queries
    payloads = {
        "ips": { "field": "ips", "value": ip, "operator": "EQ" }, # Hosts with this IP in 'ips' field
        "ip": { "field": "ip", "value": ip, "operator": "EQ" }, # Resources where 'ip' field matches
        "vip": { "field": "vip", "value": ip, "operator": "EQ", "classCodes": ["app_port_config","AppLoadBalConf"] }, # Configs where 'vip' matches
        "outerNetAddr": { "field": "outerNetAddr", "value": ip, "operator": "EQ", "classCodes": ["app_port_config"] }, # Configs where 'outerNetAddr' matches (less likely for internal)
        "nginxIp": { "field": "nginxIp", "value": ip, "operator": "EQ", "classCodes": ["app_port_config","AppLoadBalConf"] } # Configs where 'nginxIp' matches
    }

    all_results = {}
    combined_data_list = []
    seen_ids = set()

    # Execute queries
    for key, conditions in payloads.items():
        data_payload = {
            "needCount": 1,
            "conditions": [{"field": conditions["field"], "value": conditions["value"], "operator": conditions["operator"]}],
            "pageSize": 50, # Limit results per query type initially
            "pageNum": 0
        }
        # Add classCode filter if present
        if "classCodes" in conditions:
            data_payload["conditions"].append({"field": "classCode", "value": conditions["classCodes"], "operator": "IN"})

        try:
            logging.debug(f"Running CMDB store query for key '{key}' with conditions: {data_payload['conditions']}")
            data = _make_cmdb_request(STORE_QUERY_URL, method="POST", json_data=data_payload)
            if data and data.get("totalRecords", 0) > 0 and "dataList" in data:
                all_results[key] = data["dataList"]
                # Add unique items to combined list
                for item in data["dataList"]:
                    item_id = item.get("id")
                    if item_id and item_id not in seen_ids:
                        combined_data_list.append(item)
                        seen_ids.add(item_id)
                logging.info(f"Query '{key}' found {data['totalRecords']} records for IP {ip}.")
            else:
                all_results[key] = []
                logging.info(f"Query '{key}' found no records for IP {ip}.")
        except Exception as e:
            logging.error(f"Error during CMDB query '{key}' for IP {ip}: {e}")
            all_results[key] = None # Indicate error for this query type

    # --- Process Combined Results ---
    info = ""
    desktop_info = queryDesktopIpInfo(ip) # Query desktop cloud separately

    if not combined_data_list and not desktop_info:
        info = f"内网IP:{ip}: 在CMDB中未查询到相关信息。\n"
        logging.info(f"No information found in CMDB or Desktop Cloud for internal IP {ip}")
    else:
        info += f"内网IP:{ip}: 在CMDB中查到的相关信息:\n"
        info += "-" * 50 + "\n"
        processed_info = handlerDataList(combined_data_list) # Use the handler to format
        if processed_info:
            info += processed_info
        else:
             info += "(未找到可解析的CMDB资源记录)\n"

        if desktop_info:
            info += f"\n桌面云查询信息:\n{desktop_info}\n"
            info += "="*50 + "\n"

    return info.strip()


def queryDomainInfo(domain=""):
    """查询域名关联的配置信息"""
    if not domain: return ""
    logging.info(f"Querying domain info for {domain}...")
    data_payload = {
        "needCount": 1,
        "conditions": [
            { "field": "classCode", "value": ["app_port_config","AppLoadBalConf"], "operator": "IN" },
            { "field": "domain_name", "value": domain, "operator": "EQ" }
        ],
        "pageSize": 50, # Usually only a few configs per domain
        "pageNum": 0
    }
    try:
        data = _make_cmdb_request(STORE_QUERY_URL, method="POST", json_data=data_payload)
        info = ""
        if data and data.get("totalRecords", 0) > 0 and "dataList" in data:
            info += f"域名:{domain}: 在CMDB中查到的相关配置信息 (共 {data['totalRecords']} 条):\n"
            info += "-" * 50 + "\n"
            info += handlerDataList(data["dataList"]) # Reuse the handler
            logging.info(f"Found {data['totalRecords']} configurations for domain {domain}")
        else:
            info = f"域名:{domain}: 在CMDB中未查询到相关配置信息。\n"
            logging.info(f"No configurations found for domain {domain}")
        return info.strip()
    except Exception as e:
        logging.error(f"Error querying domain {domain}: {e}")
        return f"查询域名 {domain} 时出错: {e}"


def handlerDataList(dataList=[]):
    """处理从CMDB查询到的资源列表，格式化为可读字符串"""
    if not dataList: return ""

    info =""
    classCodes = set(item.get("classCode", "Unknown") for item in dataList) # Use set for efficiency
    logging.debug(f"Handling data list with class codes: {classCodes}")

    # Group items by class code for structured output (optional, but can be clearer)
    grouped_items = {}
    for item in dataList:
        code = item.get("classCode", "Unknown")
        if code not in grouped_items:
            grouped_items[code] = []
        grouped_items[code].append(item)

    # --- Format different CI types ---
    output_sections = []

    # Hosts (Linux, Windows, VM)
    host_info = ""
    host_types = ["Linux", "Windows", "VM"]
    processed_host_ids = set() # Track VMs processed via Linux/Windows to avoid duplicates
    for code in host_types:
         if code in grouped_items:
             if not host_info: host_info += "主机信息:\n" + "="*50 + "\n"
             for item in grouped_items[code]:
                 # If it's a VM and we already processed its specific OS type, skip
                 is_vm = item.get("classCode") == "VM"
                 specific_os_processed = False
                 if is_vm:
                     # Heuristic: Check if a Linux/Windows entry with same ID exists
                     # This part is complex and might need better linking logic based on CMDB structure
                     # For now, we assume if Linux/Windows entry exists, it's preferred
                     if ("Linux" in classCodes or "Windows" in classCodes) and item.get("id") in processed_host_ids:
                          continue

                 host_entry = f"类型: {item.get('className', code)}\n"
                 host_entry += f"主机名: {item.get('hostname', 'N/A')}\n"
                 if "os_ver_detl" in item: host_entry += f"OS版本: {item['os_ver_detl']}\n"
                 if "cpu_core_num" in item: host_entry += f"CPU核数: {item['cpu_core_num']}\n"
                 if "ips" in item and item["ips"]: host_entry += f"IPs: {', '.join(item['ips'])}\n"
                 # Add relations if available
                 if "machine_room" in item and isinstance(item["machine_room"], dict): host_entry += f"机房: {item['machine_room'].get('name', 'N/A')}\n"
                 if "network_domain" in item and isinstance(item["network_domain"], dict): host_entry += f"网络域: {item['network_domain'].get('name', 'N/A')}\n"
                 if "application" in item and isinstance(item["application"], dict): host_entry += f"应用: {item['application'].get('name', 'N/A')}\n"
                 if "biz_system" in item and isinstance(item["biz_system"], dict): host_entry += f"业务系统: {item['biz_system'].get('name', 'N/A')}\n"
                 # IT Owner Lookup
                 it_owners = []
                 if "itOwner" in item and isinstance(item["itOwner"], list):
                      for owner_ref in item["itOwner"]:
                           if isinstance(owner_ref, dict) and "uid" in owner_ref:
                                owner_info = queryUserById(owner_ref["uid"])
                                if owner_info: it_owners.append(owner_info)
                 if it_owners: host_entry += f"IT负责人: {'; '.join(it_owners)}\n"
                 # Comments/Usage
                 comment = item.get("comment", item.get("biz_usage", ""))
                 if comment: host_entry += f"备注: {comment}\n"

                 host_info += host_entry + "*" * 50 + "\n"
                 if not is_vm and item.get("id"): # Track processed specific OS hosts
                      processed_host_ids.add(item.get("id"))

    if host_info: output_sections.append(host_info)

    # F5 VS
    f5vs_info = ""
    if "F5VS" in grouped_items:
        f5vs_info += f"F5VS 配置 ({len(grouped_items['F5VS'])} 条):\n" + "="*50 + "\n"
        for item in grouped_items["F5VS"]:
             f5vs_entry = f"名称: {item.get('name', 'N/A')}\n"
             net_domain = item.get('network_domain', {}).get('name', 'N/A') if isinstance(item.get('network_domain'), dict) else 'N/A'
             f5vs_entry += f"VIP: {item.get('ip', 'N/A')}:{item.get('port', 'N/A')}; 网络域: {net_domain}\n"
             f5vs_entry += f"默认池: {item.get('default_pool', 'N/A')}\n"
             # Query related pool members
             F5PoolIds = queryF5PoolIdsByF5VSId(item.get("id", ""))
             PoolMembers = []
             if F5PoolIds:
                 for F5PoolId in F5PoolIds:
                     PoolMembers.extend(queryOutPoolMembersByF5PoolId(F5PoolId))
             if PoolMembers:
                 f5vs_entry += f"服务池成员: {', '.join(PoolMembers)}\n"
             f5vs_info += f5vs_entry + "*"*50 + "\n"
    if f5vs_info: output_sections.append(f5vs_info)

    # F5 Pool Members
    f5member_info = ""
    if "OutPoolMember" in grouped_items:
         f5member_info += f"F5服务池成员 ({len(grouped_items['OutPoolMember'])} 条):\n" + "="*50 + "\n"
         for item in grouped_items["OutPoolMember"]:
              member_entry = f"名称: {item.get('name', 'N/A')}\n"
              member_entry += f"成员IP: {item.get('ip', 'N/A')}:{item.get('port', 'N/A')}\n"
              # Query associated VIPs
              member_vips = queryVIPByPoolMemberId(item.get("id", ""))
              if member_vips:
                   member_entry += f"关联VIPs: {', '.join(member_vips)}\n"
              f5member_info += member_entry + "*"*50 + "\n"
    if f5member_info: output_sections.append(f5member_info)

    # Application Port Config
    app_port_info = ""
    if "app_port_config" in grouped_items:
         app_port_info += f"应用端口配置 ({len(grouped_items['app_port_config'])} 条):\n" + "="*50 + "\n"
         for item in grouped_items["app_port_config"]:
              port_entry = f"配置名称: {item.get('name', 'N/A')}\n"
              # System name logic from queryExternalIpInfo
              system_name = "N/A"
              if "user_biz_system" in item: system_name = item["user_biz_system"]
              elif "biz_system" in item and isinstance(item["biz_system"], dict): system_name = item["biz_system"].get("name", "N/A")
              elif "biz_system_ips" in item and isinstance(item["biz_system_ips"], dict): system_name = item["biz_system_ips"].get("name", "N/A")
              port_entry += f"所属系统: {system_name}\n"
              # Network type specific fields
              net_type = item.get("network_type", "N/A")
              port_entry += f"网络类型: {net_type}\n"
              if net_type == "OUT":
                   if "domain_name" in item: port_entry += f"域名: {item['domain_name']}; "
                   if "domain_port" in item: port_entry += f"入端口: {item['domain_port']}\n"
                   else: port_entry += "\n"
                   if "outerNetAddr" in item and item["outerNetAddr"]: port_entry += f"外网IP: {','.join(item['outerNetAddr'])}\n"
                   if "ips" in item and item["ips"]: port_entry += f"应用IP: {','.join(item['ips'])}\n"
                   if "nginxIp" in item and item["nginxIp"]: port_entry += f"NginxIP: {','.join(item['nginxIp'])}\n"
                   port_entry += f"VIP: {item.get('vip','N/A')}; 应用端口: {item.get('app_port','N/A')}\n"
              elif net_type == "IN":
                   if "domain_name" in item: port_entry += f"域名: {item['domain_name']}\n"
                   port_entry += f"VIP: {item.get('vip','N/A')}; 入端口: {item.get('domain_port','N/A')}\n"
                   if "nginxIp" in item and item["nginxIp"]: port_entry += f"NginxIP: {','.join(item['nginxIp'])}\n"
                   if "ips" in item and item["ips"]: port_entry += f"应用IP: {','.join(item['ips'])}; "
                   if "app_port" in item: port_entry += f"应用端口: {item['app_port']}\n"
                   else: port_entry += "\n"
              else: # Unknown network type, show common fields
                  if "domain_name" in item: port_entry += f"域名: {item['domain_name']}\n"
                  port_entry += f"VIP: {item.get('vip','N/A')}; 入端口: {item.get('domain_port','N/A')}\n"
                  if "ips" in item and item["ips"]: port_entry += f"应用IP: {','.join(item['ips'])}; "
                  if "app_port" in item: port_entry += f"应用端口: {item['app_port']}\n"
                  else: port_entry += "\n"

              app_port_info += port_entry + "*"*50 + "\n"
    if app_port_info: output_sections.append(app_port_info)


    # App Load Balancer Config
    app_lb_info = ""
    if "AppLoadBalConf" in grouped_items:
         app_lb_info += f"应用负载均衡配置 ({len(grouped_items['AppLoadBalConf'])} 条):\n" + "="*50 + "\n"
         for item in grouped_items["AppLoadBalConf"]:
              lb_entry = f"名称: {item.get('name', 'N/A')}\n"
              lb_entry += f"应用地址(VIP?): {item.get('application_addr','')}\n" # Check field name accuracy
              lb_entry += f"Nginx IP: {item.get('nginx_ip','')}\n"
              lb_entry += f"域名: {item.get('domain_name','')}, 端口: {item.get('domain_port','')}\n"
              lb_entry += f"后端IPs: {'|'.join(item.get('ips',[]))}, 后端端口: {item.get('app_port','')}\n"
              app_lb_info += lb_entry + "*"*50 + "\n"
    if app_lb_info: output_sections.append(app_lb_info)

    # PC Server
    pc_server_info = ""
    if "PCServer" in grouped_items:
         pc_server_info += f"物理服务器 ({len(grouped_items['PCServer'])} 条):\n" + "="*50 + "\n"
         for item in grouped_items["PCServer"]:
              pc_entry = f"名称: {item.get('name', 'N/A')}\n"
              pc_entry += f"管理IP: {item.get('ip','')}; OS IP: {item.get('os_ip','')}\n"
              pc_entry += f"品牌: {item.get('pcserver_brand','')}, 型号: {item.get('model', '')}\n"
              pc_entry += f"CPU型号: {item.get('cpu_model','')}, 物理CPU数: {item.get('cpu_phys_num','')}, 核心数: {item.get('cpu_core_num','')}\n"
              # Relations
              if "machine_room" in item and isinstance(item["machine_room"], dict): pc_entry += f"机房: {item['machine_room'].get('name', 'N/A')}\n"
              if "network_domain" in item and isinstance(item["network_domain"], dict): pc_entry += f"网络域: {item['network_domain'].get('name', 'N/A')}\n"
              if "application" in item and isinstance(item["application"], dict) : pc_entry += f"应用: {item['application'].get('name', 'N/A')}\n"
              if "biz_system" in item and isinstance(item["biz_system"], dict): pc_entry += f"业务系统: {item['biz_system'].get('name', 'N/A')}\n"
              # IT Owner
              it_owners = []
              if "itOwner" in item and isinstance(item["itOwner"], list):
                    for owner_ref in item["itOwner"]:
                        if isinstance(owner_ref, dict) and "uid" in owner_ref:
                            owner_info = queryUserById(owner_ref["uid"])
                            if owner_info: it_owners.append(owner_info)
              if it_owners: pc_entry += f"IT负责人: {'; '.join(it_owners)}\n"

              pc_server_info += pc_entry + "*"*50 + "\n"
    if pc_server_info: output_sections.append(pc_server_info)

    # IP Resource Net
    ip_res_info = ""
    if "IpResourceNet" in grouped_items:
         ip_res_info += f"IP资源信息 ({len(grouped_items['IpResourceNet'])} 条):\n" + "="*50 + "\n"
         for item in grouped_items["IpResourceNet"]:
              ip_entry = "IP:{}, 子网:{}, MAC地址:{}\n使用状态:{}, 分配状态:{}, 设备类型:{}, 路径:{}\n".format(
                   item.get("ip", "N/A"), item.get("subnet", "N/A"), item.get("mac_addr", "N/A"),
                   item.get("state", "N/A"), item.get("plan_state", "N/A"), item.get("deviceType","N/A"), item.get("path", "N/A")
              )
              ip_res_info += ip_entry + "*"*50 + "\n"
    if ip_res_info: output_sections.append(ip_res_info)

    # Join all sections
    info = "\n".join(output_sections)
    return info.strip()

# --- Main Combined Query Function ---

def queryIpInfo(ip=""):
    """主查询函数，根据IP类型调用不同的查询逻辑"""
    if not ip:
        return "请输入有效的IP地址。"
    try:
        if is_internal_ip(ip):
            logging.info(f"IP {ip} detected as internal. Querying internal sources...")
            return queryInternalIpInfo(ip)
        else:
            logging.info(f"IP {ip} detected as external. Querying external sources...")
            # Query both external app port config and potentially other public info?
            # For now, just the app port config as per original logic.
            return queryExternalIpInfo(ip)
            # Alternatively combine:
            # external_app_info = queryExternalIpInfo(ip)
            # other_public_info = queryPublicIpInfo(ip) # Placeholder for future GeoIP, ASN etc.
            # return f"{external_app_info}\n{other_public_info}".strip()
    except Exception as e:
        logging.error(f"Error in top-level queryIpInfo for {ip}: {e}", exc_info=True)
        return f"查询IP {ip} 时发生错误: {e}"


# --- Main Execution Block (for testing) ---
if __name__ == "__main__":
    # Setup basic logging for testing
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    print("--- Testing Internal IP ---")