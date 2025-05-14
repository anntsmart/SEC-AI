import logging
import requests
import json
from urllib.parse import urlparse, urlunparse

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout,
                             QLineEdit, QCheckBox, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont

from ui_utils import create_scroll_textedit

# Disable requests warnings about insecure connections
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


# --- Worker Thread ---
class HttpReplayThread(QThread):
    replay_complete = pyqtSignal(str, str, int) # result_text, result_type ('success'/'error'), status_code

    def __init__(self, http_request, custom_host=None, custom_port=None, use_https=False, parent=None):
        super().__init__(parent)
        self.http_request_raw = http_request
        self.custom_host = custom_host
        self.custom_port = custom_port
        self.use_https = use_https
        logging.info(f"HttpReplayThread init: CustomHost={custom_host}, CustomPort={custom_port}, UseHTTPS={use_https}")

    def run(self):
        session = requests.Session()
        session.verify = False # Disable SSL verification by default
        session.trust_env = False # Ignore environment proxy settings

        try:
            method, url, headers, body = self.parse_http_request(self.http_request_raw)
            logging.info(f"Parsed request: {method} {url}")
            logging.debug(f"Parsed Headers: {headers}")
            logging.debug(f"Parsed Body: {body[:100] if body else 'None'}")

            # --- Prepare Request arguments for requests.Request ---
            request_constructor_kwargs = {
                'method': method,
                'url': url,
                'headers': headers,
                # timeout and allow_redirects are NOT constructor args for Request
            }

            # Handle body based on method and content type
            if body and method not in ["GET", "HEAD", "OPTIONS"]:
                content_type = headers.get("Content-Type", "").lower()
                if "json" in content_type:
                    try:
                        json_data = json.loads(body)
                        request_constructor_kwargs['json'] = json_data
                        # Requests handles Content-Type for json kwarg, remove if present
                        if 'Content-Type' in request_constructor_kwargs['headers']:
                             del request_constructor_kwargs['headers']['Content-Type']
                        logging.debug("Setting body as JSON for requests.Request")
                    except json.JSONDecodeError:
                        logging.warning("Content-Type is JSON but body is not valid JSON. Sending as raw data.")
                        request_constructor_kwargs['data'] = body.encode('utf-8') # Encode as UTF-8
                elif "x-www-form-urlencoded" in content_type:
                     request_constructor_kwargs['data'] = body # Send raw for form data, Requests usually handles encoding
                     logging.debug("Setting body as form data for requests.Request")
                else:
                    request_constructor_kwargs['data'] = body.encode('utf-8') # Default to sending raw bytes
                    logging.debug("Setting body as raw data for requests.Request")

                # Content-Length handling: Let requests calculate it when using data/json kwargs.
                # If 'Content-Length' was in the original headers, requests might use or override it.
                # Best to let 'prepare_request' handle the final header.
                if 'Content-Length' in request_constructor_kwargs['headers']:
                     logging.debug("Original Content-Length found, requests/prepare_request will handle final value.")


            # Prepare the request object
            # Create the Request object using only valid constructor arguments
            req = requests.Request(**request_constructor_kwargs)
            prepared_request = session.prepare_request(req)

            # Log the final request details (be careful with sensitive data)
            logging.info(f"Sending Request: {prepared_request.method} {prepared_request.url}")
            log_headers = prepared_request.headers.copy()
            if 'Authorization' in log_headers: log_headers['Authorization'] = '***REDACTED***'
            if 'Cookie' in log_headers: log_headers['Cookie'] = '***REDACTED***'
            logging.debug(f"Final Headers: {log_headers}")
            if prepared_request.body:
                 try:
                      logging.debug(f"Final Body (first 100 bytes): {prepared_request.body[:100]}")
                 except Exception:
                      logging.debug("Final Body: (Could not decode slice for logging)")
            else:
                 logging.debug("Final Body: None")


            # --- Send Request ---
            # Define arguments specifically for session.send()
            send_timeout = (10, 30)  # Connect timeout 10s, read timeout 30s
            send_allow_redirects = True # Follow redirects by default

            response = session.send(prepared_request,
                                    timeout=send_timeout,                 # Pass timeout HERE
                                    allow_redirects=send_allow_redirects, # Pass allow_redirects HERE
                                    verify=False                          # Explicitly disable verify here too
                                    )

            # --- Process Response ---
            status_code = response.status_code
            response_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])

            response_body = ""
            try:
                response.encoding = response.apparent_encoding
                response_body = response.text
            except Exception as e:
                logging.warning(f"Could not decode response body as text: {e}. Showing raw bytes if possible.")
                try:
                    response_body = f"无法解码为文本，原始字节 (前 500):\n{response.content[:500]}"
                except Exception as e_raw:
                     response_body = f"无法读取响应体: {str(e_raw)}"


            result = f"--- Response Status ---\n{status_code} {response.reason}\n\n"
            result += f"--- Response Headers ---\n{response_headers}\n\n"
            result += f"--- Response Body ---\n{response_body}"

            result_type = "success" if 200 <= status_code < 400 else "error"
            logging.info(f"Request completed. Status: {status_code}, Type: {result_type}")
            self.replay_complete.emit(result, result_type, status_code)

        except requests.exceptions.Timeout as e:
             error_msg = f"请求超时: {str(e)}"
             logging.error(error_msg, exc_info=True)
             self.replay_complete.emit(error_msg, "error", 0)
        except requests.exceptions.ConnectionError as e:
             # More specific error for DNS resolution failure
             if "Name or service not known" in str(e) or "nodename nor servname provided" in str(e):
                 error_msg = f"DNS解析错误或无法连接主机: {str(e)}\n请检查目标地址是否正确以及网络连接。"
             else:
                error_msg = f"连接错误: {str(e)}\n请检查目标地址、端口和网络连接。"
             logging.error(error_msg, exc_info=True)
             self.replay_complete.emit(error_msg, "error", 0)
        except requests.exceptions.RequestException as e:
             error_msg = f"请求失败: {str(e)}"
             logging.error(error_msg, exc_info=True)
             self.replay_complete.emit(error_msg, "error", 0)
        except ValueError as e: # Catch parsing errors etc.
             error_msg = f"处理请求时出错: {str(e)}"
             logging.error(error_msg, exc_info=True)
             self.replay_complete.emit(error_msg, "error", 0)
        except Exception as e:
            error_msg = f"重放时发生意外错误: {str(e)}"
            logging.error(error_msg, exc_info=True)
            self.replay_complete.emit(error_msg, "error", 0)
        finally:
            session.close()
            logging.debug("HTTP session closed.")

    def parse_http_request(self, raw_request):
        """Parses raw HTTP request string into method, url, headers, body."""
        lines = raw_request.strip().splitlines()
        if not lines:
            raise ValueError("请求数据为空")

        # Parse Request Line
        request_line_parts = lines[0].strip().split(" ")
        if len(request_line_parts) < 2: # Tolerate missing HTTP version
            raise ValueError("请求行格式错误 (需要 METHOD PATH [VERSION])")
        method = request_line_parts[0].upper()
        raw_path = request_line_parts[1]

        # Parse Headers
        headers = {}
        body_lines = []
        header_section_ended = False
        host_header = None
        content_length = None

        for line in lines[1:]:
            if not line.strip():
                header_section_ended = True
                continue # Move to next line after empty line

            if header_section_ended:
                body_lines.append(line)
            else:
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    # Handle duplicate headers (e.g., Set-Cookie) - keep last? Or join? Let requests handle it.
                    headers[key] = value
                    if key.lower() == "host":
                        host_header = value
                    if key.lower() == "content-length":
                        try:
                            content_length = int(value)
                        except ValueError:
                             logging.warning(f"Invalid Content-Length header: {value}")
                else:
                     logging.warning(f"Skipping malformed header line: {line}")


        body = "\n".join(body_lines)

        # Validate body length if Content-Length was provided
        if content_length is not None and len(body.encode('utf-8')) != content_length:
             logging.warning(f"Actual body length ({len(body.encode('utf-8'))}) differs from Content-Length header ({content_length}).")
             # Trust actual body length over header for sending? Or truncate/pad?
             # For replay, using the actual body seems safer. Requests lib might adjust CL.


        # Determine target host and scheme
        target_host = self.custom_host if self.custom_host else host_header
        if not target_host:
            raise ValueError("无法确定目标主机 (缺少Host头且未提供自定义Host)")

        scheme = "https" if self.use_https else "http"
        default_port = 443 if self.use_https else 80
        port = self.custom_port

        # Incorporate port into target_host if specified or non-default
        if port:
            # Remove existing port from target_host if present
            target_host = target_host.split(":")[0]
            netloc = f"{target_host}:{port}"
            effective_port = int(port)
        else:
            # Check if host header includes port
            if ":" in target_host:
                host_part, port_part = target_host.split(":", 1)
                try:
                     effective_port = int(port_part)
                     netloc = target_host # Host header already has port
                except ValueError:
                     logging.warning(f"Host header has invalid port: {port_part}. Using default.")
                     effective_port = default_port
                     netloc = host_part # Use host without port
            else:
                effective_port = default_port
                netloc = target_host

        # Update Host header to match final target (including port if non-default)
        headers['Host'] = netloc # Ensure Host header reflects final destination

        # Construct final URL
        # If raw_path is already a full URL, use its components
        parsed_path = urlparse(raw_path)
        if parsed_path.scheme and parsed_path.netloc:
             # User provided full URL in request line, prioritize parts of it
             # but override scheme/netloc based on settings
             final_url = urlunparse((
                 scheme,
                 netloc,
                 parsed_path.path if parsed_path.path else "/",
                 parsed_path.params,
                 parsed_path.query,
                 parsed_path.fragment
             ))
             logging.info(f"Using path from request line, but overriding scheme/host/port: {raw_path} -> {final_url}")
        else:
             # Path is relative, combine with scheme/netloc
             final_url = urlunparse((
                 scheme,
                 netloc,
                 raw_path if raw_path.startswith("/") else "/" + raw_path, # Ensure leading slash
                 "", # params
                 "", # query
                 ""  # fragment
             ))
             logging.info(f"Constructed URL: {final_url}")


        return method, final_url, headers, body


# --- UI Creation and Logic ---
def create_tab(main_window):
    """Creates the HTTP Replay tab."""
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.addWidget(QLabel("HTTP数据包重放工具", font=QFont("Arial", 16, QFont.Bold)))

    # --- Request Input ---
    layout.addWidget(QLabel("HTTP请求数据:"))
    req_frame, main_window.http_replay_input = create_scroll_textedit(
        "在此输入完整的HTTP请求包，例如：\nGET /index.html HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: */*",
        read_only=False, font_family='Consolas', font_size=11
    )
    layout.addWidget(req_frame, 2) # More stretch for request input

    # --- Configuration Panel ---
    config_panel = QWidget()
    config_layout = QHBoxLayout(config_panel)
    config_layout.setContentsMargins(0, 5, 0, 5)

    config_layout.addWidget(QLabel("Host:"))
    main_window.replay_host_input = QLineEdit()
    main_window.replay_host_input.setPlaceholderText("留空则使用请求包中的Host")
    config_layout.addWidget(main_window.replay_host_input)

    config_layout.addWidget(QLabel("Port:"))
    main_window.replay_port_input = QLineEdit()
    main_window.replay_port_input.setPlaceholderText("留空则使用默认端口 (80/443)")
    main_window.replay_port_input.setFixedWidth(80) # Smaller width for port
    config_layout.addWidget(main_window.replay_port_input)

    main_window.replay_use_https = QCheckBox("使用HTTPS")
    config_layout.addWidget(main_window.replay_use_https)
    config_layout.addStretch()
    layout.addWidget(config_panel)

    # --- Control Panel ---
    control_panel = QWidget()
    control_layout = QHBoxLayout(control_panel)
    control_layout.setContentsMargins(0, 0, 0, 0)

    main_window.replay_btn_send = QPushButton("发送请求")
    main_window.replay_btn_send.setMinimumWidth(120)
    control_layout.addWidget(main_window.replay_btn_send)

    # Quick insert helpers
    control_layout.addWidget(QLabel("插入:"))
    main_window.replay_method_combo = QComboBox()
    main_window.replay_method_combo.addItems(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
    main_window.replay_method_combo.setFixedWidth(80)
    # Connect signal to insert template
    main_window.replay_method_combo.activated[str].connect(lambda method: insert_http_template(main_window, method))
    control_layout.addWidget(main_window.replay_method_combo)

    # Add common headers button (optional)
    # main_window.replay_btn_add_headers = QPushButton("常用Header", clicked=lambda: insert_common_headers(main_window))
    # control_layout.addWidget(main_window.replay_btn_add_headers)

    main_window.replay_btn_clear = QPushButton("清空请求")
    control_layout.addWidget(main_window.replay_btn_clear)

    control_layout.addStretch()
    layout.addWidget(control_panel)

    # --- Status Label ---
    main_window.replay_status_label = QLabel("准备就绪")
    # main_window.replay_status_label.setStyleSheet("font-weight: bold; color: #007acc;")
    layout.addWidget(main_window.replay_status_label)

    # --- Response Output ---
    layout.addWidget(QLabel("响应结果:"))
    resp_frame, main_window.http_replay_result = create_scroll_textedit(
        read_only=True, font_family='Consolas', font_size=11
    )
    layout.addWidget(resp_frame, 3) # Most stretch for response output

    # --- Connect Signals ---
    main_window.replay_btn_send.clicked.connect(lambda: send_http_request(main_window))
    main_window.replay_btn_clear.clicked.connect(lambda: main_window.http_replay_input.clear())


    main_window.tab_widget.addTab(tab, "HTTP重放")


def insert_http_template(main_window, method):
    """Inserts a basic HTTP request template for the selected method."""
    current_text = main_window.http_replay_input.toPlainText()
    lines = current_text.splitlines()

    template_headers = """Host: example.com
User-Agent: SecAI-ReplayTool/1.0
Accept: */*
Connection: close""" # Use close by default for single requests

    template = f"{method} / HTTP/1.1\n{template_headers}\n\n"

    # If first line looks like a request line, replace it, otherwise prepend
    if lines and len(lines[0].split()) >= 2 and lines[0].split()[0].isupper():
         # Find end of headers (first empty line)
         try:
             header_end_index = lines.index("")
             existing_body = "\n".join(lines[header_end_index+1:])
             new_request = f"{method} / HTTP/1.1\n" + "\n".join(lines[1:header_end_index]) + "\n\n" + existing_body
             main_window.http_replay_input.setPlainText(new_request)
         except ValueError: # No empty line found, replace whole thing
              main_window.http_replay_input.setPlainText(template)

    else:
        main_window.http_replay_input.setPlainText(template + current_text) # Prepend template


def send_http_request(main_window):
    """Slot to start the HTTP replay thread."""
    http_request = main_window.http_replay_input.toPlainText() # Don't strip yet, body might need whitespace
    if not http_request.strip():
        main_window.show_status("请输入有效的HTTP请求数据", "red")
        return

    custom_host = main_window.replay_host_input.text().strip()
    custom_port_str = main_window.replay_port_input.text().strip()
    use_https = main_window.replay_use_https.isChecked()

    # Validate port
    custom_port = None
    if custom_port_str:
         try:
             custom_port = int(custom_port_str)
             if not (0 < custom_port < 65536):
                  raise ValueError("端口号必须在 1-65535 之间")
         except ValueError as e:
             main_window.show_status(f"端口号无效: {e}", "red")
             return


    main_window.replay_btn_send.setEnabled(False)
    main_window.replay_status_label.setText("正在发送请求...")
    main_window.replay_status_label.setStyleSheet("color: #007acc;") # Blue
    main_window.http_replay_result.setPlainText("请求处理中...")
    main_window.show_status("正在发送HTTP请求...", "#007acc")


    # Keep reference to thread
    main_window.http_replay_thread = HttpReplayThread(
        http_request, custom_host, custom_port, use_https
    )
    main_window.http_replay_thread.replay_complete.connect(
        lambda res, type, code: show_http_replay_result(main_window, res, type, code)
    )
    main_window.http_replay_thread.start()

def show_http_replay_result(main_window, result, result_type, status_code):
    """Slot to display HTTP replay results."""
    main_window.replay_btn_send.setEnabled(True)

    status_text = "请求处理完成"
    status_color = "#888888" # Grey default

    if result_type == "success":
        status_text = f"请求成功 (状态码: {status_code})"
        status_color = "#2ed573"  # Green
    elif result_type == "error":
        if status_code > 0:
            status_text = f"请求失败 (状态码: {status_code})"
            status_color = "#ffa502" # Orange for server errors
        else:
            # Check for specific error messages
            if "连接错误" in result:
                 status_text = "连接错误"
            elif "超时" in result:
                 status_text = "请求超时"
            else:
                 status_text = "请求失败 (客户端错误)"
            status_color = "#ff4757"  # Red for client-side/network errors

    main_window.replay_status_label.setText(status_text)
    main_window.replay_status_label.setStyleSheet(f"font-weight: bold; color: {status_color};")

    main_window.http_replay_result.setPlainText(result)
    main_window.show_status(status_text, status_color)