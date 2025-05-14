import requests
import json
import re
import logging
import sys
import time # Added for dummy tool call ID generation if needed
import threading
from collections import deque

# Attempt to load config - it should have been loaded by main.py
try:
    import config
except ModuleNotFoundError:
    # This should ideally not happen if main.py loaded config correctly
    logging.error("Config module not found. API Adapter may not function correctly.")
    # Create a dummy config to prevent immediate crashes
    from types import ModuleType
    config = ModuleType("config")
    config.API_TYPE = "qwen" # Default fallback
    config.DEEPSEEK_API_KEY = ""
    config.DEEPSEEK_API_URL = ""
    config.DEEPSEEK_MODEL = ""
    config.AZURE_API_KEY = ""
    config.AZURE_API_URL = ""
    config.AZURE_API_VERSION = ""
    config.AZURE_MODEL = ""
    config.QWEN_API_KEY = ""
    config.QWEN_API_URL = ""
    config.QWEN_MODEL = ""
    config.OLLAMA_API_URL = ""
    config.OLLAMA_MODEL = ""
    config.GEMINI_API_URL = ""
    config.GEMINI_API_KEY = ""
    config.GEMINI_MODEL = ""


# Rate limiter for Gemini API (20 requests per minute)
class GeminiRateLimiter:
    def __init__(self, requests_per_minute=20, retry_delay=3):
        self.requests_per_minute = requests_per_minute
        self.retry_delay = retry_delay  # seconds to wait between retries
        self.request_timestamps = deque()
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        with self.lock:
            now = time.time()
            
            # Remove timestamps older than 1 minute
            while self.request_timestamps and now - self.request_timestamps[0] > 60:
                self.request_timestamps.popleft()
            
            # If we've reached the limit, wait until we can make another request
            if len(self.request_timestamps) >= self.requests_per_minute:
                oldest = self.request_timestamps[0]
                sleep_time = max(0, 60 - (now - oldest) + 0.1)  # Add small buffer
                logging.info(f"Gemini rate limit reached. Waiting {sleep_time:.2f} seconds before next request.")
                
                # Release lock while sleeping to allow other threads to check/update
                self.lock.release()
                time.sleep(sleep_time)
                self.lock.acquire()
                
                # Recalculate after sleeping
                now = time.time()
                while self.request_timestamps and now - self.request_timestamps[0] > 60:
                    self.request_timestamps.popleft()
            
            # Record this request
            self.request_timestamps.append(now)
    
    def record_request(self):
        """Record a request without waiting (for external tracking)"""
        with self.lock:
            now = time.time()
            self.request_timestamps.append(now)


class APIAdapter:
    def __init__(self):
        # Reload config attributes in case they were updated
        self.reload_config()
        # Initialize rate limiter for Gemini
        self.gemini_rate_limiter = GeminiRateLimiter()

    def reload_config(self):
        """Reloads configuration attributes from the imported config module."""
        try:
            # Re-import might be needed if the config object itself was replaced
            # import importlib
            # importlib.reload(config)
            # Or just access attributes directly if config module object is updated
            self.api_type = getattr(config, 'API_TYPE', 'qwen') # Default to qwen if missing
            logging.info(f"API Adapter initialized/reloaded with API_TYPE: {self.api_type}")

            if self.api_type == "deepseek":
                self.api_key = getattr(config, 'DEEPSEEK_API_KEY', '')
                self.api_endpoint = getattr(config, 'DEEPSEEK_API_URL', '')
                self.model = getattr(config, 'DEEPSEEK_MODEL', '')
            elif self.api_type == "azure":
                self.api_key = getattr(config, 'AZURE_API_KEY', '')
                self.api_endpoint = getattr(config, 'AZURE_API_URL', '')
                self.api_version = getattr(config, 'AZURE_API_VERSION', '2024-02-15-preview') # Use a version known for tool calling
                self.model = getattr(config, 'AZURE_MODEL', '') # Deployment name
            elif self.api_type == "qwen":
                self.api_key = getattr(config, 'QWEN_API_KEY', '')
                self.api_endpoint = getattr(config, 'QWEN_API_URL', '') # Should be compatible endpoint
                self.model = getattr(config, 'QWEN_MODEL', '')
            elif self.api_type == "ollama":
                 self.api_endpoint = getattr(config, 'OLLAMA_API_URL', 'http://localhost:11434/api/chat')
                 self.model = getattr(config, 'OLLAMA_MODEL', '')
                 self.api_key = None # Ollama doesn't use a key typically
            elif self.api_type == "gemini":
                 self.api_key = getattr(config, 'GEMINI_API_KEY', '')
                 self.api_endpoint = getattr(config, 'GEMINI_API_URL', '')
                 self.model = getattr(config, 'GEMINI_MODEL', '')
            else:
                logging.error(f"Unsupported API_TYPE configured: {self.api_type}")
                # Set default values to avoid errors later
                self.api_type = "qwen" # Fallback
                self.api_key = ""
                self.api_endpoint = ""
                self.model = ""

        except AttributeError as e:
            logging.error(f"Configuration attribute missing: {e}. API Adapter might fail.", exc_info=True)
            # Set safe defaults
            self.api_type = "qwen"
            self.api_key = ""
            self.api_endpoint = ""
            self.model = ""
        except Exception as e:
            logging.error(f"Error reloading config in APIAdapter: {e}", exc_info=True)


    # Modify chat_completion signature and Azure logic
    # Returns:
    # - string: if normal text response
    # - dict: if response includes tool_calls (e.g., {'role': 'assistant', 'content': None, 'tool_calls': [...]})
    # - None: on error or unexpected response format
    def chat_completion(self, messages, temperature=0.3, tools=None, tool_choice="auto", parallel_tool_calls=True): # Added parallel_tool_calls
        """
        Sends messages to the configured AI API.

        Args:
            messages (list): A list of message dictionaries (e.g., [{"role": "user", "content": ...}]).
                             For Azure, content for user/tool roles should be strings;
                             content for assistant role might be string or None (if tool_calls present).
                             The 'tool' role should include 'tool_call_id' and 'content'.
            temperature (float): The sampling temperature.
            tools (list, optional): A list of tool definitions in the API's expected format (e.g., Azure function calling schema).
            tool_choice (str, optional): Tool choice strategy (e.g., "auto", "none", {"type": "function", "function": {"name": "my_func"}}).
            parallel_tool_calls (bool, optional): Whether to enable parallel function calling during tool use. Default is True.

        Returns:
            object: Either the response text content (str) or the full assistant message dictionary (dict)
                    if tool calls are present, or None if an error occurs or response is invalid.
        """
        self.reload_config() # Ensure latest config is used
        logging.debug(f"Sending chat completion request to {self.api_type}...")

        # --- Common Payload Preparation ---
        # Ensure messages is a list
        if not isinstance(messages, list):
            logging.error("Invalid 'messages' type passed to chat_completion. Expected list.")
            raise ValueError("Messages parameter must be a list.")

        # Basic validation for message structure within the list
        for i, msg in enumerate(messages):
             if not isinstance(msg, dict) or "role" not in msg or "content" not in msg:
                  # Allow 'content' to be None for assistant tool calls
                  if not (msg.get("role") == "assistant" and "tool_calls" in msg):
                       logging.warning(f"Message at index {i} has invalid structure: {msg}. Attempting to proceed.")
                       # Potentially skip or try to fix the message here? For now, just log.


        try:
            # --- DeepSeek (Assumes no standard tool support like OpenAI/Azure) ---
            if self.api_type == "deepseek":
                if not self.api_key or not self.api_endpoint or not self.model:
                    raise ValueError("DeepSeek API Key, URL, or Model is not configured.")
                headers = { "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json" }
                payload = {
                    "model": self.model,
                    "messages": messages, # Pass the pre-formatted list
                    "temperature": temperature
                }
                logging.debug(f"DeepSeek Payload: {json.dumps(payload, indent=2, ensure_ascii=False)}")
                response = requests.post(self.api_endpoint, headers=headers, json=payload, timeout=60)
                response.raise_for_status()
                resp_json = response.json()
                # Extract content, assuming standard choices[0].message.content format
                return resp_json.get("choices", [{}])[0].get("message", {}).get("content")


            # --- Azure OpenAI (Supports standard tool calling) ---
            elif self.api_type == "azure":
                if not self.api_key or not self.api_endpoint or not self.model:
                     raise ValueError("Azure API Key, URL, or Deployment Name is not configured.")
                if not self.api_version:
                     raise ValueError("Azure API Version is not configured.")

                headers = { "api-key": self.api_key, "Content-Type": "application/json" }

                # Format messages specifically for Azure (content array for user/tool?) - Let's try simple first based on previous error fix
                azure_messages = []
                for msg in messages:
                     role = msg.get("role")
                     content = msg.get("content")
                     # Add other relevant fields if needed (name for tool, tool_call_id for tool response)
                     azure_msg = {"role": role}

                     if role == "user":
                         # Enforce content array structure that Azure expects for some models/versions
                         azure_msg["content"] = [{"type": "text", "text": str(content)}]
                     elif role == "assistant":
                         # Pass content (might be None if tool_calls present)
                         azure_msg["content"] = content
                         # Pass tool_calls if they exist on the message dict
                         if "tool_calls" in msg:
                              azure_msg["tool_calls"] = msg["tool_calls"]
                     elif role == "tool":
                         # Tool role requires tool_call_id and content
                         azure_msg["tool_call_id"] = msg.get("tool_call_id", f"dummy_tool_call_{int(time.time())}") # Add dummy ID if missing
                         azure_msg["content"] = str(content) # Tool result as string
                         if "name" in msg: # Include name if provided (optional for response)
                              pass # Azure doesn't strictly require 'name' in the tool response message itself
                     else: # system, etc.
                          azure_msg["content"] = str(content)

                     azure_messages.append(azure_msg)


                # Prepare payload
                payload = {
                    "messages": azure_messages,
                    "temperature": temperature
                }
                if tools:
                    payload["tools"] = tools
                    payload["tool_choice"] = tool_choice
                    # Add parallel_tool_calls parameter if tools are used
                    payload["parallel_tool_calls"] = parallel_tool_calls
                    logging.debug("Including tools in Azure request with parallel_tool_calls=" + str(parallel_tool_calls))

                # Construct URL carefully - ensure no double slashes if endpoint already has trailing /
                endpoint = self.api_endpoint.rstrip('/')
                api_url = f"{endpoint}/openai/deployments/{self.model}/chat/completions?api-version={self.api_version}"

                logging.debug(f"Azure Request URL: {api_url}")
                logging.debug(f"Azure Payload (excluding messages content): {json.dumps({k: v for k, v in payload.items() if k != 'messages'}, indent=2)}")

                response = requests.post(api_url, headers=headers, json=payload, timeout=60)
                response.raise_for_status()
                response_data = response.json()
                logging.debug(f"Azure Raw Response Data: {response_data}")

                # Check Azure response for tool_calls
                if "choices" in response_data and len(response_data["choices"]) > 0:
                    message_response = response_data["choices"][0].get("message", {})
                    # If the response includes tool calls, return the whole message object
                    if "tool_calls" in message_response and message_response["tool_calls"]:
                        logging.info("Azure response contains tool calls.")
                        # Standardize return format: dict with role, content, tool_calls
                        return {
                            "role": message_response.get("role", "assistant"),
                            "content": message_response.get("content"), # Often None
                            "tool_calls": message_response["tool_calls"]
                        }
                    else:
                        # Otherwise, return just the text content string
                        return message_response.get("content")
                else:
                    logging.warning(f"Unexpected Azure response structure: {response_data}")
                    return None


            # --- Qwen (Check if compatible endpoint supports OpenAI tools format) ---
            elif self.api_type == "qwen":
                if not self.api_key or not self.api_endpoint or not self.model:
                     raise ValueError("Qwen API Key, URL, or Model is not configured.")
                headers = { "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json" }

                # Assume compatible endpoint might support OpenAI tool format
                if "compatible-mode" in self.api_endpoint:
                     payload = {
                         "model": self.model,
                         "messages": messages, # Pass the list directly
                         "temperature": temperature
                     }
                     # Add tools if provided (speculative for compatible mode)
                     if tools:
                          payload["tools"] = tools
                          payload["tool_choice"] = tool_choice
                          # Add parallel_tool_calls parameter if tools are used
                          payload["parallel_tool_calls"] = parallel_tool_calls
                          logging.debug("Using Qwen OpenAI compatible payload structure with parallel_tool_calls=" + str(parallel_tool_calls))
                     else:
                          logging.debug("Using Qwen OpenAI compatible payload structure (tools speculative).")
                else:
                     # Non-compatible endpoint likely doesn't support this tool format
                     # Adapt payload for specific Qwen API if needed (check Dashscope docs)
                     payload = {
                         "model": self.model,
                         "input": {"messages": messages },
                         "parameters": {"temperature": temperature }
                     }
                     logging.debug("Using Qwen specific payload structure (tools likely unsupported).")

                response = requests.post(self.api_endpoint, headers=headers, json=payload, timeout=60)
                logging.debug(f"Qwen raw response status: {response.status_code}")
                response.raise_for_status()
                response_json = response.json()
                logging.debug(f"Qwen Raw Response Data: {response_json}")

                # Parse Qwen response (check compatible mode for tool_calls)
                if "choices" in response_json and len(response_json["choices"]) > 0:
                    qwen_message = response_json["choices"][0].get("message", {})
                    # Check for tool_calls in compatible mode response
                    if "tool_calls" in qwen_message and qwen_message["tool_calls"]:
                         logging.info("Qwen (compatible) response contains tool calls.")
                         return { # Return similar structure as Azure
                              "role": qwen_message.get("role", "assistant"),
                              "content": qwen_message.get("content"),
                              "tool_calls": qwen_message["tool_calls"]
                         }
                    else:
                         # Return text content otherwise
                         return qwen_message.get("content")
                elif "output" in response_json and "text" in response_json["output"]:
                    return response_json["output"]["text"] # For non-compatible responses
                elif "code" in response_json and "message" in response_json:
                     raise Exception(f"Qwen API Error: {response_json['code']} - {response_json['message']}")
                else:
                     logging.warning(f"Could not parse Qwen response: {response_json}")
                     return None


            # --- Ollama (Tool support varies greatly by model) ---
            elif self.api_type == "ollama":
                 if not self.api_endpoint or not self.model:
                     raise ValueError("Ollama API URL or Model is not configured.")
                 # Standard Ollama payload doesn't include tools parameter
                 payload = {
                     "model": self.model,
                     "messages": messages, # Pass the list directly
                     "stream": False,
                     "options": { "temperature": temperature }
                     # Some Ollama models might support tools via JSON mode or specific prompts,
                     # but it's not standardized like OpenAI API. We don't pass 'tools' here.
                 }
                 api_url = self.api_endpoint
                 if not api_url.endswith('/api/chat'): api_url = api_url.rstrip('/') + '/api/chat'
                 logging.debug(f"Ollama request URL: {api_url}")
                 response = requests.post(api_url, json=payload, timeout=120)
                 response.raise_for_status()
                 response_data = response.json()
                 # Expecting simple text response in 'message.content'
                 content = response_data.get("message", {}).get("content")
                 if content:
                      content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
                      return content.strip()
                 else:
                      logging.warning(f"Ollama response missing message content: {response_data}")
                      return None

            # --- Gemini API ---
            elif self.api_type == "gemini":
                if not self.api_key or not self.api_endpoint or not self.model:
                    raise ValueError("Gemini API Key, URL, or Model is not configured.")
                
                # Apply rate limiting for Gemini API
                max_retries = 3
                retry_count = 0
                
                while retry_count <= max_retries:
                    try:
                        # Wait if we need to respect rate limits
                        self.gemini_rate_limiter.wait_if_needed()
                        
                        # Format gemini content in the required structure
                        gemini_contents = []
                        for msg in messages:
                            role = msg.get("role")
                            content = msg.get("content")
                            
                            # Skip system messages, as Gemini doesn't support them in the same way
                            if role == "system":
                                # Convert system message to user message if it's the first one
                                if not gemini_contents:
                                    gemini_contents.append({
                                        "role": "user",
                                        "parts": [{"text": str(content)}]
                                    })
                                continue
                            
                            # Handle tool (function) response messages
                            if role == "tool":
                                # Tool responses need to be added as user messages with the function response format
                                tool_call_id = msg.get("tool_call_id", "")
                                function_name = msg.get("name", "unknown_function")
                                
                                # Format the tool response for Gemini
                                function_response = {
                                    "name": function_name,
                                    "response": {
                                        "content": str(content)
                                    }
                                }
                                
                                gemini_contents.append({
                                    "role": "user",
                                    "parts": [{"functionResponse": function_response}]
                                })
                                continue
                            
                            # Regular message handling
                            # Map OpenAI roles to Gemini roles
                            gemini_role = "user" if role == "user" else "model"
                            
                            # Check if this is an assistant message with function calls
                            if role == "assistant" and "tool_calls" in msg:
                                # For messages with tool calls, we need to create a model message with function calls
                                tool_calls = msg.get("tool_calls", [])
                                parts = []
                                
                                # Add content if it exists
                                if content:
                                    parts.append({"text": str(content)})
                                
                                # Add each function call
                                for tool_call in tool_calls:
                                    if tool_call.get("type") == "function":
                                        function_detail = tool_call.get("function", {})
                                        try:
                                            # If arguments is a JSON string, parse it
                                            arguments = function_detail.get("arguments", "{}")
                                            if isinstance(arguments, str):
                                                args = json.loads(arguments)
                                            else:
                                                args = arguments
                                        except json.JSONDecodeError:
                                            args = {}
                                        
                                        parts.append({
                                            "functionCall": {
                                                "name": function_detail.get("name", ""),
                                                "args": args
                                            }
                                        })
                                
                                gemini_contents.append({
                                    "role": "model",
                                    "parts": parts
                                })
                                continue
                            
                            # Add the message with the appropriate format for regular messages
                            gemini_contents.append({
                                "role": gemini_role,
                                "parts": [{"text": str(content)}]
                            })
                        
                        # Construct the URL with the API key
                        api_url = f"{self.api_endpoint.rstrip('/')}/models/{self.model}:generateContent?key={self.api_key}"
                        
                        # Prepare payload
                        payload = {
                            "contents": gemini_contents,
                            "generationConfig": {
                                "temperature": temperature
                            }
                        }
                        
                        # Add tools/functions if provided
                        if tools:
                            # Convert OpenAI/Azure tools format to Gemini format
                            gemini_tools = []
                            for tool in tools:
                                if tool.get("type") == "function":
                                    function_def = tool.get("function", {})
                                    gemini_tool = {
                                        "functionDeclarations": [
                                            {
                                                "name": function_def.get("name", ""),
                                                "description": function_def.get("description", ""),
                                                "parameters": function_def.get("parameters", {})
                                            }
                                        ]
                                    }
                                    gemini_tools.append(gemini_tool)
                            
                            if gemini_tools:
                                payload["tools"] = gemini_tools
                                
                                # Handle tool_choice parameter
                                if tool_choice and tool_choice != "auto":
                                    if tool_choice == "none":
                                        # Don't force any tool usage
                                        pass
                                    elif isinstance(tool_choice, dict) and tool_choice.get("type") == "function":
                                        # Force specific function
                                        func_name = tool_choice.get("function", {}).get("name")
                                        if func_name:
                                            # Format expected by Gemini for forcing a specific function
                                            payload["toolConfig"] = {
                                                "functionCalling": {
                                                    "mode": "FORCED",
                                                    "forcedFunction": func_name
                                                }
                                            }
                                    else:
                                        # Default to auto if not recognized
                                        pass
                        
                        headers = {"Content-Type": "application/json"}
                        
                        logging.debug(f"Gemini Request URL: {api_url}")
                        logging.debug(f"Gemini Payload (excluding message content): {json.dumps({k: v for k, v in payload.items() if k != 'contents'}, indent=2)}")
                        
                        response = requests.post(api_url, headers=headers, json=payload, timeout=60)
                        response.raise_for_status()
                        response_data = response.json()
                        logging.debug(f"Gemini Raw Response Data: {response_data}")
                        
                        # Parse Gemini response
                        if "candidates" in response_data and len(response_data["candidates"]) > 0:
                            candidate = response_data["candidates"][0]
                            
                            # Check for function calls in the response
                            function_calls = []
                            if "content" in candidate and "parts" in candidate["content"]:
                                for part in candidate["content"]["parts"]:
                                    if "functionCall" in part:
                                        function_call = part["functionCall"]
                                        # Convert Gemini's function call format to our standardized format
                                        function_calls.append({
                                            "id": f"call_{int(time.time())}_{len(function_calls)}",  # Generate an ID
                                            "type": "function",
                                            "function": {
                                                "name": function_call.get("name", ""),
                                                "arguments": json.dumps(function_call.get("args", {}), ensure_ascii=False)
                                            }
                                        })
                            
                            # If we have function calls, return them in our standardized format
                            if function_calls:
                                logging.info("Gemini response contains function calls")
                                return {
                                    "role": "assistant",
                                    "content": None,  # Content is typically None when tool_calls are present
                                    "tool_calls": function_calls
                                }
                            
                            # Otherwise, extract text content
                            elif "content" in candidate and "parts" in candidate["content"]:
                                parts = candidate["content"]["parts"]
                                if parts and "text" in parts[0]:
                                    return parts[0]["text"]
                        
                        logging.warning(f"Unexpected Gemini response structure: {response_data}")
                        return None
                        
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 429:  # Rate limit exceeded
                            retry_count += 1
                            if retry_count <= max_retries:
                                wait_time = self.gemini_rate_limiter.retry_delay * (2 ** (retry_count - 1))  # Exponential backoff
                                logging.warning(f"Gemini rate limit exceeded. Retry {retry_count}/{max_retries} after {wait_time} seconds")
                                time.sleep(wait_time)
                            else:
                                logging.error("Gemini API rate limit exceeded and max retries reached")
                                raise ConnectionError(f"Gemini API 请求错误: 429 速率限制 - 已达到每分钟20次请求的限制，请稍后重试")
                        else:
                            # Non-rate limit errors, re-raise them
                            raise
                    except Exception as e:
                        # Other exceptions, re-raise them
                        raise

            else:
                 raise ValueError(f"Invalid API Type configured: {self.api_type}")

        # --- Error Handling ---
        except requests.exceptions.Timeout:
             logging.error(f"{self.api_type} API request timed out.")
             raise TimeoutError(f"{self.api_type} API 请求超时") # Raise specific error
        except requests.exceptions.RequestException as e:
            logging.error(f"{self.api_type} API request error: {e}", exc_info=True)
            error_detail = str(e)
            status_code = None
            resp_text = ""
            if e.response is not None:
                status_code = e.response.status_code
                try: resp_text = e.response.text
                except Exception: pass
                error_detail += f" (Status: {status_code}) - Response: {resp_text[:500]}" # Add status and truncated response
            # Raise a more specific error if possible
            raise ConnectionError(f"{self.api_type} API 请求错误: {error_detail}")
        except ValueError as e: # Includes JSONDecodeError, config errors
             logging.error(f"Value or Configuration error for {self.api_type}: {e}", exc_info=True)
             raise ValueError(f"API 配置或响应处理错误 ({self.api_type}): {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during {self.api_type} API call: {e}", exc_info=True)
            raise RuntimeError(f"API 请求时发生意外错误 ({self.api_type}): {str(e)}")