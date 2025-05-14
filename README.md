# 信息安全智能体 (Information Security Agent)

一个集成了多种安全工具和AI助手的高级安全分析平台，帮助安全从业人员和研究人员更快速、更智能地执行安全分析任务。

## 项目概述

本项目提供了一个基于AI助手的工具平台，可以执行各种安全分析任务，包括CVE信息检索、IP地址查询、终端命令执行、文件操作、源码审计等。系统集成了智能AI助手，可以帮助用户理解安全问题、分析威胁并提供解决方案。

## 主要特性

- 🤖 **AI助手集成**：内置智能AI助手，理解自然语言请求并执行相应的安全分析任务
- 🔧 **多功能工具集**：提供多种安全分析工具，包括漏洞信息检索、资产查询、系统命令执行等
- 🔄 **工具依赖管理**：自动处理工具间的依赖关系，支持复杂的分析工作流
- 🔒 **安全操作确认**：对敏感操作提供用户确认机制，防止意外执行危险命令
- 📝 **详细日志记录**：记录所有工具执行情况，便于审计和调试
- **🔍 源码审计分析**：构建记忆宫殿，分层解析代码

## 工具集介绍

### 安全情报工具

1. **search_cve_info**
   - 功能：根据CVE编号在线搜索漏洞详情、描述和利用信息
   - 使用场景：快速了解特定漏洞的技术细节、影响范围和利用方法
   - 示例：`search_cve_info("CVE-2023-12345")`

2. **web_search**
   - 功能：搜索网络获取关于任何安全主题的实时信息
   - 使用场景：获取最新的安全动态、研究新出现的威胁或获取解决方案
   - 示例：`web_search("最新防勒索软件攻击技术")`

### 资产信息工具

1. **lookup_internal_ip**
   
   - 功能：查询IP地址关联的CMDB资产信息（主机、应用配置、F5等），该功能启用需要更改cmdb.py接口配置
   
   - 使用场景：快速了解内网IP对应的设备信息、责任人和应用情况
   
   - 示例：`127.0.0.1`
   
     ![image-20250514110807361](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514110807361.png)

### 系统操作工具

1. **run_terminal_powershell**
   - 功能：使用PowerShell执行终端命令
   
   - 使用场景：运行系统命令、执行安全扫描、收集系统信息等
   
   - 安全特性：内置危险命令检测和用户确认机制
   
   - 示例：`收集域控服务器`
   
     ![image-20250514110308162](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514110308162.png)
   
2. **run_terminal_cmd**
   - 功能：兼容层函数，实际调用run_terminal_powershell
   - 使用场景：保持与旧版本的兼容性
   - 示例：`run_terminal_cmd("ipconfig /all")`

### 文件操作工具

1. **list_dir**
   - 功能：列出指定目录的内容，提供文件和目录的详细信息
   - 使用场景：探索文件系统、寻找特定文件或分析目录结构
   - 示例：`list_dir("logs")`
2. **read_file**
   - 功能：读取文件内容及大纲，支持部分读取和自动继续读取
   - 使用场景：查看日志文件、配置文件、源代码等
   - 示例：`read_file("security_logs.txt", start_line_one_indexed=100, end_line_one_indexed_inclusive=200)`
3. **grep_search**
   - 功能：使用正则表达式在文件中进行快速文本搜索
   - 使用场景：在日志文件中查找特定模式、在代码中搜索安全漏洞特征等
   - 示例：`grep_search("password.*=.*'[^']*'", include_pattern="*.php")`
4. **edit_file**
   - 功能：编辑文件内容或创建新文件
   - 使用场景：修复配置文件、更新防火墙规则、添加安全策略等
   - 示例：`edit_file("config.json", "更新API密钥", "{\n  \"api_key\": \"new_secure_key\"\n}")`
5. **delete_file**
   - 功能：删除指定路径的文件
   - 使用场景：移除临时文件、清理日志、删除恶意文件等
   - 安全特性：防止删除重要系统文件和配置文件
   - 示例：`delete_file("temp_scan_results.txt")`

所有增删改操作均通过对话即可进行：

![image-20250514145117426](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514145117426.png)

### 消息通知工具

1. **send_feishu_message** (需额外配置)
   
   - 功能：发送消息到飞书用户或群组
   
   - 使用场景：发送安全警报、分析结果通知、漏洞修复建议等
   
   - 示例：`send_feishu_message(user_id="security_team", message="发现新的安全漏洞，详情如下...")`
   
     ![image-20250514162552707](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514162552707.png)

### 工具集扩展

系统支持通过添加新的工具模块来扩展功能，已包含：
- 文本解码工具 (decode_tools)

- 飞书消息发送工具 (feishu_send_message)

- 源码审计

  1、分层理解策略：
  首先了解项目结构、重要模块和关键文件
  根据需要有选择地加载最相关的代码片段
  使用之前获取的概要信息指导进一步探索
  2、记忆管理：
  当新内容进入上下文窗口时，旧内容可能会被"遗忘"（超出窗口）
  保留关键信息的摘要，而非完整代码
  可以重新访问之前读取过的文件，如果需要重新获取细节
  3、审计速率：

  限制AI API对于输入的访问速率限制，保证AI完整读取代码

  ![image-20250514112225061](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514112225061.png)

## 技术架构

### 核心组件

1. **工具管理器 (ToolManager)**
   - 管理工具的依赖关系和执行流程
   - 支持顺序执行和并行执行模式
   - 提供工具执行状态监控和错误处理

2. **工具确认系统 (ToolConfirmation)**
   - 为敏感操作提供用户确认界面
   - 显示详细的操作信息和可能的风险
   - 防止意外执行危险命令

### 安全特性

- 危险命令检测和拦截
- 工具执行权限控制
- 敏感操作用户确认
- 文件路径安全检查
- 详细的日志记录

## 使用方法

1. 启动信息安全智能体应用程序
2. 在AI助手界面中使用自然语言描述您的安全分析需求
3. AI助手会理解您的需求并调用相应的工具执行任务
4. 对于敏感操作，系统会请求您的确认后才执行
5. 查看工具执行结果并获取AI助手的分析和建议
6. 其他工具切换模块进行使用

## 安装要求

- Python 3.8+
- PyQt5
- 必要的Python库：duckduckgo_search等
- Windows系统 (PowerShell功能)

## 配置文件

- `tools_dependencies.json`: 定义工具间的依赖关系
- 其他配置文件根据实际部署情况可能需要额外设置

## 场景

- 应急响应：操作系统恶意连接排查

  ![image-20250514144625170](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514144625170.png)

- 渗透测试：自学习，并自动化验证漏洞

![image-20250514150433676](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514150433676.png)

- 查找防病毒软件，并关闭

![image-20250514151035470](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514151035470.png)

- 域内信息收集

![image-20250514151423072](C:\Users\longjw2\AppData\Roaming\Typora\typora-user-images\image-20250514151423072.png)

## 后续规划

- 增加长期记忆功能，目前仅短期记忆，当窗口关闭及销毁

- 增加RAG功能，不同职业的群体喂养之后达到不同职业的智能体，得到专属于自己的机器人：合规机器人、渗透测试机器人、病毒查杀机器人等

- 增加多智能体博弈而不是协作

- 对接常见的安全设备接口，达到：（小肚，小肚，今天有什么需要注意的告警没有？）

  在siem中查找2025年4月18日00:00-24:00所有域账号xxx登录的日志
  查找XX.XX.XX.XX在态势感知的所有告警
  查找XX.XX.XX.XX在WAF的所有告警
  查找XX.XX.XX.XX在HIDS的所有告警

  ...

  最终整理为个人画像：各类日志的登录源IP、常住地省份、城市时间段、常登陆URL、各个系统操作记录...