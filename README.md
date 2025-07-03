# Bandit Security Scanner - MCP Test Cases

## Introduction

This project uses Bandit tool to detect security vulnerabilities in MCP (Malicious Code Patterns). Bandit is a Python security vulnerability scanner designed to identify common security issues.

# Bandit 安全扫描工具 - MCP测试用例

## 简介

本项目使用Bandit工具来检测MCP(Malicious Code Patterns)中的安全漏洞。Bandit是一个Python安全漏洞扫描工具，用于查找常见的安全问题。

## 安装

```bash
pip install bandit
```

## 使用方法

扫描单个文件：
```bash
bandit -r <文件路径>
```

扫描整个目录：
```bash
bandit -r <目录路径>
```

## check.py Script

`check.py` is a custom Bandit scanning script that provides the following features:

1. **Custom Rule Loading**: Automatically loads all custom security rules from the `bandit_rules` directory
2. **Logging**: All scan results are recorded in the `log/bandit_scan.log` file
3. **Programmatic Configuration**: Configures scan parameters directly in code without modifying bandit.yaml
4. **Detailed Output**: Provides scan statistics and issue details

### check.py Usage

1. Modify path configurations in the script:
   - `CUSTOM_RULES_PATH`: Custom rules directory
   - `TARGET_TO_SCAN`: Target directory or file to scan

2. Run the script:
```bash
python check.py
```

3. View output:
   - Console will display scan results and statistics
   - Detailed logs are recorded in `log/bandit_scan.log`

## check.py 脚本

`check.py` 是一个自定义的Bandit扫描脚本，提供了以下功能：

1. **自定义规则加载**：自动加载`bandit_rules`目录下的所有自定义安全规则
2. **日志记录**：所有扫描结果会记录到`log/bandit_scan.log`文件中
3. **编程式配置**：无需修改bandit.yaml文件，直接在代码中配置扫描参数
4. **详细输出**：提供扫描统计信息和问题详情

### check.py 使用方式

1. 修改脚本中的路径配置：
   - `CUSTOM_RULES_PATH`: 自定义规则目录
   - `TARGET_TO_SCAN`: 要扫描的目标目录或文件

2. 运行脚本：
```bash
python check.py
```

3. 查看输出：
   - 控制台会显示扫描结果和统计信息
   - 详细日志会记录到`log/bandit_scan.log`文件中

## 测试用例

本项目包含以下MCP测试用例：
- 认证绕过
- 命令注入
- 凭证窃取
- 硬编码API密钥
- 间接提示注入
- 信息收集
- 拉地毯攻击(Rug Pull)
- 工具投毒
- 工具影子攻击

## 贡献

欢迎提交新的测试用例或改进现有用例。
