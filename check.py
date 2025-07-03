import os
import sys
from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import constants
import bandit.plugins as b_plugins
import logging

# 配置logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='log/bandit_scan.log',
    filemode='a'
)
log = logging.info
# ==============================================================================
# 1. 配置您的路径
# ==============================================================================
# 请在这里填入您自定义规则文件夹的绝对路径
# 使用正斜杠 / 可以避免Windows下的转义问题
CUSTOM_RULES_PATH = "D:/cursor/AIG-mcp-bandit/bandit_rules"

# 请在这里填入您要扫描的目标代码文件夹或文件
TARGET_TO_SCAN = "D:/cursor/AIG-mcp-bandit/mcp_test"

import importlib.util  
import sys  
from bandit.core import extension_loader  
  
def load_custom_plugins(custom_rules_path):  
    """动态加载自定义插件"""  
    import os  
    import glob  
      
    # 获取所有 Python 文件  
    plugin_files = glob.glob(os.path.join(custom_rules_path, "*.py"))  
      
    for plugin_file in plugin_files:  
        if os.path.basename(plugin_file).startswith('__'):  
            continue  
              
        # 动态导入模块  
        module_name = os.path.splitext(os.path.basename(plugin_file))[0]  
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)  
        module = importlib.util.module_from_spec(spec)  
        sys.modules[module_name] = module  
        spec.loader.exec_module(module)  
          
        # 查找模块中的测试函数  
        for attr_name in dir(module):  
            attr = getattr(module, attr_name)  
            if hasattr(attr, '_test_id') and hasattr(attr, '_checks'):  
                # 创建一个伪插件对象  
                class PluginWrapper:  
                    def __init__(self, name, plugin_func):  
                        self.name = name  
                        self.plugin = plugin_func  
                  
                # 添加到扩展管理器  
                plugin_wrapper = PluginWrapper(f"custom_{attr_name}", attr)  
                extension_loader.MANAGER.plugins.append(plugin_wrapper)  
                extension_loader.MANAGER.plugins_by_id[attr._test_id] = plugin_wrapper  
                extension_loader.MANAGER.plugin_names.append(plugin_wrapper.name)


def run_bandit_scan():
    """
    以编程方式配置并运行Bandit扫描。
    """
    log("--- Bandit代码内扫描启动 ---")
    # 加载自定义插件  
    load_custom_plugins(CUSTOM_RULES_PATH)  
    # ==========================================================================
    # 2. 初始化Bandit配置
    # ==========================================================================
    # 创建一个Bandit配置实例
    # 这等同于在内存中创建 bandit.yaml
    try:
        # 步骤 1: 首先创建一个默认的 BanditConfig 对象
        # 这会加载 Bandit 的内置默认配置
        conf = b_config.BanditConfig()
    except Exception as e:
        log(f"错误：创建BanditConfig失败。您的Bandit版本可能不兼容。错误信息: {e}")
        return

    # 步骤 2: 关键步骤！直接在内存中修改配置字典，添加自定义规则路径。
    # BanditConfig 对象内部有一个名为 'config' 的字典。我们直接更新它。
    # 这就实现了在不使用物理配置文件的情况下，加载插件路径的目的。
    conf.config['plugins'] = {
        'plugin_dir': CUSTOM_RULES_PATH
    }

    log(f"加载自定义规则目录: {CUSTOM_RULES_PATH}")
    log(f"扫描目标: {TARGET_TO_SCAN}")
    
    # ==========================================================================
    # 3. 初始化并运行Bandit管理器
    # ==========================================================================
    # 使用配置初始化Bandit管理器
    # 第二个参数是结果聚合方式，'file' 表示按文件聚合
    b_mgr = b_manager.BanditManager(config=conf, agg_type='file')

    # 发现要扫描的文件
    # recursive=True 表示递归扫描子目录
    b_mgr.discover_files([TARGET_TO_SCAN], recursive=True)

    if not b_mgr.files_list:
        log("\n错误：在目标路径下没有找到任何Python文件。")
        return

    log(f"\n发现 {len(b_mgr.files_list)} 个文件，开始扫描...")

    # 运行测试！
    b_mgr.run_tests()
    log("扫描完成。")
    
    # ==========================================================================
    # 4. 处理并打印扫描结果
    # ==========================================================================
    log("\n--- 扫描结果 ---")
    
    # results 是一个 bandit.Issue 对象的列表
    results = b_mgr.get_issue_list(sev_level=constants.LOW, conf_level=constants.LOW)

    if not results:
        log("太棒了！没有发现任何问题。")
        return

    log(f"发现 {len(results)} 个问题:\n")

    for issue in results:
        print(f">> Issue: [{issue.test_id}:{issue.test}] {issue.text}")
        print(f"   Severity: {issue.severity}\tConfidence: {issue.confidence}")
        print(f"   Location: {issue.fname}:{issue.lineno}")
        # 打印问题代码行
        if issue:
             print(f"   Code: {issue}")
        print("-" * 60)
        
    # 打印统计信息
    sev_map = {
        'LOW': 0, 'MEDIUM': 0, 'HIGH': 0
    }
    for issue in results:
        sev_map[issue.severity] += 1
        
    print("\n--- 统计信息 ---")
    print(f"总问题数: {len(results)}")
    print(f"按严重性: High:{sev_map['HIGH']}, Medium:{sev_map['MEDIUM']}, Low:{sev_map['LOW']}")


if __name__ == '__main__':
    # 确保路径存在
    if not os.path.isdir(CUSTOM_RULES_PATH):
        log(f"错误：自定义规则路径不存在 -> {CUSTOM_RULES_PATH}")
    if not os.path.exists(TARGET_TO_SCAN):
        log(f"错误：扫描目标路径不存在 -> {TARGET_TO_SCAN}")
        sys.exit(1)
        
    run_bandit_scan()