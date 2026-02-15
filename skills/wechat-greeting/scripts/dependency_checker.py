#!/usr/bin/env python3
"""
微信祝福Skill - 环境依赖检查器
检查Python版本和必需依赖是否已安装
"""

import sys
import json
from typing import Dict, List, Tuple

# 依赖配置
DEPENDENCIES = {
    "required": [
        {"name": "pymem", "import_name": "pymem", "pip_name": "pymem"},
        {"name": "pycryptodomex", "import_name": "Cryptodome", "pip_name": "pycryptodomex"},
        {"name": "psutil", "import_name": "psutil", "pip_name": "psutil"},
        {"name": "pywin32", "import_name": "win32api", "pip_name": "pywin32"},
    ],
    "optional": [
        {"name": "pypinyin", "import_name": "pypinyin", "pip_name": "pypinyin"},
        {"name": "jieba", "import_name": "jieba", "pip_name": "jieba"},
    ]
}


def check_python_version() -> Tuple[bool, str]:
    """检查Python版本"""
    version = sys.version_info
    if version < (3, 8):
        return False, f"Python版本过低: {version.major}.{version.minor}，需要3.8+"
    return True, f"Python {version.major}.{version.minor}.{version.micro}"


def check_dependency(dep: Dict) -> Tuple[bool, str]:
    """检查单个依赖"""
    try:
        __import__(dep["import_name"])
        return True, f"{dep['name']} 已安装"
    except ImportError:
        return False, f"{dep['name']} 未安装"


def check_all_dependencies() -> Dict:
    """检查所有依赖"""
    result = {
        "success": True,
        "python_version": "",
        "platform": sys.platform,
        "required": {},
        "optional": {},
        "missing_required": [],
        "missing_optional": [],
        "install_commands": []
    }
    
    # 检查Python版本
    py_ok, py_msg = check_python_version()
    result["python_version"] = py_msg
    
    if not py_ok:
        result["success"] = False
        result["error"] = py_msg
        return result
    
    # 检查平台
    if sys.platform != "win32":
        result["success"] = False
        result["error"] = f"当前平台 {sys.platform} 不支持，仅支持Windows"
        return result
    
    # 检查必需依赖
    for dep in DEPENDENCIES["required"]:
        ok, msg = check_dependency(dep)
        result["required"][dep["name"]] = ok
        if not ok:
            result["missing_required"].append(dep)
    
    # 检查可选依赖
    for dep in DEPENDENCIES["optional"]:
        ok, msg = check_dependency(dep)
        result["optional"][dep["name"]] = ok
        if not ok:
            result["missing_optional"].append(dep)
    
    # 生成安装命令
    if result["missing_required"]:
        result["success"] = False
        packages = [d["pip_name"] for d in result["missing_required"]]
        result["install_commands"] = [
            f"pip install {' '.join(packages)}",
            f"pip install {' '.join(packages)} -i https://pypi.tuna.tsinghua.edu.cn/simple"
        ]
    
    return result


def main():
    """主函数"""
    result = check_all_dependencies()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
