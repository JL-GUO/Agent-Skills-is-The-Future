#!/usr/bin/env python3
"""
wx_key.dll 集成模块
用于获取微信4.0+版本的数据库密钥

基于项目: https://github.com/ycccccccy/wx_key
"""

import os
import sys
import ctypes
import time
import tempfile
import subprocess
from ctypes import c_uint32, c_char_p, c_int, POINTER, c_bool, c_void_p, c_wchar_p
from typing import Optional, Tuple, Dict
import urllib.request
import zipfile
import shutil

DLL_DIR = os.path.join(os.path.dirname(__file__), "dll")
WX_KEY_DLL_NAME = "wx_key.dll"
WX_KEY_DLL_PATH = os.path.join(DLL_DIR, WX_KEY_DLL_NAME)

WX_KEY_RELEASE_URL = "https://github.com/ycccccccy/wx_key/releases/download/v2.1.8/wx_key-windows-v2.1.8.zip"

MAX_KEY_BUFFER_SIZE = 128
MAX_STATUS_BUFFER_SIZE = 512
POLL_INTERVAL = 0.1
MAX_POLL_TIME = 30


class WxKeyError(Exception):
    """wx_key DLL 错误"""
    pass


class WxKeyDLL:
    """wx_key.dll 封装类"""
    
    _instance = None
    _dll = None
    _dll_path = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._dll is not None:
            return
        
        self._dll_path = self._find_dll()
        if not self._dll_path:
            raise WxKeyError(f"未找到 {WX_KEY_DLL_NAME}，请确保DLL文件存在于: {DLL_DIR}")
        
        try:
            if not os.path.exists(self._dll_path):
                raise WxKeyError(f"DLL文件不存在: {self._dll_path}")
            
            abs_path = os.path.abspath(self._dll_path)
            
            os.add_dll_directory(os.path.dirname(abs_path))
            
            self._dll = ctypes.CDLL(abs_path)
            self._setup_functions()
        except OSError as e:
            error_msg = str(e)
            if "找不到指定的模块" in error_msg or "找不到" in error_msg:
                raise WxKeyError(
                    f"加载DLL失败: {error_msg}\n"
                    f"可能原因:\n"
                    f"1. 缺少Visual C++运行库 (安装VC++ Redistributable)\n"
                    f"2. DLL文件损坏或不完整\n"
                    f"3. 系统架构不匹配 (需要64位系统)\n"
                    f"DLL路径: {abs_path}"
                )
            raise WxKeyError(f"加载DLL失败: {e}")
        except Exception as e:
            raise WxKeyError(f"加载DLL异常: {e}")
    
    def _find_dll(self) -> Optional[str]:
        """查找DLL文件"""
        if os.path.exists(WX_KEY_DLL_PATH):
            return WX_KEY_DLL_PATH
        
        for root, dirs, files in os.walk(DLL_DIR):
            for f in files:
                if f.lower() == WX_KEY_DLL_NAME.lower():
                    return os.path.join(root, f)
        
        search_dirs = [
            os.path.dirname(__file__),
            os.path.join(os.path.dirname(__file__), ".."),
            os.getcwd(),
            os.path.join(os.environ.get("USERPROFILE", ""), ".wx_key"),
        ]
        
        for search_dir in search_dirs:
            if os.path.exists(search_dir):
                for root, dirs, files in os.walk(search_dir):
                    for f in files:
                        if f.lower() == WX_KEY_DLL_NAME.lower():
                            return os.path.join(root, f)
        
        return None
    
    def _setup_functions(self):
        """设置DLL函数签名"""
        self._dll.InitializeHook.argtypes = [c_uint32]
        self._dll.InitializeHook.restype = c_bool
        
        self._dll.PollKeyData.argtypes = [c_char_p, c_int]
        self._dll.PollKeyData.restype = c_bool
        
        self._dll.GetStatusMessage.argtypes = [c_char_p, c_int, POINTER(c_int)]
        self._dll.GetStatusMessage.restype = c_bool
        
        self._dll.CleanupHook.argtypes = []
        self._dll.CleanupHook.restype = None
        
        self._dll.GetLastErrorMsg.argtypes = []
        self._dll.GetLastErrorMsg.restype = c_char_p
    
    def initialize(self, pid: int) -> Tuple[bool, str]:
        """初始化Hook
        
        Args:
            pid: 微信进程ID
            
        Returns:
            (成功与否, 错误信息)
        """
        try:
            if not self._dll:
                return False, "DLL未加载"
            
            if pid <= 0:
                return False, f"无效的进程ID: {pid}"
            
            import psutil
            try:
                proc = psutil.Process(pid)
                if not proc.is_running():
                    return False, f"进程 {pid} 未运行"
                if proc.name() not in ['WeChat.exe', 'Weixin.exe']:
                    return False, f"进程 {pid} 不是微信进程: {proc.name()}"
            except psutil.NoSuchProcess:
                return False, f"进程 {pid} 不存在"
            except Exception as e:
                pass
            
            result = self._dll.InitializeHook(c_uint32(pid))
            if not result:
                error_msg = self._dll.GetLastErrorMsg()
                error_str = error_msg.decode('utf-8', errors='ignore') if error_msg else "未知错误"
                
                detailed_error = f"DLL返回错误: {error_str}"
                
                if "版本" in error_str or "version" in error_str.lower():
                    detailed_error += (
                        "\n\n可能原因: wx_key.dll 版本不支持当前微信版本"
                        "\n解决方案: 检查 wx_key 项目是否有更新版本"
                    )
                elif "权限" in error_str or "permission" in error_str.lower() or "拒绝" in error_str:
                    detailed_error += (
                        "\n\n可能原因: 权限不足"
                        "\n解决方案: 以管理员身份运行"
                    )
                elif "进程" in error_str or "process" in error_str.lower():
                    detailed_error += (
                        "\n\n可能原因: 进程访问失败"
                        "\n解决方案: 确保微信正在运行且未锁定"
                    )
                
                return False, detailed_error
            return True, ""
        except Exception as e:
            return False, f"初始化异常: {str(e)}"
    
    def poll_key(self, timeout: float = MAX_POLL_TIME) -> Tuple[Optional[str], str]:
        """轮询获取密钥
        
        Args:
            timeout: 超时时间（秒）
            
        Returns:
            (密钥, 状态信息)
        """
        key_buffer = ctypes.create_string_buffer(MAX_KEY_BUFFER_SIZE)
        status_buffer = ctypes.create_string_buffer(MAX_STATUS_BUFFER_SIZE)
        level = c_int(0)
        
        start_time = time.time()
        last_status = ""
        
        while time.time() - start_time < timeout:
            if self._dll.PollKeyData(key_buffer, MAX_KEY_BUFFER_SIZE):
                key = key_buffer.value.decode('utf-8', errors='ignore')
                return key, "成功获取密钥"
            
            if self._dll.GetStatusMessage(status_buffer, MAX_STATUS_BUFFER_SIZE, ctypes.byref(level)):
                current_status = status_buffer.value.decode('utf-8', errors='ignore')
                if current_status and current_status != last_status:
                    last_status = current_status
            
            time.sleep(POLL_INTERVAL)
        
        return None, f"获取密钥超时。最后状态: {last_status}"
    
    def get_status(self) -> str:
        """获取当前状态"""
        status_buffer = ctypes.create_string_buffer(MAX_STATUS_BUFFER_SIZE)
        level = c_int(0)
        
        if self._dll.GetStatusMessage(status_buffer, MAX_STATUS_BUFFER_SIZE, ctypes.byref(level)):
            return status_buffer.value.decode('utf-8', errors='ignore')
        return ""
    
    def cleanup(self):
        """清理资源"""
        try:
            self._dll.CleanupHook()
        except:
            pass
    
    def __del__(self):
        self.cleanup()


def download_wx_key_dll(progress_callback=None) -> Tuple[bool, str]:
    """下载wx_key.dll
    
    Args:
        progress_callback: 进度回调函数
        
    Returns:
        (成功与否, DLL路径或错误信息)
    """
    try:
        os.makedirs(DLL_DIR, exist_ok=True)
        
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "app.zip")
        
        if progress_callback:
            progress_callback("正在下载 wx_key...")
        
        urllib.request.urlretrieve(WX_KEY_RELEASE_URL, zip_path)
        
        if progress_callback:
            progress_callback("正在解压...")
        
        extract_dir = os.path.join(temp_dir, "extracted")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        dll_found = False
        dll_dest_path = WX_KEY_DLL_PATH
        
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                if f.lower() == WX_KEY_DLL_NAME.lower():
                    src_path = os.path.join(root, f)
                    shutil.copy2(src_path, dll_dest_path)
                    dll_found = True
                    break
            if dll_found:
                break
        
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        if dll_found:
            return True, dll_dest_path
        else:
            return False, f"解压后未找到 {WX_KEY_DLL_NAME}"
            
    except Exception as e:
        return False, f"下载失败: {e}"


def get_wechat_key_v4(pid: int, timeout: float = MAX_POLL_TIME) -> Dict:
    """获取微信4.0+版本的密钥
    
    Args:
        pid: 微信进程ID
        timeout: 超时时间
        
    Returns:
        {
            "success": bool,
            "key": str or None,
            "error": str or None,
            "status": str
        }
    """
    result = {
        "success": False,
        "key": None,
        "error": None,
        "status": ""
    }
    
    try:
        wx_key = WxKeyDLL()
    except WxKeyError as e:
        result["error"] = str(e)
        result["status"] = "DLL加载失败"
        return result
    
    init_success, init_error = wx_key.initialize(pid)
    if not init_success:
        result["error"] = f"初始化失败: {init_error}"
        result["status"] = "初始化失败"
        return result
    
    result["status"] = "正在获取密钥..."
    
    try:
        key, status = wx_key.poll_key(timeout)
        if key:
            result["success"] = True
            result["key"] = key
            result["status"] = "成功获取密钥"
        else:
            result["error"] = status
            result["status"] = "获取密钥失败"
    except Exception as e:
        result["error"] = str(e)
        result["status"] = "获取密钥异常"
    finally:
        wx_key.cleanup()
    
    return result


def get_wechat_key_memory_scan(pid: int, db_path: str = None) -> Dict:
    """使用内存扫描方式获取微信密钥（备用方法）
    
    适用于 wx_key.dll 不支持的情况
    
    Args:
        pid: 微信进程ID
        db_path: 数据库路径（用于验证密钥）
        
    Returns:
        {
            "success": bool,
            "key": str or None,
            "error": str or None,
            "status": str
        }
    """
    result = {
        "success": False,
        "key": None,
        "error": None,
        "status": ""
    }
    
    try:
        import pymem
        from pymem import Pymem
        import pymem.process
        import pymem.pattern
        import hashlib
        import hmac
    except ImportError as e:
        result["error"] = f"缺少依赖: {e}"
        result["status"] = "依赖缺失"
        return result
    
    KEY_SIZE = 32
    DEFAULT_PAGESIZE = 4096
    DEFAULT_ITER = 64000
    
    def verify_key(key, wx_db_path):
        if not wx_db_path or not os.path.exists(wx_db_path):
            return True
        try:
            with open(wx_db_path, "rb") as file:
                blist = file.read(5000)
            salt = blist[:16]
            byteKey = hashlib.pbkdf2_hmac("sha1", key, salt, DEFAULT_ITER, KEY_SIZE)
            first = blist[16:DEFAULT_PAGESIZE]
            mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
            mac_key = hashlib.pbkdf2_hmac("sha1", byteKey, mac_salt, 2, KEY_SIZE)
            hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
            hash_mac.update(b'\x01\x00\x00\x00')
            return hash_mac.digest() == first[-32:-12]
        except:
            return True
    
    try:
        pm = Pymem()
        pm.open_process_from_id(pid)
    except Exception as e:
        result["error"] = f"无法附加到进程: {e}"
        result["status"] = "进程附加失败"
        return result
    
    try:
        module = None
        module_name = None
        for dll_name in ["WeChatWin.dll", "WeixinWin.dll", "wechatwin.dll", "weixinwin.dll"]:
            try:
                module = pymem.process.module_from_name(pm.process_handle, dll_name)
                if module:
                    module_name = dll_name
                    break
            except:
                continue
        
        if module is None:
            result["error"] = "未找到微信核心模块"
            result["status"] = "模块查找失败"
            return result
        
        void_p = ctypes.c_void_p
        ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
        Handle = pm.process_handle
        
        def read_key_bytes(handle, address, address_len=8):
            array = ctypes.create_string_buffer(address_len)
            if ReadProcessMemory(handle, void_p(address), array, address_len, 0) == 0:
                return None
            address = int.from_bytes(array, 'little')
            key = ctypes.create_string_buffer(32)
            if ReadProcessMemory(handle, void_p(address), key, 32, 0) == 0:
                return None
            return bytes(key)
        
        phone_types = ["iphone\x00", "android\x00", "ipad\x00"]
        
        for phone_type in phone_types:
            try:
                type_addrs = pm.pattern_scan_module(phone_type.encode(), module_name, return_multiple=True)
                if len(type_addrs) >= 2:
                    for i in type_addrs[::-1]:
                        for j in range(i, i - 2000, -8):
                            key_bytes = read_key_bytes(Handle, j, 8)
                            if key_bytes and verify_key(key_bytes, db_path):
                                result["success"] = True
                                result["key"] = key_bytes.hex()
                                result["status"] = "成功获取密钥(内存扫描)"
                                return result
            except Exception as e:
                continue
        
        result["error"] = "内存扫描未找到有效密钥"
        result["status"] = "扫描失败"
        return result
        
    except Exception as e:
        result["error"] = f"内存扫描异常: {e}"
        result["status"] = "扫描异常"
        return result
    finally:
        try:
            pm.close_process()
        except:
            pass


def check_dll_available() -> Tuple[bool, str]:
    """检查DLL是否可用
    
    Returns:
        (可用与否, 路径或错误信息)
    """
    if os.path.exists(WX_KEY_DLL_PATH):
        return True, WX_KEY_DLL_PATH
    
    try:
        wx_key = WxKeyDLL()
        return True, wx_key._dll_path
    except WxKeyError as e:
        return False, str(e)


def setup_wx_key_dll(auto_download: bool = True) -> Tuple[bool, str]:
    """设置wx_key.dll
    
    Args:
        auto_download: 是否自动下载
        
    Returns:
        (成功与否, 路径或错误信息)
    """
    available, path = check_dll_available()
    if available:
        return True, path
    
    if not auto_download:
        return False, f"未找到 {WX_KEY_DLL_NAME}，请手动下载并放置到: {DLL_DIR}"
    
    success, result = download_wx_key_dll()
    if success:
        return True, result
    else:
        return False, result


if __name__ == "__main__":
    import argparse
    import psutil
    
    parser = argparse.ArgumentParser(description="wx_key.dll 集成测试")
    parser.add_argument("--setup", action="store_true", help="下载并设置DLL")
    parser.add_argument("--check", action="store_true", help="检查DLL是否可用")
    parser.add_argument("--get-key", action="store_true", help="获取微信密钥 (使用DLL)")
    parser.add_argument("--memory-scan", action="store_true", help="使用内存扫描获取密钥")
    parser.add_argument("--pid", type=int, help="微信进程ID")
    parser.add_argument("--timeout", type=float, default=30, help="超时时间（秒）")
    parser.add_argument("--db-path", type=str, help="数据库路径（用于验证密钥）")
    
    args = parser.parse_args()
    
    if args.setup:
        print("正在设置 wx_key.dll...")
        success, result = setup_wx_key_dll(auto_download=True)
        if success:
            print(f"设置成功: {result}")
        else:
            print(f"设置失败: {result}")
    
    elif args.check:
        available, path = check_dll_available()
        if available:
            print(f"DLL可用: {path}")
        else:
            print(f"DLL不可用: {path}")
    
    elif args.get_key:
        pid = args.pid
        if not pid:
            print("正在查找微信进程...")
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'] in ['WeChat.exe', 'Weixin.exe']:
                    pid = proc.info['pid']
                    print(f"找到微信进程: PID={pid}")
                    break
        
        if not pid:
            print("未找到微信进程")
            sys.exit(1)
        
        print(f"正在获取密钥 (PID: {pid})...")
        result = get_wechat_key_v4(pid, args.timeout)
        print(f"结果: {result}")
        
        if not result.get("success"):
            print("\nDLL方法失败，尝试内存扫描...")
            result = get_wechat_key_memory_scan(pid, args.db_path)
            print(f"内存扫描结果: {result}")
    
    elif args.memory_scan:
        pid = args.pid
        if not pid:
            print("正在查找微信进程...")
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'] in ['WeChat.exe', 'Weixin.exe']:
                    pid = proc.info['pid']
                    print(f"找到微信进程: PID={pid}")
                    break
        
        if not pid:
            print("未找到微信进程")
            sys.exit(1)
        
        print(f"正在使用内存扫描获取密钥 (PID: {pid})...")
        result = get_wechat_key_memory_scan(pid, args.db_path)
        print(f"结果: {result}")
    
    else:
        parser.print_help()
