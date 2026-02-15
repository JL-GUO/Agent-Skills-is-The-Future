#!/usr/bin/env python3
"""
微信祝福Skill - 微信数据库连接器
负责连接微信、解密数据库、读取聊天记录
支持微信3.x和4.x版本
"""

import os
import sys
import json
import ctypes
import hmac
import hashlib
import sqlite3
import tempfile
import shutil
import re
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from difflib import SequenceMatcher
from collections import Counter

WECHAT_PROCESS_NAMES = ["WeChat.exe", "Weixin.exe"]
WECHAT_DLL_NAMES = ["WeChatWin.dll", "WeixinWin.dll", "wechatwin.dll", "weixinwin.dll"]
WECHAT_DATA_DIRS = ["WeChat Files", "xwechat_files"]
WECHAT_V4_DATA_DIRS = ["xwechat_files", "WeChat Files"]
KEY_SIZE = 32
DEFAULT_PAGESIZE = 4096
DEFAULT_ITER = 64000
SQLITE_FILE_HEADER = "SQLite format 3\x00"
TEMP_DIR = os.path.join(tempfile.gettempdir(), "wechat_greeting_skill")

# Windows API
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
void_p = ctypes.c_void_p


class WeChatError(Exception):
    """微信连接错误"""
    pass


class DependencyError(Exception):
    """依赖错误"""
    pass


def check_dependencies() -> bool:
    """快速检查关键依赖"""
    try:
        import pymem
        from Cryptodome.Cipher import AES
        import psutil
        import win32api
        return True
    except ImportError as e:
        raise DependencyError(f"缺少依赖: {e}")


class WeChatConnector:
    """微信数据库连接器"""
    
    def __init__(self):
        self.pm = None
        self.temp_db_dir = None
        self._ensure_temp_dir()
    
    def _ensure_temp_dir(self):
        """确保临时目录存在"""
        os.makedirs(TEMP_DIR, exist_ok=True)
        self.temp_db_dir = TEMP_DIR
    
    def check_wechat_running(self) -> Tuple[bool, Optional[int]]:
        """检查微信是否运行"""
        try:
            import psutil
            for process in psutil.process_iter(['name', 'pid']):
                if process.info['name'] in WECHAT_PROCESS_NAMES:
                    return True, process.info['pid']
            return False, None
        except Exception as e:
            return False, None
    
    def get_exe_bit(self, file_path: str) -> int:
        """获取PE文件位数"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(60)
                pe_offset = int.from_bytes(f.read(4), 'little')
                f.seek(pe_offset + 4)
                machine = int.from_bytes(f.read(2), 'little')
                return 32 if machine == 0x14c else 64
        except:
            return 64
    
    def get_wechat_info(self) -> Dict:
        """获取微信信息（密钥、路径等）- 支持3.x和4.x版本"""
        try:
            import psutil
            import pymem
            import winreg
            from win32com.client import Dispatch
        except ImportError as e:
            raise DependencyError(f"缺少依赖: {e}")
        
        running, pid = self.check_wechat_running()
        if not running:
            raise WeChatError("微信未运行")
        
        result = {"pid": pid, "success": False}
        
        try:
            process = None
            for p in psutil.process_iter(['name', 'exe', 'pid']):
                if p.info['pid'] == pid:
                    process = p
                    break
            
            if not process:
                raise WeChatError("无法获取进程信息")
            
            result['exe_path'] = process.info['exe']
            version = Dispatch("Scripting.FileSystemObject").GetFileVersion(process.info['exe'])
            result['version'] = version
            
            version_parts = version.split('.') if version else []
            major_version = int(version_parts[0]) if version_parts and version_parts[0].isdigit() else 0
            
            result['major_version'] = major_version
            result['is_v4'] = major_version >= 4
            
            wxid = self._get_wxid_v4(pid) if major_version >= 4 else self._get_wxid_legacy(pid)
            if not wxid or wxid == "None":
                wxid = self._get_wxid_legacy(pid)
            result['wxid'] = wxid
            
            file_path = self._get_file_path_v4(wxid) if major_version >= 4 else self._get_file_path(wxid)
            if not file_path or file_path == "None":
                file_path = self._get_file_path(wxid)
            result['db_path'] = file_path
            
            if major_version >= 4:
                key = self._get_key_v4(pid, file_path)
                if not key or key == "None":
                    key = self._get_key_legacy(pid, file_path)
            else:
                key = self._get_key_legacy(pid, file_path)
            
            result['key'] = key
            
            if not key or key == "None":
                if major_version >= 4:
                    raise WeChatError(
                        f"微信4.0+版本({version})密钥获取失败。\n"
                        "请确保已正确配置wx_key.dll。\n"
                        "解决方案：\n"
                        "1. 运行 python wx_key_integration.py --setup 下载DLL\n"
                        "2. 或使用 --key 参数手动输入密钥"
                    )
                raise WeChatError("无法获取微信密钥，可能微信版本不支持")
            
            result['success'] = True
            return result
            
        except Exception as e:
            if not isinstance(e, WeChatError):
                raise WeChatError(f"获取微信信息失败: {str(e)}")
            raise
    
    def _get_wxid_v4(self, pid: int) -> str:
        """获取微信4.0版本的wxid"""
        try:
            import psutil
            process = psutil.Process(pid)
            
            for module in process.memory_maps(grouped=False):
                if module.path:
                    path_lower = module.path.lower()
                    if 'xwechat_files' in path_lower or 'wechat files' in path_lower:
                        parts = path_lower.replace('\\', '/').split('/')
                        for i, part in enumerate(parts):
                            if part in ['xwechat_files', 'wechat files'] and i + 1 < len(parts):
                                wxid_candidate = parts[i + 1]
                                if wxid_candidate.startswith('wxid_'):
                                    return wxid_candidate
            return "None"
        except:
            return "None"
    
    def _get_wxid_legacy(self, pid: int) -> str:
        """获取微信3.x版本的wxid（传统方法）"""
        Handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
        try:
            return self._get_wxid(Handle)
        finally:
            ctypes.windll.kernel32.CloseHandle(Handle)
    
    def _get_file_path_v4(self, wxid: str) -> str:
        """获取微信4.0版本的数据文件路径"""
        import winreg
        
        if not wxid:
            return "None"
        
        w_dir = "MyDocument:"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\WeChat", 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, "FileSavePath")
            winreg.CloseKey(key)
            w_dir = value
        except:
            pass
        
        if w_dir == "MyDocument:":
            try:
                user_profile = os.environ.get("USERPROFILE")
                config_path = os.path.join(user_profile, "AppData", "Roaming", "Tencent", "WeChat", "All Users", "config", "3ebffe94.ini")
                with open(config_path, "r", encoding="utf-8") as f:
                    w_dir = f.read()
            except:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
                    w_dir = winreg.QueryValueEx(key, "Personal")[0]
                    winreg.CloseKey(key)
                except:
                    w_dir = os.path.join(os.environ.get("USERPROFILE", ""), "Documents")
        
        for data_dir in WECHAT_V4_DATA_DIRS:
            msg_dir = os.path.join(w_dir, data_dir)
            file_path = os.path.join(msg_dir, wxid)
            if os.path.exists(file_path):
                return file_path
        
        for data_dir in WECHAT_V4_DATA_DIRS:
            msg_dir = os.path.join(w_dir, data_dir)
            if os.path.exists(msg_dir):
                for item in os.listdir(msg_dir):
                    if item.startswith("wxid_"):
                        return os.path.join(msg_dir, item)
        
        return "None"
    
    def _get_key_v4(self, pid: int, db_path: str) -> str:
        """使用wx_key.dll获取微信4.0+版本的密钥"""
        try:
            from wx_key_integration import get_wechat_key_v4, get_wechat_key_memory_scan, check_dll_available, setup_wx_key_dll
            
            available, dll_path = check_dll_available()
            if available:
                result = get_wechat_key_v4(pid, timeout=30)
                if result.get("success") and result.get("key"):
                    key = result["key"]
                    if len(key) == 64:
                        return key
            
            if db_path and db_path != "None":
                msg_db = os.path.join(db_path, "MSG", "MicroMsg.db")
                if not os.path.exists(msg_db):
                    msg_db = os.path.join(db_path, "MSG0", "MicroMsg.db")
                if not os.path.exists(msg_db):
                    msg_db = os.path.join(db_path, "MicroMsg.db")
                if not os.path.exists(msg_db):
                    msg_db = None
                
                result = get_wechat_key_memory_scan(pid, msg_db)
                if result.get("success") and result.get("key"):
                    key = result["key"]
                    if len(key) == 64:
                        return key
            
            return "None"
        except ImportError:
            return "None"
        except Exception:
            return "None"
    
    def _get_key_legacy(self, pid: int, db_path: str) -> str:
        """使用传统方法获取微信3.x版本的密钥"""
        try:
            import pymem
            from pymem import Pymem
            import pymem.process
            import pymem.pattern
        except ImportError:
            return "None"
        
        Handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
        
        try:
            import psutil
            process = psutil.Process(pid)
            addr_len = self.get_exe_bit(process.exe()) // 8
        except:
            addr_len = 8
        
        try:
            pm = None
            for process_name in WECHAT_PROCESS_NAMES:
                try:
                    pm = Pymem(process_name)
                    break
                except:
                    continue
            
            if pm is None:
                return "None"
            
            micro_msg_path = os.path.join(db_path, "MSG", "MicroMsg.db") if db_path != "None" else "None"
            if micro_msg_path == "None" or not os.path.exists(micro_msg_path):
                micro_msg_path = os.path.join(db_path, "MicroMsg.db") if db_path != "None" else "None"
            
            module = None
            module_name = None
            for dll_name in WECHAT_DLL_NAMES:
                try:
                    module = pymem.process.module_from_name(pm.process_handle, dll_name)
                    if module:
                        module_name = dll_name
                        break
                except:
                    continue
            
            if module is None:
                return "None"
            
            def read_key_bytes(handle, address, address_len=8):
                array = ctypes.create_string_buffer(address_len)
                if ReadProcessMemory(handle, void_p(address), array, address_len, 0) == 0:
                    return None
                address = int.from_bytes(array, 'little')
                key = ctypes.create_string_buffer(32)
                if ReadProcessMemory(handle, void_p(address), key, 32, 0) == 0:
                    return None
                return bytes(key)
            
            def verify_key(key, wx_db_path):
                if not wx_db_path or wx_db_path.lower() == "none":
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
            
            phone_types = ["iphone\x00", "android\x00", "ipad\x00"]
            for phone_type in phone_types:
                try:
                    type_addrs = pm.pattern_scan_module(phone_type.encode(), module_name, return_multiple=True)
                    if len(type_addrs) >= 2:
                        for i in type_addrs[::-1]:
                            for j in range(i, i - 2000, -addr_len):
                                key_bytes = read_key_bytes(pm.process_handle, j, addr_len)
                                if key_bytes and verify_key(key_bytes, micro_msg_path):
                                    return key_bytes.hex()
                except:
                    continue
            
            return "None"
        except:
            return "None"
        finally:
            ctypes.windll.kernel32.CloseHandle(Handle)
    
    def _get_wxid(self, h_process) -> str:
        """从内存获取wxid"""
        try:
            import pymem
        except ImportError:
            return "None"
        
        def pattern_scan_all(handle, pattern, return_multiple=False, find_num=100):
            next_region = 0
            found = []
            user_space_limit = 0x7FFFFFFF0000 if sys.maxsize > 2 ** 32 else 0x7fff0000
            while next_region < user_space_limit:
                try:
                    next_region, page_found = pymem.pattern.scan_pattern_page(
                        handle, next_region, pattern, return_multiple=return_multiple
                    )
                except:
                    break
                if page_found:
                    found += page_found
                if len(found) > find_num:
                    break
            return found
        
        addrs = pattern_scan_all(h_process, br'\\Msg\\FTSContact', return_multiple=True)
        wxids = []
        for addr in addrs:
            array = ctypes.create_string_buffer(80)
            if ReadProcessMemory(h_process, void_p(addr - 30), array, 80, 0) == 0:
                continue
            array = bytes(array).split(b"\\Msg")[0].split(b"\\")[-1]
            wxids.append(array.decode('utf-8', errors='ignore'))
        return max(wxids, key=wxids.count) if wxids else "None"
    
    def _get_file_path(self, wxid: str) -> str:
        """获取微信数据文件路径（支持3.x和4.0版本）"""
        import winreg
        
        if not wxid:
            return "None"
        
        w_dir = "MyDocument:"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Tencent\WeChat", 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, "FileSavePath")
            winreg.CloseKey(key)
            w_dir = value
        except:
            pass
        
        if w_dir == "MyDocument:":
            try:
                user_profile = os.environ.get("USERPROFILE")
                config_path = os.path.join(user_profile, "AppData", "Roaming", "Tencent", "WeChat", "All Users", "config", "3ebffe94.ini")
                with open(config_path, "r", encoding="utf-8") as f:
                    w_dir = f.read()
            except:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
                    w_dir = winreg.QueryValueEx(key, "Personal")[0]
                    winreg.CloseKey(key)
                except:
                    w_dir = os.path.join(os.environ.get("USERPROFILE", ""), "Documents")
        
        for data_dir in WECHAT_DATA_DIRS:
            msg_dir = os.path.join(w_dir, data_dir)
            file_path = os.path.join(msg_dir, wxid)
            if os.path.exists(file_path):
                return file_path
        
        for data_dir in WECHAT_DATA_DIRS:
            msg_dir = os.path.join(w_dir, data_dir)
            if os.path.exists(msg_dir):
                for item in os.listdir(msg_dir):
                    if item.startswith("wxid_"):
                        return os.path.join(msg_dir, item)
        
        return "None"
    
    def _get_key(self, h_process, db_path: str, addr_len: int, pid: int) -> str:
        """获取微信数据库密钥（支持多种方式）"""
        try:
            import pymem
            from pymem import Pymem
            import pymem.process
            import pymem.pattern
        except ImportError:
            return "None"
        
        def read_key_bytes(handle, address, address_len=8):
            array = ctypes.create_string_buffer(address_len)
            if ReadProcessMemory(handle, void_p(address), array, address_len, 0) == 0:
                return None
            address = int.from_bytes(array, 'little')
            key = ctypes.create_string_buffer(32)
            if ReadProcessMemory(handle, void_p(address), key, 32, 0) == 0:
                return None
            return bytes(key)
        
        def verify_key(key, wx_db_path):
            if not wx_db_path or wx_db_path.lower() == "none":
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
        
        pm = None
        for process_name in WECHAT_PROCESS_NAMES:
            try:
                pm = Pymem(process_name)
                break
            except:
                continue
        
        if pm is None:
            return "None"
        
        micro_msg_path = os.path.join(db_path, "MSG", "MicroMsg.db") if db_path != "None" else "None"
        if micro_msg_path == "None" or not os.path.exists(micro_msg_path):
            micro_msg_path = os.path.join(db_path, "MicroMsg.db") if db_path != "None" else "None"
        
        module = None
        module_name = None
        for dll_name in WECHAT_DLL_NAMES:
            try:
                module = pymem.process.module_from_name(pm.process_handle, dll_name)
                if module:
                    module_name = dll_name
                    break
            except:
                continue
        
        if module is None:
            return "None"
        
        phone_types = ["iphone\x00", "android\x00", "ipad\x00"]
        for phone_type in phone_types:
            try:
                type_addrs = pm.pattern_scan_module(phone_type.encode(), module_name, return_multiple=True)
                if len(type_addrs) >= 2:
                    for i in type_addrs[::-1]:
                        for j in range(i, i - 2000, -addr_len):
                            key_bytes = read_key_bytes(pm.process_handle, j, addr_len)
                            if key_bytes and verify_key(key_bytes, micro_msg_path):
                                return key_bytes.hex()
            except:
                continue
        
        key = self._get_key_by_public_key(pm, module, addr_len, micro_msg_path, verify_key)
        if key:
            return key
        
        return "None"
    
    def _get_key_by_public_key(self, pm, module, addr_len: int, db_path: str, verify_func) -> Optional[str]:
        """通过公钥模式扫描获取密钥"""
        try:
            import pymem.pattern
            
            key_bytes = b'-----BEGIN PUBLIC KEY-----\n...'
            public_key_list = pymem.pattern.pattern_scan_all(pm.process_handle, key_bytes, return_multiple=True)
            
            if not public_key_list:
                return None
            
            byte_len = addr_len
            key_len_offset = 0x8c if addr_len == 4 else 0xd0
            key_win_dll_offset = 0x90 if addr_len == 4 else 0xd8
            
            for addr in public_key_list:
                key_addr_bytes = addr.to_bytes(byte_len, byteorder="little", signed=True)
                may_addrs = pymem.pattern.pattern_scan_module(pm.process_handle, module, key_addr_bytes, return_multiple=True)
                
                if may_addrs:
                    for found_addr in may_addrs:
                        try:
                            key_len = pm.read_uchar(found_addr - key_len_offset)
                            if key_len == 32:
                                key_ptr = pm.read_longlong(found_addr - key_win_dll_offset) if addr_len == 8 else pm.read_int(found_addr - key_win_dll_offset)
                                key_data = pm.read_bytes(key_ptr, 32)
                                if key_data and verify_func(key_data, db_path):
                                    return key_data.hex()
                        except:
                            continue
            return None
        except:
            return None
    
    def decrypt_database(self, key: str, db_path: str) -> List[str]:
        """解密数据库到临时目录 - 支持3.x和4.x版本"""
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            raise DependencyError("缺少 pycryptodomex 依赖")
        
        if not os.path.exists(db_path):
            raise WeChatError("未找到微信数据库文件")
        
        if len(key) != 64:
            raise WeChatError("密钥格式错误")
        
        self._ensure_temp_dir()
        decrypted_dbs = []
        
        msg_dir = os.path.join(db_path, "MSG")
        if os.path.exists(msg_dir):
            for f in os.listdir(msg_dir):
                if f.endswith('.db'):
                    try:
                        db_file = os.path.join(msg_dir, f)
                        out_path = os.path.join(self.temp_db_dir, f)
                        if self._decrypt_single_db(key, db_file, out_path):
                            decrypted_dbs.append(out_path)
                    except Exception as e:
                        pass
        
        msg0_dir = os.path.join(db_path, "MSG0")
        if os.path.exists(msg0_dir):
            for f in os.listdir(msg0_dir):
                if f.endswith('.db'):
                    try:
                        db_file = os.path.join(msg0_dir, f)
                        out_path = os.path.join(self.temp_db_dir, f"MSG0_{f}")
                        if self._decrypt_single_db(key, db_file, out_path):
                            decrypted_dbs.append(out_path)
                    except Exception as e:
                        pass
        
        msg1_dir = os.path.join(db_path, "MSG1")
        if os.path.exists(msg1_dir):
            for f in os.listdir(msg1_dir):
                if f.endswith('.db'):
                    try:
                        db_file = os.path.join(msg1_dir, f)
                        out_path = os.path.join(self.temp_db_dir, f"MSG1_{f}")
                        if self._decrypt_single_db(key, db_file, out_path):
                            decrypted_dbs.append(out_path)
                    except Exception as e:
                        pass
        
        if not decrypted_dbs:
            for f in os.listdir(db_path):
                if f.endswith('.db'):
                    try:
                        db_file = os.path.join(db_path, f)
                        out_path = os.path.join(self.temp_db_dir, f)
                        if self._decrypt_single_db(key, db_file, out_path):
                            decrypted_dbs.append(out_path)
                    except Exception as e:
                        pass
        
        multi_dir = os.path.join(db_path, "Multi")
        if os.path.exists(multi_dir):
            for f in os.listdir(multi_dir):
                if f.endswith('.db'):
                    try:
                        db_file = os.path.join(multi_dir, f)
                        out_path = os.path.join(self.temp_db_dir, f"Multi_{f}")
                        if self._decrypt_single_db(key, db_file, out_path):
                            decrypted_dbs.append(out_path)
                    except Exception as e:
                        pass
        
        db_storage_dir = os.path.join(db_path, "DBStorage")
        if os.path.exists(db_storage_dir):
            for subdir in os.listdir(db_storage_dir):
                subdir_path = os.path.join(db_storage_dir, subdir)
                if os.path.isdir(subdir_path):
                    for f in os.listdir(subdir_path):
                        if f.endswith('.db'):
                            try:
                                db_file = os.path.join(subdir_path, f)
                                out_path = os.path.join(self.temp_db_dir, f"{subdir}_{f}")
                                if self._decrypt_single_db(key, db_file, out_path):
                                    decrypted_dbs.append(out_path)
                            except Exception as e:
                                pass
        
        if not decrypted_dbs:
            raise WeChatError("数据库解密失败，请尝试重新登录微信")
        
        return decrypted_dbs
    
    def _decrypt_single_db(self, key: str, db_path: str, out_path: str) -> bool:
        """解密单个数据库文件"""
        from Cryptodome.Cipher import AES
        
        password = bytes.fromhex(key.strip())
        with open(db_path, "rb") as file:
            blist = file.read()
        
        salt = blist[:16]
        byte_key = hashlib.pbkdf2_hmac("sha1", password, salt, DEFAULT_ITER, KEY_SIZE)
        first = blist[16:DEFAULT_PAGESIZE]
        
        mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
        mac_key = hashlib.pbkdf2_hmac("sha1", byte_key, mac_salt, 2, KEY_SIZE)
        hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
        hash_mac.update(b'\x01\x00\x00\x00')
        
        if hash_mac.digest() != first[-32:-12]:
            return False
        
        new_blist = [blist[i:i + DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)]
        
        with open(out_path, "wb") as de_file:
            de_file.write(SQLITE_FILE_HEADER.encode())
            cipher = AES.new(byte_key, AES.MODE_CBC, first[-48:-32])
            de_file.write(cipher.decrypt(first[:-48]))
            de_file.write(first[-48:])
            
            for i in new_blist:
                cipher = AES.new(byte_key, AES.MODE_CBC, i[-48:-32])
                de_file.write(cipher.decrypt(i[:-48]))
                de_file.write(i[-48:])
        
        return True
    
    def connect_database(self, db_path: str) -> sqlite3.Connection:
        """连接数据库"""
        try:
            return sqlite3.connect(db_path, check_same_thread=False)
        except Exception as e:
            raise WeChatError(f"无法连接数据库: {e}")
    
    def cleanup(self):
        """清理临时文件"""
        if self.temp_db_dir and os.path.exists(self.temp_db_dir):
            try:
                shutil.rmtree(self.temp_db_dir)
            except:
                pass


class ContactMatcher:
    """联系人匹配器"""
    
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
    
    def get_all_contacts(self) -> List[Dict]:
        """获取所有联系人"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            query = """
            SELECT Contact.UserName, Contact.Alias, Contact.Type, Contact.Remark, 
                   Contact.NickName, Contact.PYInitial, Contact.RemarkPYInitial
            FROM Contact
            INNER JOIN ContactHeadImgUrl ON Contact.UserName = ContactHeadImgUrl.usrName
            WHERE (Type!=4 AND VerifyFlag=0) AND NickName != ''
            """
            cursor.execute(query)
            results = cursor.fetchall()
            cursor.close()
            
            contacts = []
            for r in results:
                contacts.append({
                    'wxid': r[0],
                    'alias': r[1] or '',
                    'remark': r[3] or '',
                    'nickname': r[4] or '',
                    'py_initial': r[5] or '',
                    'remark_py_initial': r[6] or '',
                    'display_name': r[3] if r[3] else r[4]
                })
            return contacts
        except Exception as e:
            return []
    
    def fuzzy_match(self, name: str, contacts: List[Dict] = None) -> List[Dict]:
        """模糊匹配联系人"""
        if contacts is None:
            contacts = self.get_all_contacts()
        
        if not contacts:
            return []
        
        results = []
        name_lower = name.lower().strip()
        
        for contact in contacts:
            score, match_type = self._calculate_similarity(name_lower, contact)
            if score > 0:
                results.append({'contact': contact, 'score': score, 'match_type': match_type})
        
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:10]
    
    def _calculate_similarity(self, name: str, contact: Dict) -> Tuple[float, str]:
        """计算相似度"""
        remark = (contact.get('remark') or '').lower()
        nickname = (contact.get('nickname') or '').lower()
        py_initial = (contact.get('py_initial') or '').lower()
        remark_py_initial = (contact.get('remark_py_initial') or '').lower()
        
        if not name:
            return 0.0, "none"
        
        # 精确匹配
        if remark and name == remark:
            return 1.0, "exact_remark"
        if nickname and name == nickname:
            return 0.95, "exact_nickname"
        
        # 拼音首字母匹配
        try:
            from pypinyin import lazy_pinyin, Style
            name_pinyin = ''.join([p[0] for p in lazy_pinyin(name, style=Style.FIRST_LETTER)]).lower()
            if remark_py_initial and name_pinyin == remark_py_initial.lower():
                return 0.8, "pinyin_remark"
            if py_initial and name_pinyin == py_initial.lower():
                return 0.75, "pinyin_nickname"
        except:
            if remark_py_initial and name == remark_py_initial.lower():
                return 0.8, "pinyin_remark"
        
        # 包含匹配
        if remark and name in remark:
            return 0.6, "contains_remark"
        if nickname and name in nickname:
            return 0.55, "contains_nickname"
        
        # 模糊匹配
        max_score = 0.0
        if remark:
            max_score = max(max_score, SequenceMatcher(None, name, remark).ratio())
        if nickname:
            max_score = max(max_score, SequenceMatcher(None, name, nickname).ratio())
        
        if max_score > 0.4:
            return max_score * 0.4, "fuzzy"
        
        return 0.0, "none"


class ChatExtractor:
    """聊天记录提取器"""
    
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
    
    def get_chat_history(self, wxid: str, months: int = 3) -> List[Dict]:
        """获取聊天记录"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            end_date = datetime.now()
            start_date = end_date - timedelta(days=months * 30)
            
            query = """
            SELECT IsSender, CreateTime, StrContent, 
                   strftime('%Y-%m-%d %H:%M:%S', CreateTime, 'unixepoch', 'localtime') as create_time
            FROM MSG
            WHERE StrTalker = ? AND CreateTime BETWEEN ? AND ? AND Type = 1
            ORDER BY CreateTime DESC LIMIT 100
            """
            
            cursor.execute(query, (wxid, int(start_date.timestamp()), int(end_date.timestamp())))
            results = cursor.fetchall()
            cursor.close()
            
            chat_history = []
            for msg in results:
                if msg[2] and len(msg[2]) > 0:
                    chat_history.append({
                        'is_sender': bool(msg[0]),
                        'timestamp': msg[1],
                        'message': msg[2],
                        'create_time': msg[3]
                    })
            
            chat_history.reverse()
            return chat_history
        except Exception as e:
            return []
    
    def extract_key_info(self, chat_records: List[Dict]) -> Dict:
        """提取关键信息"""
        if not chat_records:
            return {
                "total_messages": 0,
                "sent_messages": 0,
                "received_messages": 0,
                "time_range": "",
                "chat_frequency": "无",
                "key_topics": [],
                "emotional_keywords": [],
                "relationship_hint": "未知"
            }
        
        total = len(chat_records)
        sent = sum(1 for m in chat_records if m['is_sender'])
        received = total - sent
        
        time_range = f"{chat_records[0]['create_time'][:10]} 至 {chat_records[-1]['create_time'][:10]}"
        
        timestamps = [m['timestamp'] for m in chat_records]
        time_span = max(timestamps) - min(timestamps)
        days = max(time_span / 86400, 1)
        freq = "频繁" if total/days > 10 else "较多" if total/days > 3 else "一般" if total/days > 1 else "较少"
        
        topics = self._extract_topics(chat_records)
        keywords = self._extract_emotional_keywords(chat_records)
        relationship = self._analyze_relationship(chat_records, sent, received)
        
        return {
            "total_messages": total,
            "sent_messages": sent,
            "received_messages": received,
            "time_range": time_range,
            "chat_frequency": freq,
            "key_topics": topics,
            "emotional_keywords": keywords,
            "relationship_hint": relationship
        }
    
    def _extract_topics(self, chat_records: List[Dict]) -> List[str]:
        """提取话题"""
        all_text = ' '.join([m['message'] for m in chat_records if m['message']])
        if not all_text:
            return []
        
        try:
            import jieba.analyse
            keywords = jieba.analyse.extract_tags(all_text, topK=5, allowPOS=('n', 'v', 'a'))
            return keywords
        except:
            words = re.findall(r'[\u4e00-\u9fa5]{2,}', all_text)
            return [w for w, _ in Counter(words).most_common(5)]
    
    def _extract_emotional_keywords(self, chat_records: List[Dict]) -> List[str]:
        """提取情感关键词"""
        patterns = [
            r'开心|快乐|高兴|激动|感谢|喜欢|爱|温暖|棒|赞',
            r'难过|伤心|焦虑|压力|疲惫|担心|抱歉|累',
            r'加油|支持|鼓励|期待|希望|努力|祝福|顺利|成功',
            r'辛苦|麻烦|帮助|谢谢|感谢'
        ]
        all_text = ' '.join([m['message'] for m in chat_records if m['message']])
        found = []
        for p in patterns:
            found.extend(re.findall(p, all_text))
        return [w for w, _ in Counter(found).most_common(5)]
    
    def _analyze_relationship(self, chat_records: List[Dict], sent: int, received: int) -> str:
        """分析关系类型"""
        all_text = ' '.join([m['message'] for m in chat_records if m['message']])
        
        work_kw = ['工作', '项目', '需求', '会议', '文档', '代码', '上线', '排期', '产品', '开发']
        family_kw = ['家', '爸妈', '孩子', '家人', '回家', '妈', '爸', '爷爷', '奶奶']
        friend_kw = ['玩', '游戏', '吃饭', '聚会', '旅游', '兄弟', '哥们', '姐妹']
        
        work_c = sum(1 for kw in work_kw if kw in all_text)
        family_c = sum(1 for kw in family_kw if kw in all_text)
        friend_c = sum(1 for kw in friend_kw if kw in all_text)
        
        if work_c > family_c and work_c > friend_c:
            return "工作伙伴"
        elif family_c > work_c and family_c > friend_c:
            return "家人"
        elif friend_c > work_c and friend_c > family_c:
            return "好友"
        elif sent > received * 1.5:
            return "主动联系较多"
        elif received > sent * 1.5:
            return "被动联系较多"
        else:
            return "互动均衡"


def check_wechat_status() -> Dict:
    """检查微信状态"""
    try:
        check_dependencies()
        connector = WeChatConnector()
        
        running, pid = connector.check_wechat_running()
        if not running:
            return {"success": False, "error": "微信未运行", "wechat_running": False}
        
        wechat_info = connector.get_wechat_info()
        return {
            "success": True,
            "wechat_running": True,
            "pid": pid,
            "version": wechat_info.get("version", "未知"),
            "wxid": wechat_info.get("wxid", ""),
            "db_path": wechat_info.get("db_path", ""),
            "key_available": bool(wechat_info.get("key"))
        }
    except DependencyError as e:
        return {"success": False, "error": str(e), "dependency_error": True}
    except WeChatError as e:
        return {"success": False, "error": str(e), "wechat_running": True}
    except Exception as e:
        return {"success": False, "error": f"未知错误: {str(e)}"}


def list_contacts(manual_key: str = None, manual_db_path: str = None) -> Dict:
    """列出所有联系人"""
    connector = None
    try:
        check_dependencies()
        connector = WeChatConnector()
        
        if manual_key and manual_db_path:
            wechat_info = {
                "success": True,
                "key": manual_key,
                "db_path": manual_db_path
            }
        else:
            wechat_info = connector.get_wechat_info()
            if not wechat_info.get("success"):
                return {"success": False, "error": wechat_info.get("error", "获取微信信息失败")}
        
        decrypted_dbs = connector.decrypt_database(wechat_info["key"], wechat_info["db_path"])
        
        micro_msg_db = next((db for db in decrypted_dbs if "MicroMsg.db" in db), None)
        if not micro_msg_db:
            return {"success": False, "error": "未找到联系人数据库"}
        
        conn = connector.connect_database(micro_msg_db)
        matcher = ContactMatcher(conn)
        contacts = matcher.get_all_contacts()
        conn.close()
        
        return {
            "success": True,
            "total": len(contacts),
            "contacts": [{"name": c['display_name'], "remark": c.get('remark', ''), "nickname": c.get('nickname', '')} for c in contacts[:200]]
        }
    except DependencyError as e:
        return {"success": False, "error": str(e), "dependency_error": True}
    except WeChatError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": f"执行出错: {str(e)}"}
    finally:
        if connector:
            connector.cleanup()


def get_chat_data(target_name: str, months: int = 3, manual_key: str = None, manual_db_path: str = None) -> Dict:
    """获取指定联系人的聊天数据"""
    connector = None
    try:
        check_dependencies()
        connector = WeChatConnector()
        
        if manual_key and manual_db_path:
            wechat_info = {
                "success": True,
                "key": manual_key,
                "db_path": manual_db_path
            }
        else:
            wechat_info = connector.get_wechat_info()
            if not wechat_info.get("success"):
                return {"success": False, "error": wechat_info.get("error", "获取微信信息失败")}
        
        decrypted_dbs = connector.decrypt_database(wechat_info["key"], wechat_info["db_path"])
        
        micro_msg_db = next((db for db in decrypted_dbs if "MicroMsg.db" in db), None)
        msg_db = next((db for db in decrypted_dbs if "MSG.db" in db or "MSG" in db), None)
        
        if not micro_msg_db:
            return {"success": False, "error": "未找到联系人数据库"}
        
        micro_msg_conn = connector.connect_database(micro_msg_db)
        matcher = ContactMatcher(micro_msg_conn)
        contacts = matcher.get_all_contacts()
        
        if not contacts:
            return {"success": False, "error": "未找到任何联系人"}
        
        matched = matcher.fuzzy_match(target_name, contacts)
        
        if not matched:
            return {
                "success": False,
                "error": "未找到匹配的联系人",
                "suggestions": [c['display_name'] for c in contacts[:10]]
            }
        
        best_match = matched[0]
        contact_info = best_match['contact']
        
        if best_match['score'] < 0.4:
            return {
                "success": False,
                "error": "联系人匹配不确定",
                "candidates": [m['contact']['display_name'] for m in matched[:5]],
                "best_match": contact_info['display_name'],
                "match_score": best_match['score']
            }
        
        chat_records = []
        chat_summary = {}
        
        if msg_db:
            msg_conn = connector.connect_database(msg_db)
            if msg_conn:
                extractor = ChatExtractor(msg_conn)
                chat_records = extractor.get_chat_history(contact_info['wxid'], months)
                chat_summary = extractor.extract_key_info(chat_records)
                msg_conn.close()
        
        if not chat_records:
            chat_summary = {
                "total_messages": 0,
                "sent_messages": 0,
                "received_messages": 0,
                "time_range": "",
                "chat_frequency": "无",
                "key_topics": [],
                "emotional_keywords": [],
                "relationship_hint": "未知"
            }
        
        return {
            "success": True,
            "contact_info": {
                "name": contact_info.get('display_name', ''),
                "wxid": contact_info.get('wxid', ''),
                "remark": contact_info.get('remark', ''),
                "nickname": contact_info.get('nickname', '')
            },
            "match_info": {
                "score": best_match['score'],
                "match_type": best_match['match_type']
            },
            "chat_summary": chat_summary,
            "chat_records": [
                {"time": m['create_time'], "content": m['message'], "is_sender": m['is_sender']}
                for m in chat_records[-50:]
            ]
        }
        
    except DependencyError as e:
        return {"success": False, "error": str(e), "dependency_error": True}
    except WeChatError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": f"执行出错: {str(e)}"}
    finally:
        if connector:
            connector.cleanup()


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="微信祝福Skill - 数据库连接器")
    parser.add_argument("--check", action="store_true", help="检查微信状态")
    parser.add_argument("--list-contacts", action="store_true", help="列出所有联系人")
    parser.add_argument("--name", type=str, help="联系人名称")
    parser.add_argument("--months", type=int, default=3, help="时间范围（月）")
    parser.add_argument("--key", type=str, help="手动输入密钥（64位十六进制）")
    parser.add_argument("--db-path", type=str, help="手动输入数据库路径")
    
    args = parser.parse_args()
    
    if args.check:
        result = check_wechat_status()
    elif args.list_contacts:
        result = list_contacts(args.key, args.db_path)
    elif args.name:
        result = get_chat_data(args.name, args.months, args.key, args.db_path)
    else:
        parser.print_help()
        return 1
    
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
