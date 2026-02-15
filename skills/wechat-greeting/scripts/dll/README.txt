wx_key.dll 存放目录
==================

此目录用于存放 wx_key.dll 文件，该DLL用于获取微信4.0+版本的数据库密钥。

如何获取 wx_key.dll:
1. 自动下载：运行 python ../wx_key_integration.py --setup
2. 手动下载：从 https://github.com/ycccccccy/wx_key/releases 下载 app.zip，解压后将 wx_key.dll 放到此目录

注意事项：
- DLL文件不要放在包含中文的路径下
- 需要以管理员权限运行
- 获取密钥时需要微信处于运行状态

基于项目: https://github.com/ycccccccy/wx_key
