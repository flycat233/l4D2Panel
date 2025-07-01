from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, jsonify, Blueprint
import os
import re
import datetime
from flask_cors import CORS
import requests
import subprocess
import psutil
import random
import string
from rcon.source import Client
import threading
import time
import socket  # 新增导入 socket 模块

# 新增 is_port_in_use 函数
def is_port_in_use(port, host='127.0.0.1'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

UPLOAD_FOLDER = r'D:\SteamLibrary\steamapps\common\Left 4 Dead 2 Dedicated Server\left4dead2\addons'
ALLOWED_EXTENSIONS = {'vpk'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'supersecretkey'
CORS(app)

# 钉钉 Webhook 地址，需要确保这里只定义一次
DINGTALK_WEBHOOK = 'https://oapi.dingtalk.com/robot/send?access_token='

import random
import string

# 固定密码
FIXED_PASSWORD = "自定义"
# 用于存储临时重启密码
TEMP_RESTART_PASSWORD = None

# 待删除的文件列表
files_to_delete = []

def send_dingtalk_message(message):
    headers = {
        'Content-Type': 'application/json'
    }
    data = {
        "msgtype": "text",
        "text": {
            "content": message
        }
    }
    try:
        response = requests.post(DINGTALK_WEBHOOK, json=data, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"发送钉钉消息失败: {e}")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def format_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024**3:
        return f"{size / (1024**2):.2f} MB"
    else:
        return f"{size / (1024**3):.2f} GB"

@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    vpk_files = [f for f in files if f.endswith('.vpk')]
    file_info = []
    for file in vpk_files:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file)
        size = os.path.getsize(filepath)
        mtime = os.path.getmtime(filepath)  # 获取文件修改时间戳
        upload_time = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        file_info.append({'name': file, 'size': format_size(size), 'upload_time': upload_time, 'mtime': mtime})
    # 按时间戳由大到小排序（时间由近至远）
    file_info.sort(key=lambda x: x['mtime'], reverse=True)
    # 去除 mtime 字段，因为前端不需要这个
    file_info = [{'name': item['name'], 'size': item['size'], 'upload_time': item['upload_time']} for item in file_info]
    return render_template('index.html', vpk_files=file_info)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    files = request.files.getlist('file')  # 获取所有上传的文件
    if not files:
        flash('No selected file')
        return redirect(request.url)
    uploaded_files = []
    for file in files:
        if file and allowed_file(file.filename):
            original_filename = file.filename
            safe_filename = re.sub(r'[\\/*?:"<>|]', '_', original_filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], safe_filename))
            uploaded_files.append(safe_filename)
        else:
            flash(f'Invalid file type: {file.filename}')
    if uploaded_files:
        message = f"有人上传了以下地图文件: {', '.join(uploaded_files)}"
        send_dingtalk_message(message)
    flash('Files successfully uploaded')
    return redirect(url_for('index'))

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

import logging
from flask import Flask, request, jsonify
import os

# 配置日志
logging.basicConfig(level=logging.INFO)

@app.route('/download/<filename>')
def download(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return "文件未找到", 404

# 修改删除文件路由
@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    global files_to_delete
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if check_running_server():
        if file_path not in files_to_delete:
            files_to_delete.append(file_path)
        return jsonify({"status": "pending", "message": "删除申请已提交，地图将在服务器关闭时删除"})
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            message = f"有人删除了地图文件: {filename}"
            send_dingtalk_message(message)
            logging.debug(f"文件 {filename} 删除成功")
            return jsonify({"status": "success", "message": "File successfully deleted"})
        else:
            logging.debug(f"文件 {filename} 不存在，无法删除")
            return jsonify({"status": "error", "message": "文件不存在，无法删除"})
    except PermissionError:
        logging.error(f"文件 {filename} 被占用，删除失败")
        return jsonify({"status": "error", "message": "删除失败，请先关闭服务器后重试"})
    except Exception as e:
        logging.error(f"删除文件 {filename} 时出错: {e}")
        return jsonify({"status": "error", "message": f"删除文件时出错: {e}"})

import psutil
import time

# 全局变量，用于存储 subprocess.Popen 创建的服务器进程
subprocess_server_process = None
# 全局变量，用于存储 psutil.Process 类型的服务器进程
psutil_server_process = None
# 监控线程事件，用于控制线程的停止
monitor_thread_event = threading.Event()
# 控制服务器检测的标志
should_monitor = True
# 服务器启动标志，避免重复启动
server_starting = False

# 检测是否有正在运行的求生之路服务器
def check_running_server():
    global psutil_server_process
    for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
        try:
            name = proc.info['name']
            exe_path = proc.info['exe']
            cmdline = proc.info['cmdline']
            if name == 'srcds.exe':
                if exe_path and 'left 4 dead 2' in exe_path.lower():
                    psutil_server_process = proc
                    logging.info(f"找到求生之路 2 服务器进程，PID: {proc.pid}")
                    return True
                elif cmdline and any('left4dead2' in arg.lower() for arg in cmdline):
                    psutil_server_process = proc
                    logging.info(f"找到求生之路 2 服务器进程，PID: {proc.pid}")
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    logging.info("未找到求生之路 2 服务器进程")
    return False

def start_server():
    global subprocess_server_process, should_monitor, server_starting
    if server_starting:
        logging.info("服务器正在启动中，避免重复启动")
        return False
    if check_running_server():
        logging.error("服务器已经在运行，无法再次启动")
        return False
    try:
        if is_port_in_use(27015):
            logging.error("端口 27015 已被占用，无法启动服务器")
            return False
        command = [
            r'D:\SteamLibrary\steamapps\common\Left 4 Dead 2 Dedicated Server\srcds.exe', '-console', '-game', 'left4dead2', '-maxplayers', '16',
            '+map', 'c1m1_hotel', '-ip', ' 172.16.0.3', '-port', '27015', '-usercon',
            '+rcon_password', 'rconpassword', '-insecure', '+exec', 'server.cfg', '+sv_lan', '0',
            '-tickrate', '100'
        ]
        if not os.path.exists(command[0]):
            logging.error(f"srcds.exe 路径不存在: {command[0]}")
            return False
        # 先停止所有已存在的服务器进程
        stop_all_servers()
        server_starting = True  # 设置服务器启动标志
        subprocess_server_process = subprocess.Popen(command)
        # 延长循环检查服务器启动的时间，将最大尝试次数从 30 增加到 60
        max_attempts = 60  # 延长到 60 秒
        for _ in range(max_attempts):
            if check_running_server():
                should_monitor = True  # 启动服务器后开启监控
                server_starting = False  # 服务器启动成功，清除标志
                # 获取服务器信息
                server_info = get_server_info()
                # 构建钉钉消息
                message = "服务器已成功启动！\n"
                message += f"服务器状态: {server_info['status']}\n"
                message += f"运行时间: {server_info['run_time']}\n"
                message += f"当前地图: {server_info['current_map']}\n"
                message += f"当前玩家数: {server_info['player_count']}\n"
                if server_info['players']:
                    message += "玩家列表:\n" + '\n'.join([f"- {player}" for player in server_info['players']])
                else:
                    message += "玩家列表: 无"
                # 发送钉钉消息
                send_dingtalk_message(message)
                return True
            time.sleep(1)
        logging.error("服务器在 60 秒内未成功启动")
        server_starting = False  # 服务器启动失败，清除标志
        return False
    except Exception as e:
        logging.error(f"启动服务器失败: {e}")
        server_starting = False  # 出现异常，清除标志
        return False

def stop_all_servers():
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            if proc.info['name'] == 'srcds.exe' and 'l4d2' in proc.info['exe']:
                proc.terminate()
                _, still_alive = psutil.wait_procs([proc], timeout=5)
                for p in still_alive:
                    p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def stop_server():
    global subprocess_server_process, psutil_server_process, should_monitor, files_to_delete
    should_monitor = False  # 停止服务器时关闭监控
    logging.info(f"当前 subprocess_server_process: {subprocess_server_process}")
    if psutil_server_process is not None:
        try:
            children = psutil_server_process.children(recursive=True)
            logging.info(f"子进程: {children}")
            for child in children:
                child.terminate()
            _, still_alive = psutil.wait_procs(children, timeout=5)
            for p in still_alive:
                p.kill()
            psutil_server_process.terminate()
            psutil_server_process.wait(timeout=5)
            subprocess_server_process = None
            psutil_server_process = None
            # 删除待删除的文件
            for file_path in files_to_delete:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        filename = os.path.basename(file_path)
                        message = f"服务器关闭时删除了地图文件: {filename}"
                        send_dingtalk_message(message)
                        logging.debug(f"文件 {filename} 删除成功")
                    except Exception as e:
                        logging.error(f"删除文件 {file_path} 时出错: {e}")
            files_to_delete = []
            return True
        except Exception as e:
            logging.error(f"停止服务器失败: {e}")
            return False
    return False

# 全局变量，用于存储上一次的玩家列表
last_players = []
# 新增全局变量，用于记录已经发送过通知的新玩家
notified_new_players = set()

def monitor_server():
    global should_monitor, last_players, notified_new_players
    while not monitor_thread_event.is_set():
        if should_monitor:
            try:
                server_running = check_running_server()

                if not server_running:
                    logging.warning("服务器已停止，尝试重新启动...")
                    if start_server():
                        send_dingtalk_message("服务器已意外停止，现已重新启动！")
                    else:
                        send_dingtalk_message("服务器已意外停止，尝试重新启动失败，请检查！")
                else:
                    # 获取当前服务器信息
                    server_info = get_server_info()
                    current_players = server_info['players']
                    # 找出新加入的玩家
                    new_players = [player for player in current_players if player not in last_players and player not in notified_new_players]
                    if new_players:
                        message = f"有新玩家加入服务器: {', '.join(new_players)}"
                        send_dingtalk_message(message)
                        # 将新通知的玩家添加到已通知集合中
                        notified_new_players.update(new_players)
                    # 更新上一次的玩家列表
                    last_players = current_players
                    # 移除已经离开的玩家
                    notified_new_players = {player for player in notified_new_players if player in current_players}

            except Exception as e:
                logging.error(f"监控服务器时出错: {e}")
        time.sleep(60)  # 每 60 秒检查一次

# 添加新的路由
# 修改启动服务器路由
@app.route('/start_server', methods=['POST'])
def start_server_route():
    password = request.json.get('password')
    if password != FIXED_PASSWORD:
        return jsonify({"status": "error", "message": "密码错误，启动失败"})
    if start_server():
        send_dingtalk_message("服务器已成功启动！")
        return jsonify({"status": "success", "message": "服务器已启动"})
    else:
        send_dingtalk_message("服务器启动失败，请检查！")
        return jsonify({"status": "error", "message": "服务器启动失败"})

# 修改停止服务器路由
@app.route('/stop_server', methods=['POST'])
def stop_server_route():
    password = request.json.get('password')
    if password != FIXED_PASSWORD:
        return jsonify({"status": "error", "message": "密码错误，停止失败"})
    if stop_server():
        send_dingtalk_message("服务器已成功停止！")
        return jsonify({"status": "success", "message": "服务器已停止"})
    else:
        send_dingtalk_message("服务器停止失败，请检查！")
        return jsonify({"status": "error", "message": "服务器停止失败"})

class RCONManager:
    def __init__(self, address, password):
        self.address = address
        self.password = password
        self.logger = logging.getLogger('RCONManager')

    def execute_command(self, command):
        try:
            host, port = self.address
            self.logger.info(f"准备连接到 RCON 服务器，地址: {self.address}，密码: {self.password}")
            with Client(host, port, passwd=self.password) as client:
                self.logger.info("成功建立 RCON 连接")
                response = client.run(command)
                return self.decode_response(response)
        except Exception as e:
            self.logger.error(f"执行 RCON 命令 {command} 失败，错误详情: {e}")
            return None

    def decode_response(self, response_text):
        """
        尝试多种编码方式对响应文本进行解码
        :param response_text: 原始响应文本
        :return: 解码后的字符串
        """
        # 调整编码顺序，优先尝试 gbk 和 utf-8
        encodings = ['gbk', 'utf-8', 'latin1', 'ascii']
        for encoding in encodings:
            try:
                if isinstance(response_text, bytes):
                    return response_text.decode(encoding)
                else:
                    return str(response_text)
            except UnicodeDecodeError:
                continue
        # 如果所有编码都失败，使用替换方式处理
        try:
            if isinstance(response_text, bytes):
                return response_text.decode('utf-8', errors='replace')
            else:
                return str(response_text)
        except Exception:
            return str(response_text)

RCON_ADDRESS = ('内网IP', 27015)
RCON_PASSWORD = 'rconpassword'
rcon_manager = RCONManager(RCON_ADDRESS, RCON_PASSWORD)

def parse_status_response(status_text):
    lines = status_text.split('\n')
    players = []
    current_map = ''
    player_count = 0
    run_time = '未知'

    # 定义求生之路一、二代 8 人名字列表
    l4d_characters = [
        "Bill", "Francis", "Louis", "Zoey",
        "Coach", "Nick", "Ellis", "Rochelle"
    ]
    # 定义求生之路一、二部特感名字列表
    special_infected = [
        "Boomer", "Hunter", "Smoker", "Tank", "Witch",
        "Charger", "Jockey", "Spitter", "Commando", "Bile Ogre"
    ]
    l4d_characters_lower = [name.lower() for name in l4d_characters]
    special_infected_lower = [name.lower() for name in special_infected]

    # 解析当前地图
    for line in lines:
        if 'map' in line:
            parts = line.split(':')
            if len(parts) > 1:
                current_map = parts[1].strip()
            break

    # 解析在线玩家数量
    for line in lines:
        if 'players' in line:
            parts = line.split(':')
            if len(parts) > 1:
                player_part = parts[1].split('humans')[0].strip()
                try:
                    player_count = int(player_part)
                except ValueError:
                    logging.error(f"无法将 {player_part} 转换为整数")
            break

    # 解析玩家列表
    userid_index = -1
    for i, line in enumerate(lines):
        if 'userid' in line:
            userid_index = i
            break
    if userid_index != -1:
        for player_line in lines[userid_index + 1:]:
            if not player_line.strip():
                break
            parts = player_line.split('"')
            if len(parts) > 1:
                player_name = parts[1]
                # 去除 (数字) 格式的前缀
                cleaned_name = re.sub(r'\(\d+\)\s*', '', player_name).strip()
                # 过滤掉包含 (bot) 的玩家名称、求生之路一、二代 8 人名字和特感名字
                if "(bot)" not in cleaned_name.lower() and cleaned_name.lower() not in l4d_characters_lower and cleaned_name.lower() not in special_infected_lower:
                    players.append(player_name)

    # 解析运行时间（从 hostname 中提取）
    for line in lines:
        if 'hostname' in line:
            start_index = line.find('[计时:')
            if start_index != -1:
                start_index += len('[计时:')
                end_index = line.find(']', start_index)
                if end_index != -1:
                    run_time = line[start_index:end_index]
            break

    # 假设只要能获取到 status 信息，服务器就是运行中的
    server_status = '运行中'

    return {
        'status': server_status,
        'run_time': run_time,
        'current_map': current_map,
        'player_count': len(players),  # 更新玩家数量为实际玩家数
        'players': players
    }


def get_server_info():
    try:
        status_text = rcon_manager.execute_command('status')
        if status_text is not None:
            logging.info(f"执行 'status' 命令的响应: {status_text}")
            return parse_status_response(status_text)
        else:
            logging.error("执行 'status' 命令失败")
            return {
                'status': '未知',
                'run_time': '未知',
                'current_map': '未知',
                'player_count': 0,
                'players': []
            }
    except Exception as e:
        logging.error(f"获取服务器信息失败，错误详情: {e}")
        return {
            'status': '未知',
            'run_time': '未知',
            'current_map': '未知',
            'player_count': 0,
            'players': []
        }


def generate_random_password():
    global TEMP_RESTART_PASSWORD
    characters = string.digits
    TEMP_RESTART_PASSWORD = ''.join(random.choice(characters) for i in range(6))
    # 获取服务器信息
    server_info = get_server_info()
    message = f"服务器重启临时密码: {TEMP_RESTART_PASSWORD}\n"
    message += f"服务器状态: {server_info['status']}\n"
    message += f"运行时间: {server_info['run_time']}\n"
    message += f"当前地图: {server_info['current_map']}\n"
    message += f"当前玩家数: {server_info['player_count']}\n"
    if server_info['players']:
        message += "玩家列表:\n" + '\n'.join([f"- {player}" for player in server_info['players']])
    else:
        message += "玩家列表: 无"
    send_dingtalk_message(message)
    return TEMP_RESTART_PASSWORD

# 新增重启服务器路由
@app.route('/restart_server', methods=['POST'])
def restart_server_route():
    global TEMP_RESTART_PASSWORD, subprocess_server_process, psutil_server_process
    password = request.json.get('password')
    if password != TEMP_RESTART_PASSWORD:
        return jsonify({"status": "error", "message": "密码错误，重启失败"})
    if stop_server():
        if start_server():
            send_dingtalk_message("服务器已成功重启！")
            TEMP_RESTART_PASSWORD = None
            return jsonify({"status": "success", "message": "服务器已重启"})
    send_dingtalk_message("服务器重启失败，请检查！")
    return jsonify({"status": "error", "message": "服务器重启失败"})

# 新增请求重启密码路由
@app.route('/request_restart_password', methods=['POST'])
def request_restart_password():
    random_password = generate_random_password()
    return jsonify({"status": "success", "message": "已发送重启密码和服务器信息到钉钉"})

# 定义 steamcmd 路径和下载目录
STEAMCMD_PATH = r'D:\ServerManager\steamcmd.exe'
DOWNLOAD_DIR = r'D:\SteamLibrary\steamapps\common\Left 4 Dead 2 Dedicated Server\left4dead2\addons'

@app.route('/download_workshop', methods=['POST'])
def download_workshop():
    data = request.json
    logging.info('接收到下载请求，数据: %s', data)

    workshop_id = data.get('workshop_id')
    steam_username = data.get('steam_username')
    steam_password = data.get('steam_password')
    two_factor_code = data.get('two_factor_code')

    if not workshop_id:
        logging.info("未提供 Steam 创意工坊 ID")
        return jsonify({"status": "error", "message": "未提供 Steam 创意工坊 ID"})

    if not steam_username or not steam_password:
        logging.info("未提供 Steam 账号或密码")
        return jsonify({"status": "error", "message": "未提供 Steam 账号或密码"})

    max_retries = 3  # 最大重试次数
    retries = 0

    while retries < max_retries:
        try:
            # 检查 steamcmd 路径是否存在且可执行
            if not os.path.exists(STEAMCMD_PATH):
                logging.error(f"steamcmd 路径不存在: {STEAMCMD_PATH}")
                return jsonify({"status": "error", "message": "steamcmd 路径不存在"})
            if not os.access(STEAMCMD_PATH, os.X_OK):
                logging.error(f"steamcmd 文件不可执行: {STEAMCMD_PATH}")
                return jsonify({"status": "error", "message": "steamcmd 文件不可执行"})

            command = [
                STEAMCMD_PATH,
                '+login', steam_username, steam_password
            ]

            if two_factor_code:
                command.append(two_factor_code)

            command.extend([
                '+workshop_download_item', '550', workshop_id,
                '+quit'
            ])

            # 构建在新的 DOS 窗口中运行 steamcmd 的命令
            cmd_command = f'start cmd /k "{STEAMCMD_PATH} {" ".join(command[1:])}"'
            logging.info(f"即将执行的命令: {cmd_command}")

            # 以新进程打开 DOS 窗口运行命令
            subprocess.Popen(cmd_command, shell=True)

            # 因为在新窗口异步执行，直接返回成功提示
            message = f"已在新的 DOS 窗口中启动 SteamCMD 下载创意工坊项目 {workshop_id}"
            send_dingtalk_message(message)
            return jsonify({"status": "success", "message": message})

        except Exception as e:
            logging.error(f"处理下载文件时出错: {e}")
            if retries < max_retries - 1:
                logging.info(f"第 {retries + 1} 次执行出错，尝试重试...")
                retries += 1
                continue
            else:
                return jsonify({"status": "error", "message": f"处理下载文件时出错: {e}"})

        # 将 subprocess.run 及其错误处理逻辑移到 while 循环内
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            shell=True,  # 使用 shell 模式执行命令
            timeout=1200,  # 延长超时时间到 20 分钟
            encoding='utf-8',  # 修改为 utf-8
            errors='replace'  # 避免解码错误
        )

        logging.info(f"命令执行结果 - 标准输出: {result.stdout}")
        logging.info(f"命令执行结果 - 标准错误: {result.stderr}")
        logging.info(f"命令返回码: {result.returncode}")

        # 检查是否密码错误
        if "ERROR (Invalid Password)" in result.stdout:
            error_msg = "Steam 账号密码错误，请检查后重试"
            logging.error(error_msg)
            return jsonify({"status": "error", "message": error_msg})
        # 处理两步验证
        if "Two-factor code required" in result.stdout or "Two-factor code required" in result.stderr:
            logging.info("检测到需要手机令牌，返回相应提示")
            return jsonify({"status": "pending", "need_2fa": True, "message": "需要输入手机令牌", "workshop_id": workshop_id, "steam_username": steam_username, "steam_password": steam_password})
        # 检查是否需要邮箱验证码
        elif "Email code required" in result.stdout:
            error_msg = "需要邮箱验证码，请检查邮箱并重新提交"
            logging.error(error_msg)
            return jsonify({"status": "pending", "need_email_code": True, "message": error_msg})
        # 检查是否需要人机验证
        elif "Captcha required" in result.stdout:
            error_msg = "需要进行人机验证，请在网页端完成验证后重试"
            logging.error(error_msg)
            return jsonify({"status": "error", "message": error_msg})

        if result.returncode != 0:
            error_msg = f"下载失败: {result.stderr}"
            logging.error(error_msg)
            if retries < max_retries - 1:
                logging.info(f"第 {retries + 1} 次执行失败，尝试重试...")
                retries += 1
                continue
            else:
                return jsonify({"status": "error", "message": error_msg})

        # 查找下载的 vpk 文件并移动到指定目录、重命名
        download_path = os.path.join('steamapps', 'workshop', 'content', '550', workshop_id)
        if not os.path.exists(download_path):
            logging.error(f"下载路径 {download_path} 不存在")
            if retries < max_retries - 1:
                logging.info(f"第 {retries + 1} 次未找到下载路径，尝试重试...")
                retries += 1
                continue
            else:
                return jsonify({"status": "error", "message": f"下载路径 {download_path} 不存在"})

        # 检查目标目录写入权限
        if not os.access(DOWNLOAD_DIR, os.W_OK):
            logging.error(f"目标目录 {DOWNLOAD_DIR} 没有写入权限")
            return jsonify({"status": "error", "message": f"目标目录 {DOWNLOAD_DIR} 没有写入权限"})

        found_file = False
        for root, dirs, files in os.walk(download_path):
            for file in files:
                if file.endswith('.vpk'):
                    source_path = os.path.join(root, file)
                    new_filename = f"{workshop_id}_{file}"
                    destination_path = os.path.join(DOWNLOAD_DIR, new_filename)

                    # 确保目标目录存在
                    if not os.path.exists(DOWNLOAD_DIR):
                        os.makedirs(DOWNLOAD_DIR)

                    logging.info(f"准备将文件 {source_path} 移动到 {destination_path}")
                    try:
                        os.rename(source_path, destination_path)
                        message = f"成功下载并移动创意工坊文件: {new_filename}"
                        send_dingtalk_message(message)
                        found_file = True
                        return jsonify({"status": "success", "message": message})
                    except Exception as e:
                        error_msg = f"移动文件 {source_path} 到 {destination_path} 时出错: {e}"
                        logging.error(error_msg)
                        return jsonify({"status": "error", "message": error_msg})

        if not found_file:
            logging.error("未找到下载的 VPK 文件")
            if retries < max_retries - 1:
                logging.info(f"第 {retries + 1} 次未找到 VPK 文件，尝试重试...")
                retries += 1
                continue
            else:
                return jsonify({"status": "error", "message": "未找到下载的 VPK 文件"})

        return jsonify({"status": "error", "message": "多次尝试后仍失败，请检查相关设置"})

@app.route('/get_server_info', methods=['POST'])
def get_server_info_route():
    server_info = get_server_info()
    # 构建钉钉消息
    message = f"服务器状态: {server_info['status']}\n"
    message += f"运行时间: {server_info['run_time']}\n"
    message += f"当前地图: {server_info['current_map']}\n"
    message += f"当前玩家数: {server_info['player_count']}\n"
    if server_info['players']:
        message += "玩家列表:\n" + '\n'.join([f"- {player}" for player in server_info['players']])
    else:
        message += "玩家列表: 无"
    send_dingtalk_message(message)
    return jsonify(server_info)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    # 检测是否有正在运行的服务器
    if not check_running_server():
        print("未检测到正在运行的求生之路服务器，尝试启动新服务器...")
        if not start_server():
            print("启动新服务器失败，请检查配置。")
            exit(1)

    # 启动监控线程
    monitor_thread = threading.Thread(target=monitor_server)
    monitor_thread.start()
    try:
        app.run(host='0.0.0.0', port=27016, debug=True)
    finally:
        # 当 Flask 应用停止时，停止监控线程
        monitor_thread_event.set()
        monitor_thread.join()