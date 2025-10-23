import time
import os
import subprocess
import threading
import select
import json

from flask import request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from collections import deque

from server import app, auth, reloader
from server.db import database
from server.db.models import FlagStatus, Task
from server.spam import is_spam_flag
from werkzeug.utils import secure_filename
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")

MAX_LOG_LINES = 1000
running_processes = {}
process_logs = {}

def log_reader(process, filename, stdout, stderr):
    """Чтение вывода процесса и сохранение в лог"""
    print(f"Starting log reader for {filename}, PID: {process.pid}")
    
    # Создаем хранилище логов для этого процесса
    process_logs[filename] = deque(maxlen=MAX_LOG_LINES)
    
    try:
        while process.poll() is None:
            # Используем select для неблокирующего чтения
            reads = [stdout, stderr]
            ret = select.select(reads, [], [], 0.1)
            
            for fd in ret[0]:
                if fd == stdout:
                    line = stdout.readline()
                    if line:
                        line = line.decode('utf-8', errors='replace').rstrip()
                        process_logs[filename].append({
                            'timestamp': time.time(),
                            'type': 'stdout',
                            'message': line
                        })
                        print(f"STDOUT [{filename}]: {line}")
                
                if fd == stderr:
                    line = stderr.readline()
                    if line:
                        line = line.decode('utf-8', errors='replace').rstrip()
                        process_logs[filename].append({
                            'timestamp': time.time(),
                            'type': 'stderr',
                            'message': line
                        })
                        print(f"STDERR [{filename}]: {line}")
            
            time.sleep(0.05)
        
        print(f"Process {filename} finished, reading remaining output...")
        
        # Читаем оставшиеся данные после завершения процесса
        remaining_stdout, remaining_stderr = process.communicate()
        
        if remaining_stdout:
            lines = remaining_stdout.decode('utf-8', errors='replace').splitlines()
            for line in lines:
                process_logs[filename].append({
                    'timestamp': time.time(),
                    'type': 'stdout',
                    'message': line
                })
                print(f"STDOUT (remaining) [{filename}]: {line}")
        
        if remaining_stderr:
            lines = remaining_stderr.decode('utf-8', errors='replace').splitlines()
            for line in lines:
                process_logs[filename].append({
                    'timestamp': time.time(),
                    'type': 'stderr',
                    'message': line
                })
                print(f"STDERR (remaining) [{filename}]: {line}")
                
        print(f"Log reader for {filename} finished. Total logs: {len(process_logs[filename])}")
            
    except Exception as e:
        error_msg = f"Error in log reader for {filename}: {str(e)}"
        print(error_msg)
        process_logs[filename].append({
            'timestamp': time.time(),
            'type': 'stderr',
            'message': error_msg
        })

@app.route('/scripts/<path:filename>')
@auth.auth_required
def download_script(filename):
    return send_from_directory(SCRIPTS_DIR, filename, as_attachment=True)


@app.route('/api/get_config')
@auth.api_auth_required
def get_config():
    config = reloader.get_config()
    return jsonify({key: value for key, value in config.items()
                    if 'PASSWORD' not in key and 'TOKEN' not in key})


@app.route('/api/post_flags', methods=['POST'])
@auth.api_auth_required
def post_flags():
    flags = request.get_json()
    flags = [item for item in flags if not is_spam_flag(item['flag'])]

    cur_time = round(time.time())
    rows = [(item['flag'], item['sploit'], item['team'], item.get('task', 'default'), cur_time, FlagStatus.QUEUED.name)
            for item in flags]

    db = database.get()
    db.executemany("INSERT OR IGNORE INTO flags (flag, sploit, team, task, time, status) "
                   "VALUES (?, ?, ?, ?, ?, ?)", rows)
    db.commit()

    return ''

@app.route('/api/scripts')
@auth.auth_required
def get_scripts():
    """Get list of all script files"""
    try:
        files = []
        for filename in os.listdir(SCRIPTS_DIR):
            file_path = os.path.join(SCRIPTS_DIR, filename)
            if os.path.isfile(file_path):
                stat = os.stat(file_path)
                files.append({
                    'name': filename,
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'download_url': f'/scripts/{filename}'
                })
        
        # Sort by modification time (newest first)
        files.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify(files)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload_script', methods=['POST'])
@auth.auth_required
def upload_script():
    file = request.files.get('file')  # может быть None
    if not file or not file.filename:
        return jsonify({"error": "No file selected"}), 400

    # Теперь точно str, можно безопасно использовать secure_filename
    filename = secure_filename(file.filename)

    if filename == '':
        return jsonify({"error": "Invalid file name"}), 400

    save_path = os.path.join(SCRIPTS_DIR, filename)
    file.save(save_path)

    return jsonify({"message": f"File '{filename}' uploaded successfully."}), 200

@app.route('/api/delete_script/<filename>', methods=['DELETE'])
@auth.auth_required
def delete_script(filename):
    """Delete a script file"""
    try:
        # Security check to prevent path traversal
        safe_filename = secure_filename(filename)
        if safe_filename != filename:
            return jsonify({"error": "Invalid filename"}), 400
            
        file_path = os.path.join(SCRIPTS_DIR, safe_filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
            
        # Если скрипт запущен, останавливаем его
        if safe_filename in running_processes:
            process_info = running_processes[safe_filename]
            process_info['process'].terminate()
            try:
                process_info['process'].wait(timeout=5)
            except subprocess.TimeoutExpired:
                process_info['process'].kill()
            del running_processes[safe_filename]
            
        # Удаляем логи
        if safe_filename in process_logs:
            del process_logs[safe_filename]
            
        os.remove(file_path)
        return jsonify({"message": f"File '{safe_filename}' deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run_script/<filename>', methods=['POST'])
@auth.auth_required
def run_script(filename):
    """Run a script file"""
    try:
        # Security check to prevent path traversal
        safe_filename = secure_filename(filename)
        if safe_filename != filename:
            return jsonify({"error": "Invalid filename"}), 400
            
        file_path = os.path.join(SCRIPTS_DIR, safe_filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        # Проверяем, не запущен ли уже этот скрипт
        if safe_filename in running_processes:
            return jsonify({"error": "Script is already running"}), 400

        # Получаем URL сервера и task из запроса
        config = reloader.get_config()
        server_url = request.json.get('server_url') if request.json else None
        task = request.json.get('task', '') if request.json else ''  # Получаем task из запроса
        
        if not server_url:
            # Используем URL из конфигурации или дефолтный
            server_url = f"http://{config.get('SERVER_HOST', 'localhost')}:{config.get('SERVER_PORT', 5000)}"

        # Путь к start_sploit.py
        start_sploit_path = os.path.join(PROJECT_ROOT, "start_sploit.py")
        
        if not os.path.exists(start_sploit_path):
            return jsonify({"error": "start_sploit.py not found"}), 500

        # Делаем скрипт исполняемым
        if not os.access(file_path, os.X_OK):
            os.chmod(file_path, 0o755)

        # Запускаем скрипт через start_sploit.py
        cmd = [
            'python', start_sploit_path,
            file_path,
            '-u', server_url
        ]

        # Добавляем task, если указан
        if task:
            cmd.extend(['--task', task])

        # Добавляем токен, если он есть в конфигурации
        if config.get('TOKEN'):
            cmd.extend(['--token', config['TOKEN']])

        print(f"Starting command: {' '.join(cmd)}")

        # Запускаем процесс с отдельными каналами stdout/stderr
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=False,  # Важно для корректной работы с байтами
            cwd=PROJECT_ROOT
        )

        # Запускаем поток для чтения логов
        log_thread = threading.Thread(
            target=log_reader,
            args=(process, safe_filename, process.stdout, process.stderr),
            daemon=True
        )
        log_thread.start()

        # Сохраняем информацию о процессе
        running_processes[safe_filename] = {
            'process': process,
            'start_time': time.time(),
            'command': ' '.join(cmd),
            'status': 'running',
            'log_thread': log_thread,
            'task': task  # Сохраняем task для отображения
        }

        # Добавляем начальное сообщение в логи
        if safe_filename not in process_logs:
            process_logs[safe_filename] = deque(maxlen=MAX_LOG_LINES)
        
        task_info = f" with task: {task}" if task else ""
        process_logs[safe_filename].append({
            'timestamp': time.time(),
            'type': 'stdout',
            'message': f"Script started with PID: {process.pid}{task_info}, Command: {' '.join(cmd)}"
        })

        return jsonify({
            "message": f"Script '{safe_filename}' started successfully" + (f" with task: {task}" if task else ""),
            "pid": process.pid,
            "command": ' '.join(cmd),
            "task": task
        })

    except Exception as e:
        print(f"Error running script {filename}: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop_script/<filename>', methods=['POST'])
@auth.auth_required
def stop_script(filename):
    """Stop a running script"""
    try:
        safe_filename = secure_filename(filename)
        if safe_filename != filename:
            return jsonify({"error": "Invalid filename"}), 400

        if safe_filename not in running_processes:
            return jsonify({"error": "Script is not running"}), 404

        process_info = running_processes[safe_filename]
        process = process_info['process']
        
        # Добавляем сообщение о остановке в логи
        if safe_filename in process_logs:
            process_logs[safe_filename].append({
                'timestamp': time.time(),
                'type': 'stdout',
                'message': "Script stopping by user request..."
            })
        
        # Завершаем процесс
        process.terminate()
        try:
            process.wait(timeout=5)  # Ждем 5 секунд для graceful shutdown
        except subprocess.TimeoutExpired:
            process.kill()  # Принудительно завершаем если не завершился
        
        # Удаляем из списка запущенных процессов
        del running_processes[safe_filename]
        
        # Добавляем сообщение о завершении в логи
        if safe_filename in process_logs:
            process_logs[safe_filename].append({
                'timestamp': time.time(),
                'type': 'stdout',
                'message': "Script stopped successfully"
            })
        
        return jsonify({"message": f"Script '{safe_filename}' stopped successfully"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/script_status/<filename>')
@auth.auth_required
def script_status(filename):
    """Get status of a script"""
    try:
        safe_filename = secure_filename(filename)
        if safe_filename != filename:
            return jsonify({"error": "Invalid filename"}), 400

        if safe_filename not in running_processes:
            return jsonify({"status": "not_running"})

        process_info = running_processes[safe_filename]
        process = process_info['process']
        
        # Проверяем статус процесса
        return_code = process.poll()
        if return_code is None:
            status = "running"
        else:
            status = "finished"
            # Удаляем завершенный процесс из списка
            del running_processes[safe_filename]
        
        return jsonify({
            "status": status,
            "pid": process.pid,
            "start_time": process_info['start_time'],
            "command": process_info['command'],
            "return_code": return_code
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/api/running_scripts')
@auth.api_auth_required
def get_running_scripts():
    """Get list of all running scripts"""
    try:
        running = []
        for filename, info in running_processes.items():
            process = info['process']
            return_code = process.poll()
            
            if return_code is None:
                status = "running"
            else:
                status = "finished"
                continue
            
            running.append({
                'filename': filename,
                'pid': process.pid,
                'start_time': info['start_time'],
                'status': status,
                'command': info['command'],
                'task': info.get('task', '')
            })
        
        # Очищаем завершенные процессы
        finished_scripts = [name for name, info in running_processes.items() 
                          if info['process'].poll() is not None]
        for name in finished_scripts:
            del running_processes[name]
            
        return jsonify(running)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_tasks')
@auth.api_auth_required
def get_tasks():
    """Get list of all tasks from JSON file"""
    try:
        with open('tasks.json', 'r') as f:
            data = json.load(f)
        
        tasks = []
        for item in data:
            # Преобразуем словарь в namedtuple
            task = Task(
                Name=item.get('Name', ''),
                IP=item.get('IP', ''),
                Notes=item.get('Notes', '')
            )
            tasks.append(task._asdict())  # конвертируем в dict для jsonify

        return jsonify(tasks)
    except FileNotFoundError:
        return jsonify({"error": "tasks.json file not found"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500