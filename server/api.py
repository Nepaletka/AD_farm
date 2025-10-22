import time
import os

from flask import request, jsonify

from server import app, auth, database, reloader
from server.models import FlagStatus
from server.spam import is_spam_flag
from werkzeug.utils import secure_filename
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")


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

@app.route('/api/upload_script', methods=['POST'])
@auth.api_auth_required
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
