import os
import shutil
import subprocess
import tempfile
import zipfile
from flask import Flask, request, send_file, after_this_request, abort
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Disclaimer: This entire file was vibe coded. If there are issues
# don't hesitate to make a ticket. There's nothing special going
# on here anyways, just focus on the encryption.

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 60 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = './uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[]
)
limiter.init_app(app)

@app.route('/')
def index():
    return '''
    <h1>Encryption Oracle</h1>
    <p>Upload a file (max 60MB) to encrypt with a new random key along with the server flag:</p>
    <form method=post enctype=multipart/form-data action="/oracle">
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/oracle', methods=['POST'])
@limiter.limit("1 per 5 minutes")
def oracle():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    temp_dir = tempfile.mkdtemp(dir=app.config['UPLOAD_FOLDER'])

    try:
        key_path = os.path.join(temp_dir, "key")
        with open(key_path, "wb") as f:
            f.write(os.urandom(16))

        file_path = os.path.join(temp_dir, "input.bin")
        file.save(file_path)

        filesize = os.path.getsize(file_path)
        if filesize % 16 != 0:
            padding = 16 - (filesize % 16)
            with open(file_path, 'ab') as f:
                f.write(b'\x00' * padding)

        flag_path = os.path.join(temp_dir, "flag.txt")
        shutil.copy("flag.txt", flag_path)

        subprocess.run(['./encrypt', key_path, file_path], check=True)
        subprocess.run(['./encrypt', key_path, flag_path], check=True)

        zip_path = os.path.join(temp_dir, "encrypted_data.zip")
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(file_path, arcname="input.enc")
            zipf.write(flag_path, arcname="flag.enc")

        @after_this_request
        def cleanup(response):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                app.logger.error(f"Error deleting temp dir {temp_dir}: {e}")
            return response

        return send_file(zip_path, as_attachment=True)

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        app.logger.error(f"Exception during processing: {e}")
        return 'Internal Server Error', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
