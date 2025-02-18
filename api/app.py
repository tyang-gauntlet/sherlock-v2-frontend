from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
from services.solidity_analyzer import analyze_solidity_files

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'sol', 'json'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200


@app.route('/analyze', methods=['POST'])
def analyze_code():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    files = request.files.getlist('files')

    if not files:
        return jsonify({'error': 'No files selected'}), 400

    saved_files = []
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            saved_files.append(filepath)

    if not saved_files:
        return jsonify({'error': 'No valid files uploaded'}), 400

    try:
        # Analyze the uploaded files
        analysis_results = analyze_solidity_files(saved_files)

        # Clean up uploaded files
        for filepath in saved_files:
            try:
                os.remove(filepath)
            except Exception as e:
                print(f"Error removing file {filepath}: {str(e)}")

        return jsonify(analysis_results), 200

    except Exception as e:
        # Clean up uploaded files in case of error
        for filepath in saved_files:
            try:
                os.remove(filepath)
            except Exception as cleanup_error:
                print(f"Error removing file {filepath}: {str(cleanup_error)}")

        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
