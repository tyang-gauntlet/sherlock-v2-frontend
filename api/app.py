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
    file_details = []

    try:
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                saved_files.append(filepath)
                file_details.append({
                    'name': filename,
                    'path': filepath,
                    'size': os.path.getsize(filepath)
                })

        if not saved_files:
            return jsonify({'error': 'No valid files uploaded'}), 400

        try:
            # Perform the analysis
            analysis_results = analyze_solidity_files(saved_files)

            # Add file metadata to results
            for file_detail in file_details:
                matching_result = next(
                    (r for r in analysis_results['files'] if r['file_name'] == os.path.basename(
                        file_detail['path'])),
                    None
                )
                if matching_result:
                    matching_result['file_size'] = file_detail['size']

            return jsonify(analysis_results), 200

        except Exception as analysis_error:
            return jsonify({
                'error': f'Analysis failed: {str(analysis_error)}',
                'files': file_details,
                'status': 'error'
            }), 500

    except Exception as e:
        return jsonify({
            'error': f'Server error: {str(e)}',
            'status': 'error'
        }), 500

    finally:
        # Clean up uploaded files
        for filepath in saved_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as cleanup_error:
                print(f"Error removing file {filepath}: {str(cleanup_error)}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
