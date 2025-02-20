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
    print("Received analyze request")
    if 'files' not in request.files:
        print("No files in request")
        return jsonify({'error': 'No files provided'}), 400

    files = request.files.getlist('files')
    print(f"Received {len(files)} files")

    if not files:
        print("No files selected")
        return jsonify({'error': 'No files selected'}), 400

    saved_files = []
    file_details = []

    try:
        for file in files:
            print(f"Processing file: {file.filename}")
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                print(f"Saving file to: {filepath}")
                file.save(filepath)

                # Print file details for debugging
                print(f"=== File Details for {filename} ===")
                print(f"File size: {os.path.getsize(filepath)} bytes")
                print(f"File exists: {os.path.exists(filepath)}")
                print("First few lines of the file:")
                try:
                    with open(filepath, 'r') as f:
                        first_lines = ''.join(f.readlines()[:10])
                        print(first_lines)
                except Exception as e:
                    print(f"Error reading file: {str(e)}")
                print("=== End File Details ===")

                saved_files.append(filepath)
                file_details.append({
                    'name': filename,
                    'path': filepath,
                    'size': os.path.getsize(filepath)
                })
                print(f"File saved successfully: {filename}")

        if not saved_files:
            print("No valid files uploaded")
            return jsonify({'error': 'No valid files uploaded'}), 400

        try:
            print("Starting analysis")
            # Perform the analysis
            analysis_results = analyze_solidity_files(saved_files)
            print("Analysis completed")
            print(f"Analysis results: {analysis_results}")

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
            print(f"Analysis error: {str(analysis_error)}")
            return jsonify({
                'error': f'Analysis failed: {str(analysis_error)}',
                'files': file_details,
                'status': 'error'
            }), 500

    except Exception as e:
        print(f"Server error: {str(e)}")
        return jsonify({
            'error': f'Server error: {str(e)}',
            'status': 'error'
        }), 500

    # Comment out file cleanup for debugging
    # finally:
    #     # Clean up uploaded files
    #     for filepath in saved_files:
    #         try:
    #             if os.path.exists(filepath):
    #                 os.remove(filepath)
    #                 print(f"Cleaned up file: {filepath}")
    #         except Exception as cleanup_error:
    #             print(f"Error removing file {filepath}: {str(cleanup_error)}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5001)))
