from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
from services.slither_analyzer import analyze_with_slither
from services.diligence_analyzer import analyze_with_diligence

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


def merge_analysis_results(slither_results, diligence_results):
    """
    Merge results from both analyzers, removing duplicates and combining insights.
    """
    merged = {
        'files': [],
        'overall_risk_level': 'LOW',
        'total_contracts': slither_results['total_contracts'],
        'total_functions': slither_results['total_functions'],
        'vulnerabilities': [],
        'suggestions': []
    }

    # Create a set to track unique vulnerabilities
    seen_vulns = set()

    # Helper function to create a unique key for a vulnerability
    def vuln_key(v):
        return f"{v['type']}_{v['severity']}_{v.get('line', '')}_{v.get('contract', '')}_{v.get('function', '')}"

    # Merge vulnerabilities from both analyzers
    for vuln in slither_results['vulnerabilities'] + diligence_results['vulnerabilities']:
        key = vuln_key(vuln)
        if key not in seen_vulns:
            seen_vulns.add(key)
            merged['vulnerabilities'].append(vuln)

    # Merge suggestions similarly
    seen_suggestions = set()
    for suggestion in slither_results['suggestions'] + diligence_results['suggestions']:
        key = vuln_key(suggestion)
        if key not in seen_suggestions:
            seen_suggestions.add(key)
            merged['suggestions'].append(suggestion)

    # Merge file results
    file_map = {}
    for file_result in slither_results['files'] + diligence_results['files']:
        if file_result['file_name'] not in file_map:
            file_map[file_result['file_name']] = file_result
        else:
            # Combine vulnerabilities and suggestions for the same file
            existing = file_map[file_result['file_name']]
            existing['vulnerabilities'].extend(file_result['vulnerabilities'])
            existing['suggestions'].extend(file_result['suggestions'])

            # Update risk level to the highest between the two
            risk_levels = {'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
            existing_level = risk_levels.get(existing['risk_level'], -1)
            new_level = risk_levels.get(file_result['risk_level'], -1)
            if new_level > existing_level:
                existing['risk_level'] = file_result['risk_level']

    merged['files'] = list(file_map.values())

    # Set overall risk level to the highest found
    if any(v['severity'] == 'HIGH' for v in merged['vulnerabilities']):
        merged['overall_risk_level'] = 'HIGH'
    elif any(v['severity'] == 'MEDIUM' for v in merged['vulnerabilities']):
        merged['overall_risk_level'] = 'MEDIUM'
    elif merged['vulnerabilities']:
        merged['overall_risk_level'] = 'LOW'

    # Sort vulnerabilities by severity
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    merged['vulnerabilities'].sort(
        key=lambda x: severity_order.get(x['severity'].upper(), 3))

    return merged


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
            # Run both analyzers
            slither_results = analyze_with_slither(saved_files)
            diligence_results = analyze_with_diligence(saved_files)

            # Merge results
            merged_results = merge_analysis_results(
                slither_results, diligence_results)

            # Add file metadata to results
            for file_detail in file_details:
                matching_result = next(
                    (r for r in merged_results['files'] if r['file_name'] == os.path.basename(
                        file_detail['path'])),
                    None
                )
                if matching_result:
                    matching_result['file_size'] = file_detail['size']

            return jsonify(merged_results), 200

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
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5001)))
