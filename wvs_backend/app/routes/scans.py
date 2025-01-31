from flask import Blueprint, jsonify, request, send_file
from app.tasks import scan_website
from app.models import ScanResult

bp = Blueprint('scans', __name__)

@bp.route('/scan', methods=['POST'])
def start_scan():
    url = request.json.get('url')
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'Invalid URL protocol'}), 400
    
    task = scan_website.delay(url)
    return jsonify({'task_id': task.id}), 202

@bp.route('/status/<task_id>', methods=['GET'])
def get_status(task_id):
    task = scan_website.AsyncResult(task_id)
    return jsonify(task.info)

@bp.route('/report/<int:scan_id>', methods=['GET'])
def get_report(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return send_file(scan.report_path, mimetype='application/pdf')