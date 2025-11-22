from flask import Flask, request, jsonify
from flask_cors import CORS

from collectors import collector
from collectors import ec2_collector
from collectors import sg_collector
from collectors import s3_collector
from collectors import iampolicy_collector
from collectors import iampolicystatements_collector

from analyzers import analytics_layer_iam
from analyzers import analytics_layer_sg

app = Flask(__name__)  # create Flask app, initializes flask app

# Enable CORS for all routes
CORS(app)

@app.route('/')     #simple home page api
def home():
    return "AWS Collector API is running"

@app.route('/collect', methods=['GET']) #when client sends get request to /collect, Flask will call run_collector()
def run_collector():
    """Run the full data collector and return results"""
    results = collector.collect_all()  # call your collector_all function from collector.py file
    return jsonify(results)  # return JSON response

@app.route('/collect/ec2', methods=['GET'])
def run_collector_ec2():
    """Run the Ec2 data collector and return results"""
    results_ec2 = ec2_collector.collect_ec2_data()
    return jsonify(results_ec2)

@app.route('/collect/sg', methods=['GET'])
def run_collector_sg():
    """Run the SG data collector and return results"""
    results_sg = sg_collector.collect_sg_data()
    return jsonify(results_sg)

@app.route('/collect/s3', methods=['GET'])
def run_collector_s3():
    """Run the Ec2 data collector and return results"""
    results_s3 = s3_collector.collect_s3_data()
    return jsonify(results_s3)

@app.route('/collect/iampolicy', methods=['GET'])
def run_collector_iampolicy():
    """Run the iam policy data collector and return results"""
    results_iampolicy = iampolicy_collector.collect_iampolicy_data()
    return jsonify(results_iampolicy)

@app.route('/collect/iampolicystatements', methods=['GET'])
def run_collector_iampolicystatements():
    """Run the iampolicystatements data collector and return results"""
    results_iampolicystatements = iampolicystatements_collector.collect_iampolicystatements_data()
    return jsonify(results_iampolicystatements)

@app.route('/analyzer/sg', methods=['GET'])
def run_analyzer_sg():
    """Run the analytics function to show faulty SG rules"""
    results_analytics_sg = analytics_layer_sg.analytics_sg()
    return jsonify(results_analytics_sg)

@app.route('/analyzer/iam', methods=['GET'])
def run_analyzer_iam():
    """Run the analytics function to show faulty iam policies"""
    results_analytics_iam = analytics_layer_iam.analytics_iam()
    return jsonify(results_analytics_iam)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
