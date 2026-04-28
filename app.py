from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta

from collectors import collector
from collectors import ec2_collector
from collectors import sg_collector
from collectors import s3_collector
from collectors import iampolicy_collector
from collectors import iampolicystatements_collector
from collectors import vpcflowlog_collector

from analyzers import analytics_layer_iam
from analyzers import analytics_layer_sg
from analyzers import analytics_layer_iam_useraccesskey

# 👇 NEW IMPORT (rule engine brain)
from core.rule_engine import evaluate_all


app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return "AWS Collector API is running"


# ---------------- FULL COLLECTION ----------------
@app.route('/collect', methods=['GET'])
def run_collector():
    results = collector.collect_all()
    return jsonify(results)


# ---------------- INDIVIDUAL COLLECTORS ----------------
@app.route('/collect/ec2', methods=['GET'])
def run_collector_ec2():
    return jsonify(ec2_collector.collect_ec2_data())

@app.route('/collect/sg', methods=['GET'])
def run_collector_sg():
    return jsonify(sg_collector.collect_sg_data())

@app.route('/collect/s3', methods=['GET'])
def run_collector_s3():
    return jsonify(s3_collector.collect_s3_data())

@app.route('/collect/iampolicy', methods=['GET'])
def run_collector_iampolicy():
    return jsonify(iampolicy_collector.collect_iampolicy_data())

@app.route('/collect/iampolicystatements', methods=['GET'])
def run_collector_iampolicystatements():
    return jsonify(iampolicystatements_collector.collect_iampolicystatements_data())

@app.route('/collect/vpcflowlog', methods=['GET'])
def run_collector_vpcflowlog():
    yesterday = datetime.utcnow() - timedelta(days=1)
    return jsonify(
        vpcflowlog_collector.collect_vpcflowlog_data(
            yesterday.year,
            yesterday.month,
            yesterday.day,
            "vpc-flow-log-hanu",
            426728253870
        )
    )


# ---------------- ANALYZERS (OLD STYLE) ----------------
@app.route('/analyzer/sg', methods=['GET'])
def run_analyzer_sg():
    return jsonify(analytics_layer_sg.analytics_sg())

@app.route('/analyzer/iam', methods=['GET'])
def run_analyzer_iam():
    return jsonify(analytics_layer_iam.analytics_iam())

@app.route('/analyzer/iam_useraccesskey', methods=['GET'])
def run_analyzer_iam_useraccesskey():
    return jsonify(analytics_layer_iam_useraccesskey.analytics_iam_useraccesskey())


# ---------------- PRISMA STYLE FINDINGS ENGINE (NEW) ----------------
@app.route('/findings', methods=['GET'])
def get_findings():

    # collect raw data
    sg = analytics_layer_sg.analytics_sg()
    iam = analytics_layer_iam.analytics_iam()
    s3 = s3_collector.collect_s3_data()

    # 🧠 RULE ENGINE (single brain now)
    findings = evaluate_all(
        sg_data=sg,
        iam_data=iam,
        s3_data=s3
    )

    return jsonify({
        "status": "success",
        "count": len(findings),
        "findings": findings
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
