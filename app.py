from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
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

from core.rule_engine import evaluate_all


# ---------------- APP INIT ----------------
app = Flask(__name__)
CORS(app)

# ---------------- DB CONFIG ----------------
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:password@localhost/cloud_audit"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ---------------- MODEL (NO models.py needed) ----------------
class Finding(db.Model):
    __tablename__ = "finding"

    id = db.Column(db.Integer, primary_key=True)

    service = db.Column(db.String(100))
    resource_type = db.Column(db.String(100))
    resource_id = db.Column(db.String(200))

    finding = db.Column(db.Text)
    severity = db.Column(db.String(50))

    status = db.Column(db.String(20), default="open")


# create tables
with app.app_context():
    db.create_all()


# ---------------- HOME ----------------
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


# ---------------- ANALYZERS ----------------
@app.route('/analyzer/sg', methods=['GET'])
def run_analyzer_sg():
    return jsonify(analytics_layer_sg.analytics_sg())

@app.route('/analyzer/iam', methods=['GET'])
def run_analyzer_iam():
    return jsonify(analytics_layer_iam.analytics_iam())

@app.route('/analyzer/iam_useraccesskey', methods=['GET'])
def run_analyzer_iam_useraccesskey():
    return jsonify(analytics_layer_iam_useraccesskey.analytics_iam_useraccesskey())


# ---------------- FINDINGS (WITH DB SAVE FIX) ----------------
@app.route('/findings', methods=['GET'])
def get_findings():

    sg = analytics_layer_sg.analytics_sg()
    iam = analytics_layer_iam.analytics_iam()
    s3 = s3_collector.collect_s3_data()

    findings = evaluate_all(
        sg_data=sg,
        iam_data=iam,
        s3_data=s3
    )

    # ---------------- SAVE TO DB ----------------
    for f in findings:
        record = Finding(
            service=f.get("service"),
            resource_type=f.get("resource_type"),
            resource_id=f.get("resource_id"),
            finding=f.get("finding"),
            severity=f.get("severity"),
            status="open"
        )
        db.session.add(record)

    db.session.commit()

    return jsonify({
        "status": "success",
        "count": len(findings),
        "findings": findings
    })


# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
