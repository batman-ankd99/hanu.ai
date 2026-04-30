from flask import Flask, jsonify
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

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://cloud_user:StrongPassword123@127.0.0.1/cloud_audit"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ---------------- MODEL (FIXED) ----------------
class Finding(db.Model):
    __tablename__ = "findings"   # ✅ FIX: was "finding"

    id = db.Column(db.Integer, primary_key=True)

    service = db.Column(db.String(100))
    resource_type = db.Column(db.String(100))
    resource_id = db.Column(db.String(200))

    finding = db.Column(db.Text)
    severity = db.Column(db.String(50))

    status = db.Column(db.String(20), default="open")


# create tables (safe now)
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
@app.route('/collect/ec2')
def run_ec2():
    return jsonify(ec2_collector.collect_ec2_data())

@app.route('/collect/sg')
def run_sg():
    return jsonify(sg_collector.collect_sg_data())

@app.route('/collect/s3')
def run_s3():
    return jsonify(s3_collector.collect_s3_data())

@app.route('/collect/iampolicy')
def run_iampolicy():
    return jsonify(iampolicy_collector.collect_iampolicy_data())

@app.route('/collect/iampolicystatements')
def run_iampolicystatements():
    return jsonify(iampolicystatements_collector.collect_iampolicystatements_data())

@app.route('/collect/vpcflowlog')
def run_vpcflow():
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
@app.route('/analyzer/sg')
def analyzer_sg():
    return jsonify(analytics_layer_sg.analytics_sg())

@app.route('/analyzer/iam')
def analyzer_iam():
    return jsonify(analytics_layer_iam.analytics_iam())

@app.route('/analyzer/iam_useraccesskey')
def analyzer_iam_useraccesskey():
    return jsonify(analytics_layer_iam_useraccesskey.analytics_iam_useraccesskey())


# ---------------- FINDINGS API (FIXED CORE ISSUE) ----------------
@app.route('/findings', methods=['GET'])
def get_findings():

    # ALWAYS read directly from correct table
    results = db.session.execute("SELECT * FROM findings").fetchall()

    findings_list = []

    for row in results:
        findings_list.append({
            "id": row.id,
            "service": row.service,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "finding": row.finding,
            "severity": row.severity,
            "status": row.status
        })

    return jsonify({
        "status": "success",
        "count": len(findings_list),
        "findings": findings_list
    })


# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
