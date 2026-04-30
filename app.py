import csv
import io
from flask import Response
from sqlalchemy import text
from flask import Flask, jsonify
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

from core.rule_engine import evaluate_all

from db import db
from models import Finding


# ---------------- APP INIT ----------------
app = Flask(__name__)
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://cloud_user:StrongPassword123@127.0.0.1/cloud_audit"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()


# ---------------- HOME ----------------
@app.route('/')
def home():
    return "AWS Cloud Audit API is running"


# ---------------- COLLECTORS ----------------
@app.route('/collect', methods=['GET'])
def run_collector():
    return jsonify(collector.collect_all())


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


# ---------------- SAVE FINDINGS ----------------
def save_findings(findings):
    for f in findings:
        record = Finding(
            service=f["service"],
            resource_type=f["resource_type"],
            resource_id=f["resource_id"],
            finding=f["finding"],
            severity=f["severity"],
            status=f.get("status", "open")
        )
        db.session.add(record)

    db.session.commit()


# ---------------- SCAN ----------------
@app.route('/scan', methods=['POST'])
def run_scan():
    try:
        # STEP 1: CLEAN OLD FINDINGS
        db.session.execute(text("DELETE FROM findings"))
        db.session.commit()

        # STEP 2: COLLECT DATA
        collected = collector.collect_all()

        # STEP 3: RUN RULE ENGINE (IMPORTANT FIX)
        findings = evaluate_all(
            ec2_data=collected.get("ec2"),
            sg_data=collected.get("sg"),
            s3_data=collected.get("s3"),
            iam_data=collected.get("iampolicy")
        )

        # STEP 4: SAVE FINDINGS TO DB (FIXED)
        if findings:
            save_findings(findings)

        return jsonify({
            "status": "success",
            "message": "Scan completed successfully",
            "findings_count": len(findings) if findings else 0
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

#----------------csv file -----------
@app.route('/findings/export/csv', methods=['GET'])
def export_findings_csv():

    results = db.session.execute(text("""
        SELECT service, resource_type, resource_id, finding, severity, status
        FROM findings
        ORDER BY id DESC
    """)).fetchall()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # header
    writer.writerow([
        "service",
        "resource_type",
        "resource_id",
        "finding",
        "severity",
        "status"
    ])

    # rows
    for row in results:
        writer.writerow([
            row.service,
            row.resource_type,
            row.resource_id,
            row.finding,
            row.severity,
            row.status
        ])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=vulnerabilities.csv"
        }
    )

#------PCI DSS compliance ----------

@app.route('/pci-summary', methods=['GET'])
def pci_summary():

    results = db.session.execute(text("""
        SELECT severity, COUNT(*) as count
        FROM findings
        GROUP BY severity
    """)).fetchall()

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for row in results:
        severity = (row.severity or "").upper()
        if severity in summary:
            summary[severity] = row.count

    # ---------------- SIMPLE PCI SCORE MODEL ----------------
    pci_score = 100
    pci_score -= summary["CRITICAL"] * 15
    pci_score -= summary["HIGH"] * 8
    pci_score -= summary["MEDIUM"] * 3

    pci_score = max(pci_score, 0)

    compliance_status = (
        "COMPLIANT" if pci_score >= 90 else
        "PARTIAL" if pci_score >= 70 else
        "NON-COMPLIANT"
    )

    return jsonify({
        "status": "success",
        "pci_score": pci_score,
        "compliance_status": compliance_status,
        "breakdown": summary
    })

# ---------------- RISK SUMMARY ----------------
@app.route('/risk-summary', methods=['GET'])
def risk_summary():

    results = db.session.execute(text("""
        SELECT severity, COUNT(*) as count
        FROM findings
        GROUP BY severity
    """)).fetchall()

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for row in results:
        severity = (row.severity or "").upper()
        if severity in summary:
            summary[severity] = row.count

    return jsonify({
        "status": "success",
        "risk_summary": summary
    })


# ---------------- FINDINGS ----------------
@app.route('/findings', methods=['GET'])
def get_findings():

    results = db.session.execute(text("""
        SELECT id, service, resource_type, resource_id, finding, severity, status
        FROM findings
        ORDER BY id DESC
    """)).fetchall()

    findings_list = []
    severity_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for row in results:

        severity = (row.severity or "").upper()

        findings_list.append({
            "id": row.id,
            "service": row.service,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "finding": row.finding,
            "severity": severity,
            "status": row.status
        })

        if severity in severity_count:
            severity_count[severity] += 1

    return jsonify({
        "status": "success",
        "total": len(findings_list),
        "severity_breakdown": severity_count,
        "findings": findings_list
    })


# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
