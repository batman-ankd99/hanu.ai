from flask import Flask, request, jsonify
from db_utils import get_db_connection
from db.findings_store import save_findings

# 👇 your aggregator (IMPORTANT)
from findings_api import get_all_findings

app = Flask(__name__)


# -------------------------
# TRIGGER SCAN (NEW - IMPORTANT)
# -------------------------
@app.route("/scan", methods=["POST"])
def scan_findings():

    try:
        # 1. Run collectors + analytics
        all_data = get_all_findings()

        findings = all_data.get("findings", [])

        # 2. Save to DB
        save_findings(findings)

        return jsonify({
            "status": "success",
            "message": "Scan completed",
            "summary": all_data.get("summary", {}),
            "count": len(findings)
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })


# -------------------------
# GET ALL FINDINGS (FROM DB)
# -------------------------
@app.route("/findings", methods=["GET"])
def get_findings():

    severity = request.args.get("severity")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if severity:
            query = """
                SELECT id, severity, finding, resource_id, created_at
                FROM findings
                WHERE severity = %s
                ORDER BY created_at DESC;
            """
            cursor.execute(query, (severity,))
        else:
            query = """
                SELECT id, severity, finding, resource_id, created_at
                FROM findings
                ORDER BY created_at DESC;
            """
            cursor.execute(query)

        rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "id": r[0],
                "severity": r[1],
                "finding": r[2],
                "resource_id": r[3],
                "created_at": str(r[4])
            })

        cursor.close()
        conn.close()

        return jsonify({
            "status": "success",
            "count": len(results),
            "findings": results
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })


# -------------------------
# RISK SUMMARY
# -------------------------
@app.route("/risk-summary", methods=["GET"])
def risk_summary():

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            SELECT severity, COUNT(*)
            FROM findings
            GROUP BY severity;
        """

        cursor.execute(query)
        rows = cursor.fetchall()

        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for r in rows:
            summary[r[0]] = r[1]

        cursor.close()
        conn.close()

        return jsonify({
            "status": "success",
            "risk_summary": summary
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })


# -------------------------
# RUN APP
# -------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
