from flask import Flask, request, jsonify
import psycopg2
from db_utils import get_db_connection

app = Flask(__name__)


# -------------------------
# GET ALL FINDINGS
# -------------------------
@app.route("/findings", methods=["GET"])
def get_findings():

    severity = request.args.get("severity")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if severity:
            query = """
                SELECT rule_id, severity, description, resource_id, detected_at
                FROM findings
                WHERE severity = %s
                ORDER BY detected_at DESC;
            """
            cursor.execute(query, (severity,))
        else:
            query = """
                SELECT rule_id, severity, description, resource_id, detected_at
                FROM findings
                ORDER BY detected_at DESC;
            """
            cursor.execute(query)

        rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "rule_id": r[0],
                "severity": r[1],
                "description": r[2],
                "resource_id": r[3],
                "detected_at": str(r[4])
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
# RISK SUMMARY (PRISMA STYLE)
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
