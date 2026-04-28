from analyzers import analytics_layer_iam
from analyzers import analytics_layer_sg
from analyzers import analytics_layer_iam_useraccesskey


def get_all_findings():

    all_findings = []

    try:
        # ---------------- IAM FINDINGS ----------------
        iam = analytics_layer_iam.analytics_iam()
        all_findings.extend(iam.get("findings", []))

        # ---------------- SG FINDINGS ----------------
        sg = analytics_layer_sg.analytics_sg()
        all_findings.extend(sg.get("findings", []))

        # ---------------- IAM ACCESS KEY ----------------
        iam_key = analytics_layer_iam_useraccesskey.analytics_iam_useraccesskey()
        all_findings.extend(iam_key.get("findings", []))

        # ---------------- SUMMARY ----------------
        summary = {
            "total": len(all_findings),
            "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
        }

        return {
            "status": "success",
            "summary": summary,
            "findings": all_findings
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
