from analyzers import analytics_layer_iam
from analyzers import analytics_layer_sg
from analyzers import analytics_layer_iam_useraccesskey


def get_all_findings():

    all_findings = []

    try:
        # ---------------- IAM FINDINGS ----------------
        iam = analytics_layer_iam.analytics_iam()
        all_findings.extend(iam.get("records", []))

        # ---------------- SG FINDINGS ----------------
        sg = analytics_layer_sg.analytics_sg()
        all_findings.extend(sg.get("records", []))

        # ---------------- IAM ACCESS KEY ----------------
        iam_key = analytics_layer_iam_useraccesskey.analytics_iam_useraccesskey()
        all_findings.extend(iam_key.get("records", []))

        # ---------------- SUMMARY ----------------
        summary = {
            "total": len(all_findings)
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
