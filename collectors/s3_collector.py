@app.route('/scan', methods=['POST'])
def run_scan():
    try:
        collected = collector.collect_all()

        # pass collected data into rule engine
        evaluate_all(
            ec2_data=collected.get("ec2"),
            sg_data=collected.get("sg"),
            s3_data=collected.get("s3"),
            iam_data=collected.get("iampolicy")
        )

        return jsonify({
            "status": "success",
            "message": "Scan completed successfully"
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
