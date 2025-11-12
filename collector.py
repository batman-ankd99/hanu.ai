from ec2_collector import collect_ec2_data
from sg_collector import collect_sg_data
from s3_collector import collect_s3_data
from iampolicy_collector import collect_iampolicy_data
from iampolicystatements_collector import collect_iampolicystatements_data
import time
import logging

logging.basicConfig(level=logging.INFO)


def collect_all():

    results = {}
    try:
        start = time.time()
        logging.info("Starting data collection...")

        results["ec2"] = collect_ec2_data()
        results["sg"] = collect_sg_data()
        results["s3"] = collect_s3_data()
        results["iampolicy"] = collect_iampolicy_data()
        results["iampolicy_statements"] = collect_iampolicystatements_data()

        duration = round(time.time() - start, 2) # 2 is to round of till 2 digits after substraction
        logging.info(f"Collection complete in {duration}s")

        return {"status": "success", "details": results}

        print(results)

    except Exception as e:
        logging.error(f"Collector failed: {e}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    collect_all()
