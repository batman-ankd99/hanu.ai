from collectors.ec2_collector import collect_ec2_data
from collectors.sg_collector import collect_sg_data
from collectors.s3_collector import collect_s3_data
from collectors.iampolicy_collector import collect_iampolicy_data
from collectors.iampolicystatements_collector import collect_iampolicystatements_data
from collectors.iam_mfa_collector import collect_iam_mfa_data

import time
import logging

logging.basicConfig(level=logging.INFO)


def collect_all():

    try:
        start = time.time()
        logging.info("Starting data collection...")

        results = {
            "ec2": collect_ec2_data(),
            "sg": collect_sg_data(),
            "s3": collect_s3_data(),
            "iampolicy": collect_iampolicy_data(),
            "iampolicy_statements": collect_iampolicystatements_data(),
            "iam_mfa": collect_iam_mfa_data()
        }

        duration = round(time.time() - start, 2)
        logging.info(f"Collection complete in {duration}s")
        logging.info(f"Collection summary: {results}")

        # 🔥 IMPORTANT: return flat structure (NOT nested under "details")
        return results

    except Exception as e:
        logging.error(f"Collector failed: {e}")
        return {
            "ec2": None,
            "sg": None,
            "s3": None,
            "iampolicy": None,
            "error": str(e)
        }


if __name__ == "__main__":
    print(collect_all())
