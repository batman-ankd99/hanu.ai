import boto3
from datetime import datetime, timezone
import os
import json
import uuid

def analytics_iam_useraccesskey():
    iam = boto3.client('iam')
    user_res = iam.list_users()
    current_time = datetime.now(timezone.utc)
    age_dict_warning = []
    #print(user_res['Users'])


    for user_info in user_res['Users']:
    #    print(user_info['UserName'])
    #    print(user_info['UserId'])

        user_access_key = iam.list_access_keys(
                UserName = user_info['UserName'],)
    #    print(user_access_key['AccessKeyMetadata'])

        for user_key in user_access_key['AccessKeyMetadata']:
    #        print(user_key)
            age = current_time - user_key['CreateDate']
            if age.days > 30:
                severity = "HIGH" if age.days > 90 else "MEDIUM"
                finding = {
                    "id": str(uuid.uuid4()),
                    "service": "iam",
                    "resource_type": "iam_user",
                    "resource_id": user_key['UserName'],
                    "finding": f"Access key {user_key['AccessKeyId']} is {age.days} days old",
                    "severity": severity,
                    "status": "OPEN",
                    "recommendation": "Rotate or delete unused access keys",
                    "created_at": datetime.utcnow().isoformat()
                }

                findings.append(finding)

                age_dict_warning.append(key_info)
    print(age_dict_warning)
    return {
        "status": "success",
        "count": len(findings),
        "findings": findings
    }


if __name__ == "__main__":
    analytics_iam_useraccesskey()
