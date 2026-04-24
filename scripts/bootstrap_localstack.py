from __future__ import annotations

import os

import boto3
from botocore.exceptions import ClientError


def _s3_client():
    return boto3.client(
        "s3",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


def _kms_client():
    return boto3.client(
        "kms",
        endpoint_url=os.environ["AWS_ENDPOINT_URL"],
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


def ensure_bucket() -> None:
    bucket_name = os.environ["EVIDENCE_BUCKET"]
    s3 = _s3_client()
    existing_buckets = {bucket["Name"] for bucket in s3.list_buckets().get("Buckets", [])}
    if bucket_name in existing_buckets:
        print(f"S3 bucket ready: {bucket_name}")
        return
    s3.create_bucket(Bucket=bucket_name)
    print(f"S3 bucket created: {bucket_name}")


def ensure_kms_alias() -> None:
    alias_name = os.environ["KMS_MASTER_KEY_ID"]
    kms = _kms_client()

    aliases = kms.list_aliases().get("Aliases", [])
    for alias in aliases:
        if alias.get("AliasName") == alias_name:
            print(f"KMS alias ready: {alias_name}")
            return

    key_id = kms.create_key(Description="ProofScan local dev key")["KeyMetadata"]["KeyId"]
    try:
        kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    except ClientError as exc:
        if "AlreadyExistsException" not in str(exc):
            raise
    print(f"KMS alias created: {alias_name} -> {key_id}")


if __name__ == "__main__":
    ensure_bucket()
    ensure_kms_alias()
