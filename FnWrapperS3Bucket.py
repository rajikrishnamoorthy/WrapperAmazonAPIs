import boto3

def create_myorg_bucket():
    # Prompt the user for the bucket name, region, and sensitivity
    bucket_name = input("Enter the S3 bucket name: ")
    region = input("Enter the region: ")
    sensitivity = input("Enter the sensitivity of the bucket (low, medium, or high): ")

    # Create an S3 client
    s3_client = boto3.client('s3', region_name=region)

    # Create the bucket
    s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={'LocationConstraint': region}
    )

    # Apply encryption based on sensitivity
    if sensitivity.lower() == 'low':
        # Enable AES256 encryption for low sensitivity
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    },
                ]
            }
        )
    else:
        # Create a KMS client
        kms_client = boto3.client('kms', region_name=region)

        # Create a new customer-managed key for medium or high sensitivity
        key_response = kms_client.create_key(
            Description=f'{bucket_name} Key',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS'
        )
        key_id = key_response['KeyMetadata']['KeyId']

        # Enable KMS encryption with the customer-managed key
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': key_id
                        }
                    },
                ]
            }
        )
  
    # Enable MFA Delete (Assuming MFA is configured on the AWS account)
    s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled', 'MFADelete': 'Enabled'},
        MFA="SERIAL_NUMBER MFA_CODE" # Replace with your MFA serial number and code
    )

    # Block public access
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    # Enable access logging
    s3_client.put_bucket_logging(
        Bucket=bucket_name,
        BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': bucket_name, # Logging target bucket
                'TargetPrefix': 'logs/' # Logging target prefix
            }
        }
    )
    
    #Update bucket policy
    # Deny HTTP requests (only allow HTTPS) and allow only specific IAM role for PutObject and GetObject
    iam_role = f"{bucket_name}-RWAccess"
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyHTTP",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {"Bool": {"aws:SecureTransport": False}}
            },
            {
                "Sid": "AllowSpecificRole",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam:::role/{iam_role}"},
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }

    s3_client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(bucket_policy)
    )

    print(f"Bucket {bucket_name} created with security controls.")

# Invoke the function
create_myorg_bucket()
