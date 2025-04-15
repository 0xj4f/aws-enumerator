def get_boto3_session(region):
    import boto3
    return boto3.Session(region_name=region)
