import boto3


def get_boto3_session(region):
    return boto3.Session(region_name=region)


def get_enabled_regions(session):
    """Query EC2 for all enabled regions in this account."""
    ec2 = session.client('ec2')
    response = ec2.describe_regions(
        Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
    )
    return sorted([r['RegionName'] for r in response['Regions']])
