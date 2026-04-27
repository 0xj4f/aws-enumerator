"""
EKS authentication helper.

Generates a Kubernetes API token by presigning a STS GetCallerIdentity URL
with the cluster name as a special header. This is the same flow that
`aws eks get-token` uses, but in pure Python (no external CLI calls).
"""

import base64
import os
import tempfile
from botocore.signers import RequestSigner


def get_eks_token(cluster_name, session):
    """Generate a K8s API token for an EKS cluster using STS presigning.

    Returns a string like 'k8s-aws-v1.<base64url>'
    """
    client = session.client('sts')
    region = session.region_name or 'us-east-1'

    signer = RequestSigner(
        client.meta.service_model.service_id,
        region,
        'sts',
        'v4',
        session.get_credentials(),
        session.events
    )

    params = {
        'method': 'GET',
        'url': f'https://sts.{region}.amazonaws.com/'
               '?Action=GetCallerIdentity&Version=2011-06-15',
        'body': {},
        'headers': {'x-k8s-aws-id': cluster_name},
        'context': {}
    }

    signed_url = signer.generate_presigned_url(
        params,
        region_name=region,
        expires_in=60,
        operation_name=''
    )

    encoded = base64.urlsafe_b64encode(signed_url.encode('utf-8')).decode('utf-8').rstrip('=')
    return f'k8s-aws-v1.{encoded}'


def write_ca_cert(cluster_name, ca_data_b64):
    """Write the cluster CA cert (base64-encoded in DescribeCluster) to a temp file.
    Returns the path. Caller is responsible for cleanup."""
    ca_pem = base64.b64decode(ca_data_b64)
    fd, path = tempfile.mkstemp(prefix=f"eks-{cluster_name}-", suffix=".crt")
    with os.fdopen(fd, 'wb') as f:
        f.write(ca_pem)
    return path


def build_k8s_client(cluster_name, endpoint, ca_data_b64, session):
    """Construct an authenticated kubernetes.client.ApiClient for an EKS cluster."""
    from kubernetes import client as k8s_client

    token = get_eks_token(cluster_name, session)
    ca_path = write_ca_cert(cluster_name, ca_data_b64)

    config = k8s_client.Configuration()
    config.host = endpoint
    config.verify_ssl = True
    config.ssl_ca_cert = ca_path
    config.api_key = {"authorization": f"Bearer {token}"}

    return k8s_client.ApiClient(configuration=config), ca_path
