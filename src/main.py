import os
import json
import time
import logging
import re
import requests
import subprocess
import base64
from kubernetes import client, config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

REMOTE_ENDPOINT = os.getenv('REMOTE_ENDPOINT', 'http://receiver.superprotocol.io/images')
TIMEOUT = int(os.getenv('TIMEOUT', '120'))
NODE_NAME = os.getenv('NODE_NAME', '')
POD_NAME_PATTERN = re.compile(r'^(app-|exec|trusted-|registry)')
ARGOCD_SERVER = os.getenv('ARGOCD_SERVER', 'argocd-server.argocd.svc.cluster.local')
ARGOCD_USER = os.getenv('ARGOCD_USER', 'admin')

def get_argocd_password():
    try:
        config.load_incluster_config()
        with client.ApiClient() as api_client:
            api_instance = client.CoreV1Api(api_client)
            api_response = api_instance.read_namespaced_secret('argocd-initial-admin-secret', 'argocd')
            return base64.b64decode(api_response.data['password'])
    except Exception as e:
        logging.exception(f"Failed to get argocd secret")
        raise e

ARGOCD_PASSWORD = os.getenv('ARGOCD_PASSWORD', get_argocd_password())


def argocd_login():
    try:
        login_cmd = [
            'argocd', 'login', ARGOCD_SERVER,
            '--username', ARGOCD_USER,
            '--password', ARGOCD_PASSWORD,
            '--insecure',  # Remove if using valid TLS
            '--grpc-web',
            '--skip-test-tls'
        ]
        result = subprocess.run(login_cmd, capture_output=True, text=True, check=True)
        logger.info("ArgoCD login successful")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"ArgoCD login failed: {e.stderr}")
        return False

def get_argocd_apps():
    if not ARGOCD_SERVER or not ARGOCD_USER or not ARGOCD_PASSWORD:
        logger.warning("ArgoCD credentials not configured")
        return {}

    if not argocd_login():
        return {}

    try:
        result = subprocess.run(
            ['argocd', 'app', 'list', '-o', 'json'],
            capture_output=True, text=True, check=True
        )
        apps = json.loads(result.stdout)
        return {app['metadata']['name']: app['status']['summary']['images'] 
               for app in apps if 'images' in app['status'].get('summary', {})}
    except json.JSONDecodeError:
        logger.error("Failed to parse ArgoCD output")
        return {}
    except Exception as e:
        logger.error(f"Error getting ArgoCD apps: {str(e)}")
        return {}

def get_node_info():
    try:
        config.load_incluster_config()
        v1 = client.CoreV1Api()
        node = v1.read_node(NODE_NAME)
        if not node.status:
            logger.warning("Node status not available")
            return {"node_name": NODE_NAME, "node_ip": None}

        # Try multiple address types common in RKE2
        address_types = ['InternalIP', 'ExternalIP', 'Hostname']
        for addr_type in address_types:
            addresses = [addr.address for addr in node.status.addresses 
                        if addr.type == addr_type]
            if addresses:
                return {
                    "node_name": node.metadata.name,
                    "node_ip": addresses[0],
                    "cluster": "rke2",
                    "address_type": addr_type
                }
        logger.warning("No valid addresses found for node")
        return {"node_name": NODE_NAME, "node_ip": None}
    except Exception as e:
        logger.error(f"Error getting node info: {str(e)}")
        return {}

def get_pod_images():
    try:
        v1 = client.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces(watch=False)
        return {
            p.metadata.name: [c.image for c in p.spec.containers]
            for p in pods.items
            if POD_NAME_PATTERN.match(p.metadata.name)
        }
    except Exception as e:
        logger.error(f"Error getting pods: {str(e)}")
        return {}

def send_data(data):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(REMOTE_ENDPOINT, json=data, headers=headers, timeout=10)
        logger.info(f"Data sent successfully. Status: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send data: {str(e)}")

if __name__ == "__main__":
    while True:
        try:
            node_info = get_node_info()
            pod_images = get_pod_images()
            argocd_images = get_argocd_apps()
            report = {
                "timestamp": time.time(),
                "node_info": node_info,
                "pod_images": pod_images,
                "argocd_images": argocd_images
            }
            logger.info("Node: %s (%s)\nCollected images:\nPods: %s\nArgoCD: %s",
                node_info.get('node_name', 'N/A'),
                node_info.get('node_ip', 'N/A'),
                json.dumps(pod_images, indent=2),
                json.dumps(argocd_images, indent=2))
            print(report)
            #send_data(report)
        except Exception as e:
            logger.error(f"Main loop error: {str(e)}")
        time.sleep(TIMEOUT)
