import os
import json
import time
import logging
import re
import subprocess
import base64
from pydantic import BaseModel
from kubernetes import client, config
from pythonjsonlogger.json import JsonFormatter


class SPReporterConfig(BaseModel):
    timeout: int
    node_name: str
    pod_name_pattern: re.Pattern
    argocd_server: str
    argocd_user: str
    argocd_password: str


class SPReporter:
    def __init__(self):
        self._init_logs()
        self.config = self._get_config()

    def _init_logs(self):
        logger = logging.getLogger()
        logHandler = logging.StreamHandler()
        formatter = JsonFormatter("{filename}{levelname}{asctime}{message}", style="{")
        logHandler.setFormatter(formatter)
        logger.addHandler(logHandler)
        logger.setLevel(logging.INFO)

    def _get_argocd_password(self):
        try:
            config.load_incluster_config()
            with client.ApiClient() as api_client:
                api_instance = client.CoreV1Api(api_client)
                api_response = api_instance.read_namespaced_secret(
                    "argocd-initial-admin-secret", "argocd"
                )
                return base64.b64decode(api_response.data["password"])
        except Exception as e:
            logging.exception(f"Failed to get argocd secret")
            raise e

    def _get_config(self) -> SPReporterConfig:
        return SPReporterConfig(
            timeout=int(os.getenv("TIMEOUT", "120")),
            node_name=os.getenv("NODE_NAME", ""),
            pod_name_pattern=re.compile(r"^(app-|exec|trusted-|registry)"),
            argocd_server=os.getenv(
                "ARGOCD_SERVER", "argocd-server.argocd.svc.cluster.local"
            ),
            argocd_user=os.getenv("ARGOCD_USER", "admin"),
            argocd_password=os.getenv("ARGOCD_PASSWORD", self._get_argocd_password()),
        )

    def run(self):
        while True:
            try:
                node_info = self.get_node_info()
                pod_images = self.get_pod_images()
                argocd_images = self.get_argocd_apps()
                report = {
                    "timestamp": time.time(),
                    "node_info": node_info,
                    "pod_images": pod_images,
                    "argocd_images": argocd_images,
                }
                logging.info(
                    "Node: %s (%s)\nCollected images:\nPods: %s\nArgoCD: %s",
                    node_info.get("node_name", "N/A"),
                    node_info.get("node_ip", "N/A"),
                    json.dumps(pod_images, indent=2),
                    json.dumps(argocd_images, indent=2),
                )
                print(report)
            except Exception as e:
                logging.error(f"Main loop error: {str(e)}")
            time.sleep(self.config.TIMEOUT)

    def argocd_login(self):
        try:
            login_cmd = [
                "argocd",
                "login",
                self.config.argocd_server,
                "--username",
                self.config.argocd_user,
                "--password",
                self.config.argocd_password,
                "--insecure",  # Remove if using valid TLS
                "--grpc-web",
                "--skip-test-tls",
            ]
            result = subprocess.run(
                login_cmd, capture_output=True, text=True, check=True
            )
            logging.info("ArgoCD login successful")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"ArgoCD login failed: {e.stderr}")
            return False

    def get_argocd_apps(self):
        if (
            not self.config.argocd_server
            or not self.config.argocd_user
            or not self.config.argocd_password
        ):
            logging.warning("ArgoCD credentials not configured")
            return {}

        if not argocd_login():
            return {}

        try:
            result = subprocess.run(
                ["argocd", "app", "list", "-o", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            apps = json.loads(result.stdout)
            return {
                app["metadata"]["name"]: app["status"]["summary"]["images"]
                for app in apps
                if "images" in app["status"].get("summary", {})
            }
        except json.JSONDecodeError:
            logging.error("Failed to parse ArgoCD output")
            return {}
        except Exception as e:
            logging.error(f"Error getting ArgoCD apps: {str(e)}")
            return {}

    def get_node_info(self):
        try:
            config.load_incluster_config()
            v1 = client.CoreV1Api()
            node = v1.read_node(self.config.node_name)
            if not node.status:
                logging.warning("Node status not available")
                return {"node_name": self.config.node_name, "node_ip": None}
            address_types = ["InternalIP", "ExternalIP", "Hostname"]
            for addr_type in address_types:
                addresses = [
                    addr.address
                    for addr in node.status.addresses
                    if addr.type == addr_type
                ]
                if addresses:
                    return {
                        "node_name": node.metadata.name,
                        "node_ip": addresses[0],
                        "cluster": "rke2",
                        "address_type": addr_type,
                    }
            logging.warning("No valid addresses found for node")
            return {"node_name": self.config.node_name, "node_ip": None}
        except Exception as e:
            logging.error(f"Error getting node info: {str(e)}")
            return {}

    def get_pod_images(self):
        try:
            v1 = client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces(watch=False)
            return {
                p.metadata.name: [c.image for c in p.spec.containers]
                for p in pods.items
                if self.config.pod_name_pattern.match(p.metadata.name)
            }
        except Exception as e:
            logging.error(f"Error getting pods: {str(e)}")
            return {}


def main():
    sp_reporter = SPReporter()
    sp_reporter.run()


if __name__ == "__main__":
    main()
