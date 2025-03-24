from kubernetes import client, config

from .models import KubernetesNodeInfoModel


class KubernetesDataCollector:
    def __init__(self):
        config.load_incluster_config()
        self.v1 = client.CoreV1Api()
        self.nodes = self._get_node_names()

    def _get_node_names(self) -> list:
        node_list = self.v1.list_node()
        return [node.metadata.name for node in node_list.items]

    def _get_node_info(self, node_name: str) -> models.KubernetesNodeInfoModel:
        node_info = self.v1.read_node(node_name)
