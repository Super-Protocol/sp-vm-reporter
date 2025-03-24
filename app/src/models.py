from pydantic import BaseModel


class KubernetesNodeInfoModel(BaseModel):
    hostname: str
    addresses: list[str]
    labels: list[str]
