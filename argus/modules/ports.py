import socket
from typing import List

from argus.config import COMMON_PORTS, DEFAULT_PORT_TIMEOUT
from argus.models.asset import ServiceExposure
from argus.utils.logger import get_logger

logger = get_logger(__name__)


def scan_common_ports(host: str, timeout: float = DEFAULT_PORT_TIMEOUT) -> List[ServiceExposure]:
    services: List[ServiceExposure] = []

    for port, (service_name, classification) in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                services.append(
                    ServiceExposure(
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        classification=classification,
                    )
                )
        except Exception as exc:
            logger.debug("Port probe failed for %s:%s - %s", host, port, exc)
        finally:
            sock.close()

    return services