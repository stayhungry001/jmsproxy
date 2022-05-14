import logging


class Ecs:
    def __init__(self):
        self.ecs_id = ""
        self.instance_name = ""
        self.private_ip = ""
        self.public_ip = ""
        self.vpc_id = ""
        self.os_type = "linux"


def _get_logger():
    log = logging.getLogger("__jmsproxy__")
    h = logging.FileHandler('jms.log', mode='a')
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    h.setFormatter(fmt)
    log.setLevel(logging.INFO)
    log.addHandler(h)
    return log


logger = _get_logger()
