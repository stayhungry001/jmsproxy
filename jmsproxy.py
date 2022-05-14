from aliyun import AliYun
from jumpserver import JmsProxy
import yaml
from common import logger


def get_cloud_handlers(cloud_regions):
    cloud_handlers = {}
    for region in cloud_regions:
        cloud_handlers[region['name']] = AliYun(region['ak'],
                                                region['sk'],
                                                region['region_id'])
    return cloud_handlers


if __name__ == '__main__':
    logger.info('Start sync assets.')
    with open('config.yaml') as f:
        cfg = yaml.safe_load(f)
    jmsproxy = JmsProxy(cfg['jumpserver_host'],
                        cfg['jumpserver_ak'],
                        cfg['jumpserver_sk'],
                        cfg['networks'])
    cloud_regions = get_cloud_handlers(cfg['regions'])
    for network in cfg['networks']:
        cloud_handler = cloud_regions[network['region']]
        for ecs in cloud_handler.ecs_list_by_vpc_id(network['vpc_id']):
            jmsproxy.create_or_update_asset(ecs)
    logger.info('Sync asset. finished.')