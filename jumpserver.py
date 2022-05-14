import requests
import datetime
from httpsig.requests_auth import HTTPSignatureAuth
from common import Ecs, logger


class JmsErrorResponse(Exception):
    def __init__(self, status_code, expected_code, response_message):
        self._status_code = status_code
        self._expected_code = expected_code
        self._response_message = response_message

    def __str__(self):
        return "Jumpserver response error, status code: {}, expected status code {}, messsage: {}".format(
            self._status_code, self._expected_code, self._response_message
        )


class Jumpserver:
    def __init__(self, host: str, access_key_id, access_key_secret):
        self.__host = host
        self.__auth = self._get_auth(access_key_id, access_key_secret)

    @staticmethod
    def _get_auth(access_key_id, access_key_secret):
        signature_headers = ['(request-target)', 'accept', 'date']
        auth = HTTPSignatureAuth(key_id=access_key_id,
                                 secret=access_key_secret,
                                 algorithm='hmac-sha256',
                                 headers=signature_headers)
        return auth

    def __get_headers(self):
        return

    def __do_requests(self, method, uri, params=None, json_body=None, status_code=200):
        url = '{}{}'.format(self.__host.rstrip("/"), uri)
        headers = {
            'Accept': 'application/json',
            'X-JMS-ORG': '00000000-0000-0000-0000-000000000002',
            'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        }
        response = getattr(requests, method)(url,
                                             auth=self.__auth,
                                             headers=headers,
                                             params=params,
                                             json=json_body)

        if response.status_code == status_code:
            return response.json()
        else:
            raise JmsErrorResponse(response.status_code, status_code, response.text)

    def patch(self, uri, json_body, status_code=200):
        return self.__do_requests('patch', uri, json_body=json_body, status_code=status_code)

    def post(self, uri, json_body, status_code=201):
        return self.__do_requests('post', uri, json_body=json_body, status_code=status_code)

    def get(self, uri, params=None, status_code=200):
        return self.__do_requests('get', uri, status_code=status_code)

    def delete(self, url, status_code=204):
        return self.__do_requests('delete', url, status_code=status_code)

    def list(self, url, params: dict):
        params['limit'] = 10
        offset = 0
        total = 100
        while offset < total:
            params['offset'] = offset
            response = self.get(url, params)
            for item in response['results']:
                offset += 1
                yield item
            total = response['count']

    def create_asset(self, ecs_id, hostname, private_ip, public_ip, admin_user_id, node_id, domain):
        url = "/api/v1/assets/assets/"
        j_body = {
            "hostname": hostname,
            "ip": private_ip,
            "platform": "Linux",
            "protocol": "ssh",
            "comment": "{}|{}".format(ecs_id, public_ip),
            "domain": domain,
            "nodes": [node_id],
            "admin_user": admin_user_id
        }
        return self.post(url, j_body)

    def get_assets(self):
        return self.get('/api/v1/assets/assets/', params={})

    def get_user_info(self):
        return self.get('/api/v1/users/users/', params={})

    def get_nodes(self):
        return self.get('/api/v1/assets/nodes/')

    def get_admin_users(self):
        return self.get('/api/v1/assets/admin-users/', params={})

    def get_domains(self):
        return self.get('/api/v1/assets/domains/', params={})

    def update_asset(self, asset_id, attributes: dict):
        """
        update asset by asset id
        :param asset_id: the asset id from jumpserver
        :param attributes: The attributes needes to be updated.
                            Valid key incluse: hostname, public ip, nodes
        :return:
        """

        url = "/api/v1/assets/assets/{}/".format(asset_id)
        return self.patch(url, json_body=attributes)

    def delete_asset(self, asset_id):
        url = "/api/v1/assets/assets/{}/".format(asset_id)
        return self.delete(url)


class JmsProxy:
    def __init__(self, host: str, access_key_id, access_key_secret, networks):
        self.__jms = Jumpserver(host, access_key_id, access_key_secret)
        self.__networks = networks
        self.__init_assets()
        self.__init_nodes()
        self.__init_admin_users()
        self.__init_domains()
        self.__ecs_ids = set()

    def __init_domains(self):
        self.__domains = {}
        for domain in self.__jms.get_domains():
            self.__domains[domain['name']] = domain['id']

    def __init_admin_users(self):
        self.__admin_users = {}
        for user in self.__jms.get_admin_users():
            self.__admin_users[user['name']] = user['id']

    def __init_nodes(self):
        self.__nodes = {}
        for node in self.__jms.get_nodes():
            self.__nodes[node['name']] = node['id']

    def __init_assets(self):
        self._assets = {}
        for asset in self.__jms.get_assets():
            self.__cache_asset(asset)

    def __cache_asset(self, asset):
        comment = asset['comment']
        server_id = comment.split('|')[0] if comment else asset['hostname']
        self._assets[server_id] = {
            'private_ip': asset['ip'],
            'public_ip': asset['public_ip'] if asset['public_ip'] else "",
            'hostname': asset['hostname'],
            'asset_id': asset['id'],
            'node_id': asset['nodes'][0]
        }

    def __get_network_by_vpc_id(self, vpc_id):
        for network in self.__networks:
            if network['vpc_id'] == vpc_id:
                return network

    def __get_node_id_by_hostname(self, hostname: str):
        _tags = hostname.split('-')
        if len(_tags) > 4 and self.__nodes.get(_tags[3]):
            return self.__nodes.get(_tags[3])
        return self.__nodes.get('default')

    def update_asset(self, ecs: Ecs):
        asset = self._assets.get(ecs.ecs_id)
        if asset is None:
            return
        attributes = {}
        if asset['hostname'] != ecs.instance_name:
            attributes['hostname'] = ecs.instance_name
            attributes['nodes'] = [self.__get_node_id_by_hostname(ecs.instance_name)]
        if asset['public_ip'] != ecs.public_ip:
            attributes['public_ip'] = ecs.public_ip
            attributes['comment'] = "{}|{}".format(ecs.ecs_id, ecs.public_ip)
        if attributes:
            logger.info("update asset {} with attributes. {}".format(asset['hostname'],
                                                                     ";".join(
                                                                         ["{}:{}".format(key, value) for key, value in
                                                                          attributes.items()])))
            asset = self.__jms.update_asset(asset['asset_id'], attributes)
            self.__cache_asset(asset)

    def create_or_update_asset(self, ecs: Ecs) -> None:
        self.__ecs_ids.add(ecs.ecs_id)
        if ecs.os_type == "windows":
            return
        if self._assets.get(ecs.ecs_id):
            self.update_asset(ecs)
        else:
            network = self.__get_network_by_vpc_id(ecs.vpc_id)
            logger.info('create asset {}.'.format(ecs.instance_name))
            asset = self.__jms.create_asset(ecs.ecs_id,
                                            ecs.instance_name,
                                            ecs.private_ip,
                                            ecs.public_ip,
                                            self.__admin_users.get(network['admin_user']),
                                            self.__get_node_id_by_hostname(ecs.instance_name),
                                            self.__domains.get(network['name']))
            self.__cache_asset(asset)

    def clean_asset(self):
        """
        Clean asset after all assets are synced. The __ecs_ids caches the ecs id list every time.
        Be careful to make sure all assets are synced before clean asset.
        :return:
        """
        for asset_id, asset in self._assets.items():
            if self.__nodes.get(asset['node_id']) not in ['prod', 'test', 'dev', 'pre']:
                continue
            if asset_id in self.__ecs_ids:
                logger.info('Delete asset {}.'.format(asset['hostname']))
                # self.__jms.delete_asset(asset['asset_id'])
        self.__ecs_ids = set()
