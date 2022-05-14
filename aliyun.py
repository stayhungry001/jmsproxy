# aliyun-python-sdk-slb
# aliyun-python-sdk-core
# aliyun-python-sdk-ecs
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.auth.credentials import AccessKeyCredential
from aliyunsdkcore.request import RpcRequest
from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest
import json
from common import Ecs


class AliYun:
    def __init__(self, ak, sk, region_id):
        cred = AccessKeyCredential(ak, sk)
        self._clt = AcsClient(region_id=region_id, credential=cred)

    def _do_request(self, request: RpcRequest):
        request.set_accept_format('json')
        response = self._clt.do_action_with_exception(request)
        return json.loads(response)

    def _get_ecs_object(self, ecs) -> Ecs:
        _e = Ecs()
        _e.ecs_id = ecs['InstanceId']
        _e.instance_name = ecs['InstanceName']
        _e.vpc_id = ecs['VpcAttributes']['VpcId']
        _e.private_ip = ecs['VpcAttributes']['PrivateIpAddress']["IpAddress"][0]
        if ecs['PublicIpAddress']['IpAddress']:
            _e.public_ip = ecs['PublicIpAddress']['IpAddress'][0]
        _e.os_type = ecs['OSType']
        return _e

    def ecs_list_by_vpc_id(self, vpc_id: str):
        request = DescribeInstancesRequest()
        request.set_MaxResults(100)
        request.set_VpcId(VpcId=vpc_id)
        page = 1
        count = 0
        total = 100
        while count < total:
            request.set_PageNumber(page)
            response = self._do_request(request)
            for ecs in response['Instances']['Instance']:
                count += 1
                yield self._get_ecs_object(ecs)
            total = response['TotalCount']
            page += 1
