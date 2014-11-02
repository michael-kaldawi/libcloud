# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Verizon Cloud Compute Driver (http://cloud.verizon.com/)
API Documentation: http://cloud.verizon.com/documentation/
Created by Michael Kaldawi (michael.kaldawi@verizon.com, mkaldawi@gmail.com)
"""
from setuptools.compat import unicode

"""
Instructions
------------

"""

import base64
import re
import datetime
import hmac
import hashlib

from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import b

from libcloud.compute.providers import Provider
from libcloud.common.base import JsonResponse, ConnectionUserAndKey
from libcloud.compute.types import (NodeState, InvalidCredsError,
                                    LibcloudError)
from libcloud.compute.base import (Node, NodeDriver, NodeImage, NodeSize,
                                   NodeLocation)
from libcloud.utils.networking import is_private_subnet
from libcloud.common.verizon import VerizonAuth

API_HOST = 'iadg2.cloud.verizon.com'            # TO BE REMOVED - for dev
ACCESS_KEY = 'API_KEY'     # TO BE REMOVED - for dev
SECRET_KEY = 'API_SECRET_KEY' # TO BE REMOVED - for dev


NODE_STATE_MAP = {
    'ON': NodeState.RUNNING,
    'OFF': NodeState.STOPPED,
    'IN_PROGRESS': NodeState.PENDING,
    'STARTING': NodeState.PENDING,
    'STOPPING': NodeState.PENDING,
    'TERMINATED': NodeState.TERMINATED,
    'UNKNOWN': NodeState.UNKNOWN,
}

PATH = {
    'vm': '/api/compute/vm',
    'vdisk-template': '/api/compute/vdisk-template',
    'ip': '/api/compute/ip-address'
}

VALID_RESPONSE_CODES = [httplib.OK, httplib.ACCEPTED, httplib.CREATED,
                        httplib.NO_CONTENT]
CONNECT_ATTEMPTS = 10

class VerizonResponse(JsonResponse):
    """
    Verizon API Response
    """

    def parse_error(self):
        if self.status == httplib.UNAUTHORIZED:
            raise InvalidCredsError('Authorization Failed')
        if self.status == httplib.NOT_FOUND:
            raise Exception("The resource you are looking for is not found.")

        return self.body

    def success(self):
        return self.status in VALID_RESPONSE_CODES

class VerizonConnectionKey(ConnectionUserAndKey):
    pass

class VerizonConnection(ConnectionUserAndKey):
    host = API_HOST
    responseCls = VerizonResponse
    allow_insecure = False

    def add_default_headers(self, headers):
        headers.update(self._addAuthHeaders(method=self.method, action=self.action))
        if self.method in ('GET', 'OPTIONS'):
            return headers

        #Make a REST OPTIONS call to the API Resource
        prev_method = self.method
        types = self.request(action=self.action, method='OPTIONS').object
        self.method = prev_method
        if 'methods' in types.keys():
            if self.method in types['methods'].keys():
                #All valid resources will have an Accept MIME type
                headers['Accept'] = types['methods'][self.method]['responseType']
                #But not all will have a Content-type
                if 'requestType' in types['methods'][self.method].keys():
                    headers['Content-type'] = types['methods'][self.method]['requestType']
        return headers

    def pre_connect_hook(self, params, headers):
        return params, headers

    def _addAuthHeaders(self, method, action):
        now = datetime.datetime.utcnow() + datetime.timedelta()
        # NOTE: There is a timeshift
        # problem in some environments
        # Add a timedelta if needed.
        timeStamp = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
        contentType = ''
        canonicalizedHeaders = ''

        # Create the string to sign, comprising five fields,
        #  each terminated by a newline
        # All field must be in ASCII format
        stringToSign =  method.encode('ascii', 'ignore') + "\n"				    # GET, POST, PATCH, etc, in all CAPS
        stringToSign += contentType.encode('ascii', 'ignore') + "\n"   # The MIME type of data being sent.
        stringToSign += timeStamp.encode('ascii', 'ignore') + "\n"				# The timestamp as calculated above
        stringToSign += canonicalizedHeaders.encode('ascii', 'ignore') + "\n"   # The canonicalized headers as calculated above
        stringToSign += action.encode('ascii', 'ignore') + "\n"			        # The resource string, all lowercase

        signature = base64.b64encode(hmac.new(key=SECRET_KEY, msg=unicode(stringToSign, "utf-8"), digestmod=hashlib.sha256).digest())

        return {'Date': timeStamp,
                'x-tmrk-authorization': 'CloudApi AccessKey=' + ACCESS_KEY + ' SignatureType=HmacSHA256 Signature=' + signature }

class VerizonCloudComputeNodeDriver(NodeDriver):
    """
    Verizon node driver class.

    # >>> from libcloud.compute.providers import get_driver
    # >>> driver = get_driver('vcc')
    # >>> conn = driver('API_KEY', \
    # 'API_SECRET_KEY')
    # >>> conn.list_nodes()
    """
    type = Provider.VCC
    api_name = 'vcc'
    name = 'VerizonCloudCompute'
    website = 'http://cloud.verizon.com'
    connectionCls = VerizonConnection

    def allocate_ip(self):
        result = self.connection.request(action=PATH['ip'], method='POST', data={}).object
        return result

    def list_images(self):
        result = self.connection.request(action=PATH['vdisk-template']).object
        return [self._to_image(value) for value in result.get('items', [])]

    def list_nodes(self):
        """
        List available nodes

        :rtype: ``list`` of :class:`Node`
        """
        result = self.connection.request(action=PATH['vm']).object
        return [self._to_node(data=value) for value in result.get('items', [])]

    def _to_node(self, data):
        """Convert node in Node instances
        """

        state = NODE_STATE_MAP.get(data.get('status'))

        extra = {
            'arch': data.get('arch'),
            'consoleHref': data.get('consoleHref'),
            'controllers': data.get('controllers'),
            'description': data.get('description'),
            'diskOps': data.get('diskOps'),
            'guestCustomizations': data.get('guestCustomizations'),
            'href': data.get('href'),
            'jobHistory': data.get('jobHistory'),
            'memory': data.get('memory'),
            'os': data.get('name'),
            'processorCores': data.get('processorCores'),
            'processorSpeed': data.get('processorSpeed'),
            'tags': data.get('tags'),
            'type': data.get('type'),
            'vdiskMounts': data.get('vdiskMounts'),
            'vmMetrics': data.get('vmMetrics'),
            'vnics': data.get('vnics'),
        }

        node = Node(id=data.get('id'), name=data.get('name'),
                    public_ips=['vnics'], private_ips=['vnics'],    # HACK, need to fix
                    state=state, driver=self, extra=extra)
        return node

    def _to_image(self, data):
        image = NodeImage(id=data.get('id'), name=data.get('name'), driver=self, extra=data)
        return image


from libcloud.compute.providers import get_driver
import json
driver = get_driver('vcc')
conn = driver(key=ACCESS_KEY, secret=SECRET_KEY)
# nodes = conn.list_nodes()
#
# for i in range(len(nodes)):
#     print nodes[i].name
#     print json.dumps(nodes[i].extra, sort_keys=False, indent=4)
#
# images = conn.list_images()

result =  conn.allocate_ip()


