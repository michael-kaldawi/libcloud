# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Verizon Cloud Compute Authentication (http://cloud.verizon.com/)
API Documentation: http://cloud.verizon.com/documentation/
Created by Michael Kaldawi (michael.kaldawi@verizon.com, mkaldawi@gmail.com)
"""

import datetime
import hmac
import hashlib
import base64
import json
import re

import requests
from setuptools.compat import unicode


class VerizonAuth(object):
    """
    Authentication class handles all authentication for interaction
        with Verizon Cloud Compute resources.
    """

    def __init__(self, host, secret_key, access_key):
        """
        :param secret_key:	User's secret API key
        :param access_key: 	User's access API key
        :param host: 		User's host url
        """
        self._host = host
        self._secret_key = secret_key
        self._access_key = access_key

    def _request(self, rest_verb, api_resource, headers={}, data={},
                 pretty_print=False):
        """
        This internal method performs the main request operations.
            Content Type Check,
            Encoding,
            Authentication,
            Signed String Creation,
            Perform Request,
            Print or return the request.

        :param rest_verb: 	    The API verb being used
        :param api_resource:    url extension to the wanted resource
        :param data: 		    data passed for POST or PATCH
        :param pretty_print: 	if True, prints JSON 'pretty print'
        :return self.results:   request results
        """
        self._rest_verb = rest_verb
        self._api_resource = api_resource
        content_type = ''
        canonicalized_headers = ''
        self._headers = headers
        self._pretty_print = pretty_print
        self.results = {}

        if 'Content-type' in headers.keys() is not None:
            content_type = headers['Content-type']
        else:
            content_type = ''

        """
        Ensure that the apiResource passed to the REST methods
            is sent as ASCII text and does not include the URL.
        """
        re.sub(self._host, '', api_resource.encode('ascii', 'ignore'))

        """
            All calls made via the F5 front-end must be signed against the
            user's keys.
            Create the signature and add the 'Date' and 'x-tmrk-authorization'
            headers to the request to enable key-based authentication.
            NOTE: Do *not* add the x-tmrk-org and x-tmrk-user headers to the request.
            These will cause the API to ignore the x-tmrk-authorization header, resulting in a 403.
        """
        now = datetime.datetime.utcnow()
        time_stamp = now.strftime("%a, %d %b %Y %H:%M:%S GMT")

        """
            Create the string to sign, comprising five fields, each terminated
            by a newline. All field must be in ASCII format.
                GET, POST, PATCH, etc, in all CAPS
                The MIME type of data being sent
                The timestamp as calculated above
                The canonicalized headers as calculated above
                The resource string, all lowercase
        """
        string_to_sign = self._rest_verb.encode('ascii', 'ignore') + "\n"
        string_to_sign += content_type.encode('ascii', 'ignore') + "\n"
        string_to_sign += time_stamp.encode('ascii', 'ignore') + "\n"
        string_to_sign += canonicalized_headers.encode('ascii', 'ignore') + "\n"
        string_to_sign += self._api_resource.encode('ascii', 'ignore') + "\n"
        signature = base64.b64encode(
            hmac.new(key=self._secret_key,
                     msg=unicode(string_to_sign, "utf-8"),
                     digestmod=hashlib.sha256).digest())
        self._headers.update(
            {'Date': time_stamp,
                'x-tmrk-authorization':
                'CloudApi AccessKey=' + self._access_key +
                ' SignatureType=HmacSHA256 Signature=' + signature}
        )

        """
            Perform the HTTP request.
        """
        r = requests.request(self._rest_verb, self._host + self._api_resource,
                             headers=self._headers, data=json.dumps(data))

        """
            Save the results to be returned to the user in JSON
        """
        self.results = json.loads(json.dumps(r.json()))

        """
            Print and/or return the results.
        """
        if pretty_print:
            print(json.dumps(self.results, indent=3))
            return
        else:
            return self.results

    def _get_content_types(self, rest_verb, api_resource):
        """
        This method fetches the correct mime types and content styles.

        :param rest_verb:     REST verb/action (POST, GET, etc.)
        :param api_resource:  URI of resource accessed (vm, vdisk, etc)
        :return headers:     headers for modification REST actions
        """
        headers = {}
        if rest_verb in ('GET', 'OPTIONS'):
            return headers

        """
            For a POST, PATCH, or DELETE call, make a REST OPTIONS call to
            the API Resource
        """
        types = self._request('OPTIONS', api_resource)
        if 'methods' in types.keys():
            if rest_verb in types['methods'].keys():
                # All valid resources will have an Accept MIME type and an href
                headers['Accept'] = types['methods'][rest_verb]['responseType']
                # But not all will have a Content-type
                if 'requestType' in types['methods'][rest_verb].keys():
                    headers['Content-type'] = \
                        types['methods'][rest_verb]['requestType']
        return headers

    def request(self, rest_verb, api_resource, data={}, dry_run=False,
                pretty_print=False):
        """
        This is the function a user will use to access VCC resources.

        :param rest_verb:        REST verb to be executed
        :param api_resource:     resource URI accessed
        :param data:            data for modifying resources (POST, PATCH)
        :param dry_run:          no real access if True - for testing
        :param pretty_print:       pretty printing option
        :return:                request results in dictionary
        """
        return self._request(rest_verb=rest_verb,
                             api_resource=api_resource,
                             headers=self._get_content_types(
                             rest_verb=rest_verb, api_resource=api_resource),
                             data=data,
                             pretty_print=pretty_print)

    if __name__ == '__main__':
        print("Verizon Cloud Compute Driver (http://cloud.verizon.com/) \
            API Documentation: http://cloud.verizon.com/documentation/ \
            Created by Michael Kaldawi (michael.kaldawi@verizon.com, " \
              "mkaldawi@gmail.com)")
        pass