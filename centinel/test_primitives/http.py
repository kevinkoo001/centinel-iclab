# Eric Goren nytikitaco@gmail.com
# Summer 2014

import ConfigParser
import os
import utils.http as http
import base64
import socket
import time

from utils import logger
from centinel.experiment import Experiment


class ConfigurableHTTPRequestExperiment(Experiment):
    name = "config_http"

    def __init__(self, input_file):
        self.input_file = input_file
        self.results = []
        self.host = None
        self.path = "/"
        self.args = dict()
        self.ssl = False
        self.headers = {}
        self.addHeaders = False
        self.url = ""

    def run(self):
        parser = ConfigParser.ConfigParser()
        parser.read([self.input_file, ])
        if not parser.has_section('HTTP'):
            return

        self.args.update(parser.items('HTTP'))

        if 'browser' in self.args.keys():
            self.browser = self.args['browser']
            self.addHeaders = True
            if self.browser == "ie" or self.browser == "Internet Explorer":
                self.headers["user-agent"] = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
            elif self.browser == "Firefox":
                self.headers["user-agent"] = "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1"
            elif self.browser == "Chrome" or self.browser == "Google Chrome":
                self.headers["user-agent"] = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.56 Safari/537.17"
        for key in self.args.keys():
            if key.startswith("header_"):
                self.addHeaders = True
                value = self.args[key]
                header_key = ""
                split = key.split("header_")
                for x in range(1, len(split)):  # Just in case there are any conflicts in the split or header name
                    header_key += split[x]
                self.headers[header_key] = value

        url_list = parser.items('URLS')

        for url in url_list[0][1].split():
            self.url = url
            self.path = '/'
            self.host, self.path = self.get_host_and_path_from_url(url)
            self.whole_url = url
            self.http_request()

    def get_host_and_path_from_url(self, url):
        path = '/'
        temp_url = url
        url_without_http = ""
        host = ""
        if temp_url.startswith("http://") or temp_url.startswith("https://"):
            split_url = temp_url.split("/")
            for x in range(1, len(split_url)):
                if split_url[x] != "":
                    temp_url = split_url[x]
                    host_index = x
                    break
            url_without_http = temp_url
            for x in range(host_index + 1, len(split_url)):
                url_without_http += '/' + split_url[x]
            url_without_http_split = url_without_http.split("/")
            for x in range(1, len(url_without_http_split)):
                if url_without_http_split[x] != '':
                    path += url_without_http_split[x] + '/'
        elif '/' in temp_url:
            split = temp_url.split("/")
            temp_url = split[0]
            if len(split) > 1:
                for x in range(1, len(split)):
                    path += split[x] + '/'

        host = temp_url
        return host, path

    # Returns true of the string is an ip address
    def isIp(self, string):
        a = string.split('.')
        if len(a) != 4:
            return False
        for x in a:
            if not x.isdigit():
                return False
            i = int(x)
            if i < 0 or i > 255:
                return False
        return True

    # Records target_domain, target_ip address, and target_dns_success
    def dns_test(self, results):
        target_ip_address = ""
        target_domain = self.host
        if self.isIp(self.host):
            target_ip_address = self.host
            target_domain = self.host
            target_dns_success = True
        else:
            try:
                target_ip_address = socket.gethostbyname(self.host)
                target_dns_success = True
            except Exception as e:
                target_dns_success = False
                results["target_dns_error_text"] = str(e)

        results["target_ip_address"] = target_ip_address
        results["target_dns_success"] = str(target_dns_success)
        results["target_domain"] = target_domain

    def http_request(self):
        result = {"url": self.url}

        self.dns_test(result)
        # Make HTTP Request
        start_time = time.time()
        if self.addHeaders:
            http_result = http.get_request(self.host, self.path, self.headers, self.ssl)
            result["request_headers.b64"] = base64.b64encode(str(self.headers))
        else:
            http_result = http.get_request(self.host, self.path, ssl=self.ssl)
        end_time = time.time()
        all_redirects = []  # Contains dict("string", "string")
        result["request_url"] = self.whole_url
        result["host"] = self.host
        result["request_path"] = self.path
        result["request_method"] = http_result["request"]["method"]
        # If no response was received...
        if "body" not in http_result["response"]:
            logger.log("e", "No HTTP Response from " + self.whole_url)
            result["response_error_text"] = "No response"
            self.results.append(result)
            return

        status = http_result["response"]["status"]
        first_response = {}  # Will count as redirect 0
        first_response["response_url"] = self.whole_url
        first_response["response_number"] = 0
        first_response["response_time_taken_seconds"] = end_time - start_time
        headers = http_result["response"]["headers"]
        headers["reason"] = http_result["response"]["reason"]  # Add reason to headers
        first_response["response_headers.b64"] = base64.b64encode(str(headers))
        first_response["response_status"] = str(http_result["response"]["status"])
        first_response["response_body.b64"] = base64.b64encode(http_result["response"]["body"])

        is_redirecting = str(status).startswith("3") and "location" in http_result["response"]["headers"]  # Check for redirects
        if is_redirecting:
            first_response["response_redirect_url"] = http_result["response"]["headers"]["location"]
        all_redirects.append(first_response)
        result["redirect"] = str(is_redirecting)
        last_redirect = ""
        redirect_number = 1
        redirect_url = ""
        if is_redirecting:
            try:

                redirect_result = None
                while redirect_result is None or (str(redirect_result["response"]["status"]).startswith("3") and "location" in redirect_result["response"]["headers"]):  # While there are more redirects...
                    if redirect_number > 50:  # Break redirect after 50 redirects
                        logger.log("i", "Breaking redirect loop. Over 50 redirects")
                        break
                    if redirect_result is None:
                        redirect_url = http_result["response"]["headers"]["location"]
                    else:
                        redirect_url = redirect_result["response"]["headers"]["location"]
                    ssl = redirect_url.startswith("https://")
                    if redirect_url == last_redirect:
                        break
                    if last_redirect == "":
                        logger.log("i", "Redirecting from " + self.whole_url + " to " + redirect_url)
                    else:
                        logger.log("i", "Redirecting from " + last_redirect + " to " + redirect_url)
                    host, path = self.get_host_and_path_from_url(redirect_url)
                    start_time = time.time()
                    redirect_result = http.get_request(host, path, ssl=ssl)
                    if "body" not in http_result["response"]:
                        result["response_error_text"] = "No response from " + redirect_result
                        raise Exception("No HTTP Response from " + redirect_url)
                    end_time = time.time()
                    temp_results = {}
                    temp_results["response_url"] = redirect_url
                    temp_results["response_number"] = redirect_number
                    temp_results["response_time_taken_seconds"] = (end_time - start_time)
                    headers = redirect_result["response"]["headers"]
                    headers["reason"] = redirect_result["response"]["reason"]  # Add reason to headers
                    temp_results["response_headers.b64"] = base64.b64encode(str(headers))
                    temp_results["response_status"] = str(redirect_result["response"]["status"])
                    temp_results["response_body.b64"] = base64.b64encode(redirect_result["response"]["body"])
                    if "location" in redirect_result["response"]["headers"] and str(redirect_result["response"]["status"]).startswith("3"):
                        temp_results["response_redirect_url"] = redirect_result["response"]["headers"]["location"]
                    last_redirect = redirect_url
                    redirect_number += 1
                    all_redirects.append(temp_results)
            except Exception as e:
                logger.log("e", "Http redirect failed for " + redirect_url + " : " + str(e))
        result["responses"] = all_redirects
        result["total_redirects"] = str(redirect_number - 1)
        self.results.append(result)