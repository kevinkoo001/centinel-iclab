# Eric Goren nytikitaco@gmail.com
# Summer 2014

import ConfigParser
import os
import utils.http as http
import base64
import socket
import time
import pycurl
import re
from utils import logger
from centinel.experiment import Experiment


class ConfigurableHTTPRequestExperiment(Experiment):
    name = "config_http"
    REDIRECT_LIMIT = 50

    def __init__(self, input_file):
        self.input_file = input_file
        self.results = []
        self.host = None
        self.path = "/"
        self.args = dict()
        self.ssl = False
        self.addHeaders = False
        self.url = ""

        # These variables are class variables because they have to be accessed over multiple methods, including callback methods
        self.headers = []
        self.response_headers = dict()
        self.response_body = ""
        self.redirect_number = 0
        self.result = {}
        self.is_status_line = True

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
                self.headers.append("user-agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)")
            elif self.browser == "Firefox":
                self.headers.append("user-agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1")
            elif self.browser == "Chrome" or self.browser == "Google Chrome":
                self.headers.append("user-agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.56 Safari/537.17")
        for key in self.args.keys():
            if key.startswith("header_"):
                self.addHeaders = True
                value = self.args[key]
                header_key = ""
                split = key.split("header_")
                for x in range(1, len(split)):  # Just in case there are any conflicts in the split or header name
                    header_key += split[x]
                self.headers.append(header_key + ": " + value)


        url_list = parser.items('URLS')

        for url in url_list[0][1].split():
            self.url = url
            self.path = '/'
            self.host, self.path = self.get_host_and_path_from_url(url)
            self.whole_url = url
            self.pycurl_http_request()
            # self.http_request()

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

    def handle_headers(self, buf):
        if self.is_status_line:
            m = re.match(r'HTTP\/\S*\s*\d+\s*(.*?)\s*$', buf.splitlines()[0])
            if m:
                status_message = "%s" % m.groups(1)  # Removes extra formatting in string
                self.response_headers["Reason"] = status_message  # Store the status message as another header
            self.is_status_line = False
            return
        split = buf.splitlines()
        for line in split:
            if ": " not in line:  # If can't be split into header/value
                continue
            header_value_split = line.split(": ")
            header = header_value_split[0]
            value = ""
            for x in range(1, len(header_value_split)):  # In case there were more than one ': ' in the value...
                value += header_value_split[x]
            self.response_headers[header] = value


    def handle_body(self, body):
        self.response_body += body

    def write_curl_results(self, curl, last_url):
        key = "redirect_" + str(self.redirect_number)
        self.result[key] = dict()
        self.result[key]["response_number"] = self.redirect_number
        self.result[key]["response_status"] = str(curl.getinfo(pycurl.HTTP_CODE))
        self.result[key]["response_headers.b64"] = base64.b64encode(str(self.response_headers))
        self.result[key]["response_body.b64"] = base64.b64encode(self.response_body)
        if last_url is None:
            self.result[key]["response_url"] = self.whole_url
        else:
            self.result[key]["response_url"] = last_url
        if "Location" in self.response_headers.keys():
            self.result[key]["response_redirect_url"] = self.response_headers["Location"]



    def pycurl_http_request(self):

        self.result = {
                  "url": self.url,
                  "request_url": self.whole_url,
                  "host": self.host,
                  "request_path": self.path, }

        self.dns_test(self.result)
        self.response_headers.clear()  # Clear headers from previous tests

        c = pycurl.Curl()
        c.setopt(pycurl.URL, self.whole_url)
        c.setopt(pycurl.FOLLOWLOCATION, 0)  # Do not automatically handle redirects. We want to record data every step of the way
        c.setopt(pycurl.WRITEFUNCTION, self.handle_body)
        c.setopt(pycurl.HEADERFUNCTION, self.handle_headers)
        if self.addHeaders:
            c.setopt(pycurl.HTTPHEADER, self.headers)

        self.redirect_number = 0
        last_url = None
        while self.redirect_number == 0 or str(c.getinfo(pycurl.HTTP_CODE)).startswith("3"):
            if self.redirect_number == self.REDIRECT_LIMIT:
                logger.log("e", "Too many redirects... Breaking loop")
                break
            c.perform()
            self.write_curl_results(c, last_url)
            if str(c.getinfo(pycurl.HTTP_CODE)).startswith("3"):
                c.setopt(pycurl.URL, self.response_headers["Location"])
                if last_url is None:
                    logger.log("i", "Redirecting from " + self.whole_url + " to " + self.response_headers["Location"])
                else:
                    logger.log("i", "Redirecting from " + last_url + " to " + self.response_headers["Location"])
                last_url = self.response_headers["Location"]
            self.response_headers.clear()  # Clear headers in case there are redirects
            self.response_body = ""  # Clear response body for next field
            self.is_status_line = True
            self.redirect_number += 1
        c.close()
        self.results.append(self.result)
