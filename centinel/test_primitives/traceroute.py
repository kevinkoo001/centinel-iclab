import ConfigParser
import os
import subprocess
import socket
from centinel.experiment import Experiment
from utils import logger

# This traceroute works by pinging the host with incrementing TTLs
class ConfigurableTracerouteExperiment(Experiment):
    name = "config_traceroute"

    def __init__(self, input_file):
        self.input_file = input_file
        self.results = []
        self.args = dict()
        self.url = ""

    def run(self):
        parser = ConfigParser.ConfigParser()
        parser.read([self.input_file])
        if not parser.has_section('Traceroute'):
            return
        self.args.update(parser.items('Traceroute'))
        url_list = parser.items('URLS')

        if 'max_hops' in self.args.keys():
            self.max_hops = int(self.args['max_hops'])
        else:
            self.max_hops = 30

        if 'start_hop' in self.args.keys():
            self.start_hop = int(self.args['start_hop'])
        else:
            self.start_hop = 1

        if 'timeout' in self.args.keys():
            self.timeout = int(self.args['timeout'])
        else:
            self.timeout = 3

        for url in url_list[0][1].split():
            self.url = url
            temp_url = url
            if temp_url.startswith("http://") or temp_url.startswith("https://"):
                split_url = temp_url.split("/")
                for x in range(1, len(split_url)):
                    if split_url[x] != "":
                        temp_url = split_url[x]
                        break
            elif '/' in temp_url:
                temp_url = temp_url.split("/")[0]
            self.host = temp_url
            self.traceroute()

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

    # Returns if the string is an ip address
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

    def traceroute(self):

        results = {
            "url": self.url,
            "host": self.host,
            "max_hops": self.max_hops,
            "start_hop": self.start_hop,
            "timeout": self.timeout
        }

        self.dns_test(results)

        traceroute_results = []  # Contains Dict("string", "string")
        try:
            t = self.start_hop
            finalIp = "Placeholder"
            logger.log("i", "Conducting traceroute on " + self.host)
            for t in range(self.start_hop, self.max_hops + 1):
                process = ['ping', self.host, '-c 1', '-t ' + str(t), '-W ' + str(self.timeout)]
                # Ping in separate process
                response = subprocess.Popen(process, stdout=subprocess.PIPE).communicate()[0]

                # Parse the process output for information on the ping
                if t == 1:
                    if response == "":
                        raise Exception("Host not available")
                    pingSendInfo = response.splitlines()[0]
                    pingSendSplit = pingSendInfo.split()
                    finalIp = pingSendSplit[2].translate(None, '()')
                ping_info = response.splitlines()[1]
                split_by_word = str.split(ping_info)
                reverseDns = "Not Found"
                ip = "Not Found"
                for string in split_by_word:
                    stripped = string.translate(None, '():')
                    if self.isIp(stripped):
                        ip = stripped
                    if '=' not in stripped and '.' in stripped and not self.isIp(stripped):
                        reverseDns = stripped
                temp_results = {}  # Results for this hop of the traceroute
                temp_results["hop_number"] = str(t)
                temp_results["ip"] = ip
                temp_results["reverse_dns"] = reverseDns
                traceroute_results.append(temp_results)
                if ip == "Not Found" and reverseDns != "Not Found":
                    pass  # May implement something here later to see what happened
                if ip == finalIp or t == self.max_hops:
                    logger.log("s", "Finished Traceroute")
                    break
            results["total_hops"] = t
            results["traceroute"] = traceroute_results
        except Exception as e:
            logger.log("e", "Error occured in traceroute for " + self.host + ": " + str(e))
            results["error_text"] = str(e)
        self.results.append(results)
