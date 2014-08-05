import ConfigParser
import socket
from centinel.experiment import Experiment


class ConfigurableTCPConnectExperiment(Experiment):
    name = "conig_tcp_connect"

    def __init__(self, input_file):
        self.input_file = input_file
        self.results = []
        self.host = None
        self.port = None
        self.args = dict()

    def run(self):
        parser = ConfigParser.ConfigParser()
        parser.read([self.input_file, ])
        if not parser.has_section('TCP'):
            return

        self.args.update(parser.items('TCP'))

        # one port for all of the URLs
        if 'port' in self.args.keys():
            self.port = self.args['port']
        else:
            self.port = "80"

        url_list = parser.items('URLS')
        for url in url_list[0][1].split():
            temp_url = url
            # get host name from url
            if temp_url.startswith("http://") or temp_url.startswith("https://"):
                split_url = temp_url.split("/")
                for x in range(1, len(split_url)):
                    if split_url[x] != "":
                        temp_url = split_url[x]
                        break
            elif '/' in temp_url:
                temp_url = temp_url.split("/")[0]
            self.host = temp_url
            self.tcp_connect()

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

    def tcp_connect(self):
        result = {
            "host": self.host,
            "port": self.port
        }
        self.dns_test(result)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, int(self.port)))
            sock.close()
            result["success"] = "True"
        except Exception as err:
            result["error_text"] = str(err)
            result["success"] = "False"

        self.results.append(result)
