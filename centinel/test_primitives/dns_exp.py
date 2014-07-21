import dns.resolver
import ConfigParser
import os
import struct
import random
import socket

from centinel.experiment import Experiment
from utils import logger

class ConfigurableDNSExperiment(Experiment):
    name = "config_dns"
    def __init__(self, input_file):
        self.input_file = input_file
        self.results = []
        self.args = dict()

    def run(self):
        parser = ConfigParser.ConfigParser()
        parser.read([self.input_file, ])
        if not parser.has_section('DNS'):
            return

        self.args.update(parser.items('DNS'))

        if 'resolver' in self.args.keys():
            self.resolver = self.args['resolver']
        else:
            self.resolver = "8.8.8.8"

        if 'record' in self.args.keys():
            self.record = self.args['record']
        else:
            self.record = 'A'

        if 'timeout' in self.args.keys():
            self.timeout = int(self.args['timeout'])
        else:
            self.timeout = 3

        url_list = parser.items('URLS')
        for url in url_list[0][1].split():
            self.host = url
            self.dns_test()

    def build_packet(self, url, record_type=0x0001):
        packet = struct.pack("!6H", random.randint(1, 65536), 256, 1, 0, 0, 0)
        split_url = url.split(".")
        for part in split_url:
            packet += struct.pack("!B", len(part))
            for byte in bytes(part):
                packet += struct.pack("!c", byte)
        packet += struct.pack("!B2H", 0, int(record_type), 1)
        return packet

    def test_for_second_packet(self, result):
        packet = self.build_packet(self.host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('', 8888))
            sock.settimeout(self.timeout)
            sock.sendto(packet, (self.resolver, 53))
            received_first_packet = False
            try:
                data, addr = sock.recvfrom(1024)
                received_first_packet = True
            except socket.timeout:
                logger.log("i", "Didn't receive first packet")
            received_second_packet = False
            result["first_packet"] = str(received_first_packet)
            if received_first_packet:
                try:
                    second_packet, addr = sock.recvfrom(1024)
                    received_second_packet = True
                    logger.log("i", "Received second DNS Packet")
                except socket.timeout:
                    logger.log("i", "Didn't receive second packet")
            result["second_packet"] = str(received_second_packet)
        except socket.timeout:
            logger.log("i", "Socket timed out")
        except Exception as e:
            logger.log("e", "Error in socket creation: " + str(e))
        sock.close()




    def dns_test(self):
        result = {
            "host": self.host,
            "resolver": self.resolver,
            "record_type": self.record,
            "timeout": self.timeout
        }
        ans = ""
        if self.record == 'A':
            res = dns.resolver.query(self.host, self.record)
            for i in res.response.answer:
                if ans == "":
                    ans = i.to_text()
                else:
                    ans = ans + ", " + i.to_text()
        else:
            try:
                query = dns.message.make_query(self.host, self.record)
                response = dns.query.udp(query, self.resolver, timeout=self.timeout)
                for answer in response.answer:
                    if ans == "":
                        ans = answer.to_text()
                    else:
                        ans += ", " + answer.to_text()
            except dns.exception.Timeout:
                logger.log("e", "Query Timed out for " + self.host)
                ans = "Timeout"
            except Exception as e:
                logger.log("e", "Error Querying " + self.record + " record for " + self.host + " (" + str(e) + ")")
                ans = "Error"

        if ans != "Error":
            if ans == "":
                ans = self.record + " records unavailable for " + self.host
                logger.log("i", ans)
            else:
                logger.log("s", ans)


        result['record'] = ans

        self.test_for_second_packet(result)

        self.results.append(result)
