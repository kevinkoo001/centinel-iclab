# Eric Goren nytikitaco@gmail.com
# Summer 2014

import dns.resolver
import ConfigParser
import os
import struct
import random
import socket
import base64
import dns
import dns.rdatatype
from centinel.experiment import Experiment
from utils import logger
from dns import reversename


class ConfigurableDNSExperiment(Experiment):
    name = "config_dns"

    def __init__(self, input_file):
        self.input_file = input_file
        self.results = []
        self.args = dict()
        self.resolver = "8.8.8.8"
        self.record_types = []
        self.timeout = 15
        self.second_record_timeout = 3
        self.url = ""
        self.rdclass = 1
        self.chaos_question = ""

    def run(self):
        parser = ConfigParser.ConfigParser()
        parser.read([self.input_file, ])
        if not parser.has_section('DNS'):
            return

        self.args.update(parser.items('DNS'))

        if 'resolver' in self.args.keys():
            self.resolver = self.args['resolver']

        if 'chaos_question' in self.args.keys():
            self.chaos_question = self.args['chaos_question']

        if 'record_types' in self.args.keys():
            record = self.args['record_types']
            records = record.split(" ")
            for rec in records:
                self.record_types.append(rec)
        else:
            self.record_types.append("A")

        # Allow backwards compatibility for older configurable experiments
        if 'record' in self.args.keys():
            record = self.args['record']
            self.record_types.append(record)

        if 'timeout' in self.args.keys():
            self.timeout = int(self.args['timeout'])

        if 'class' in self.args.keys():
            self.rdclass = dns.rdataclass.from_text(self.args['class'])

        url_list = parser.items('URLS')
        for url in url_list[0][1].split():
            self.url = url
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
            self.dns_test()

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

    # Builds an A-Record DNS Packet
    # This packet is used to test if there is another packet being sent by the censor
    def build_packet(self, url, record_type=0x0001):
        packet = struct.pack("!6H", random.randint(1, 65536), 256, 1, 0, 0, 0)
        split_url = url.split(".")
        for part in split_url:
            packet += struct.pack("!B", len(part))
            for byte in bytes(part):
                packet += struct.pack("!c", byte)
        packet += struct.pack("!B2H", 0, int(record_type), 1)
        return packet

    # Tests to see if another DNS Packet is being sent by sending an A-Record DNS Packet and listening twice
    def test_for_second_packet(self, result):
        packet = self.build_packet(self.host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('', 8888))
            sock.settimeout(self.second_record_timeout)
            sock.sendto(packet, (self.resolver, 53))
            received_first_packet = False
            try:
                first_packet, addr = sock.recvfrom(1024)
                received_first_packet = True
                result["first_packet.b64"] = base64.b64encode(first_packet)
            except socket.timeout:
                logger.log("i", "Didn't receive first packet")
            received_second_packet = False
            result["received_first_packet"] = str(received_first_packet)
            if received_first_packet:
                try:
                    second_packet, addr = sock.recvfrom(1024)
                    received_second_packet = True
                    result["second_packet.b64"] = base64.b64encode(second_packet)
                    logger.log("i", "Received second DNS Packet")
                except socket.timeout:
                    logger.log("i", "Didn't receive second packet")
            result["received_second_packet"] = str(received_second_packet)
        except socket.timeout:
            logger.log("i", "Socket timed out")
        except Exception as e:
            logger.log("e", "Error in socket creation: " + str(e))
        if sock is not None:
            sock.close()

    def dns_test(self):
        record_type_string = ""
        for x in range(0, len(self.record_types)):
            record_type_string += self.record_types[x]
            if x != len(self.record_types) - 1:
                record_type_string += ", "

        result = {
            "url": self.url,
            "host": self.host,
            "resolver": self.resolver,
            "record_types": record_type_string,
            "timeout": self.timeout,
            "record_class": self.rdclass
        }

        result["records"] = dict()
        ans = ""
        for record_type in self.record_types:
            result["records"][record_type] = dict()
            dns_records = []  # Array to store DNS Records
            if self.isIp(self.host) and record_type == "A":  # If Ip is passed in instead of Url, default to PTR record
                try:
                    addr = reversename.from_address(self.host)  # Get address
                    answers = dns.resolver.query(addr, "PTR")  # Query PTR Records
                    for i in answers.response.answer:
                        logger.log("s", i.to_text())
                        dns_records.append(i.to_text())  # Add the record to the list
                except Exception as e:
                    logger.log("e", "Error querying PTR records for Ip " + self.host + " (" + str(e) + ")")
                    ans += "Error (" + str(e) + ")" + "; "
            else:
                try:
                    if self.rdclass == 3:
                        result["chaos_query_question"] = self.chaos_question
                        if not self.isIp(self.host):
                            ip = socket.gethostbyname(self.host)
                        else:
                            ip = self.host
                        query = dns.message.make_query(self.chaos_question, "TXT", rdclass=self.rdclass)
                        response = dns.query.udp(query, ip, timeout=self.timeout)  # Get the response of the query
                    else:
                        query = dns.message.make_query(self.host, record_type, rdclass=self.rdclass)
                        query.flags |= dns.flags.RD  # Desire recursion
                        query.find_rrset(query.additional, dns.name.root, self.rdclass, dns.rdatatype.OPT, create=True, force_unique=True)
                        response = dns.query.udp(query, self.resolver, timeout=self.timeout)  # Get the response of the query
                    for answer in response.answer:
                        if "\n" in answer.to_text():  # Sometimes these records are separated by newlines in one answer
                            for resp in answer.to_text().split("\n"):
                                dns_records.append(resp)
                                logger.log("s", resp)
                        else:
                            dns_records.append(answer.to_text())
                            logger.log("s", answer.to_text())
                except dns.exception.Timeout:
                    logger.log("e", "Query Timed out for " + self.host)
                    ans += "Timeout" + "; "
                except Exception as e:
                    logger.log("e", "Error Querying " + record_type + " record for " + self.host + " (" + str(e) + ")")
                    ans += "Error (" + str(e) + ")" + "; "

            if not ans.startswith("Error ("):
                if len(dns_records) == 0:
                    ans += record_type + " records unavailable for " + self.host + "; "

            result["records"][record_type]["dns_records"] = dns_records
            result["records"][record_type]['records_received'] = len(dns_records)

        if ans != "":
            ans = ans[:-2]  # Remove extra semicolon and space
            logger.log("i", ans)
        result["error_text"] = ans

        self.test_for_second_packet(result)

        self.results.append(result)