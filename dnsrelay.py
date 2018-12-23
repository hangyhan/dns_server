# coding=utf-8
import argparse
from socketserver import BaseRequestHandler, ThreadingUDPServer
import dns.resolver
import time
import struct

HOST_IP = "172.16.42.210"


def lib_build(config_path):
    """
        Create the libaray of local DNS server
    """
    lib = {}
    file = open(config_path, 'r')
    for line in file.readlines():
        entry = line.strip('\n').split(' ')
        lib.update({entry[1]: entry[0]})
    file.close()
    return lib


def debugger_config(FLAGS):
    """
        Configure the debug mode and DNS server
    """
    if not (FLAGS.d or FLAGS.dd):
        print("Debugging with level-1\n")
        debug_mode = 1
    elif FLAGS.d:
        if FLAGS.server_addr is None:
            print(
                "Error. [--server_addr] is needed in level-2 debugging mode.")
            exit(-1)
        elif FLAGS.config_path is None:
            print(
                "Error. [--config_path] is needed in level-1 debugging mode.")
            exit(-1)
        print("Debugging with level-2\n")
        debug_mode = 2
    else:
        if FLAGS.server_addr is None:
            print("Error. [--server_addr] is need in level-3 debugging mode.")
            exit(-1)
        print("Debugging with level-3\n")
        debug_mode = 3

    lib = lib_build(FLAGS.config_path)
    return lib, debug_mode, FLAGS.server_addr


class DNSHandler(BaseRequestHandler):

    def DNS_query_resolver(self, message):
        """
            resolve the dns query message
        """
        query_id, flag, query_num, ans_RR_num, auth_RR_num, addi_RR_num = struct.unpack(
            '>HHHHHH', message[0:12])
        header = {"query_id": query_id, "flag": flag, "query_num": query_num,
                  "ans_RR_num": ans_RR_num, "auth_RR_num": auth_RR_num, "addi_RR_num": addi_RR_num}
        entity = message[12:]
        body = {}
        i = 1
        domain = ''
        while True:
            if entity[i] == 0:
                break
            elif entity[i] < 32:
                domain += '.'
            else:
                domain += chr(entity[i])
            i += 1
        query_bytes = entity[0:i+1]
        (query_type, query_classify) = struct.unpack('>HH', entity[i+1:i+5])
        query_length = i+5
        body.update({"domain": domain, "queryBytes": query_bytes, "queryType": query_type,
                     "queryClassify": query_classify, "queryLen": query_length})

        return header, body

    def Print_Debug_Info(self, debug_mode, query_id, domain, ip_addr, client_address, query_header, query_body):
        """
            Print the information for debugging
        """
        if debug_mode == 1:
            print("domain name: %s" % domain)
            print("IP address: %s\n" % ip_addr)
        elif debug_mode == 2:
            print("Time: %s" % str(time.strftime(
                '%Y.%m.%d %H:%M:%S', time.localtime(time.time()))))
            print("Request ID: %s" % query_id)
            print("Client address: %s" % client_address[0])
            print("domain name: %s\n" % domain)
        else:
            print("ID: ", query_header['query_id'])
            print("Flag: ", query_header['flag'])
            print("Questions:", query_header['query_num'])
            print("Answers:", query_header['ans_RR_num'])
            print("Author:", query_header['auth_RR_num'])
            print("Additional:", query_header['addi_RR_num'])
            print("domain name:", query_body['domain'])
            print("Type:", query_body['queryType'])
            print("Classify:", query_body['queryClassify'])
            print("Length:", query_body['queryLen'])
            print("Server IP address: %s" % HOST_IP)
            print("Port:", 53)
            print("IP address: %s\n" % ip_addr)

    def create_dnsmsg(self, header, body, ip_addr):
        """
            Create the response message
        """
        self.answers = 1
        if ip_addr =='0.0.0.0':
            self.flags = 33155
        else:
            self.flags = 33152
        self.name = 49164
        self.type = 1
        self.classify = 1
        self.ttl = 5000
        self.datalength = 4

        msg = struct.pack('>HHHHHH', header["query_id"], self.flags,
                          header["query_num"], self.answers, header["auth_RR_num"], header["addi_RR_num"])
        msg += body['queryBytes'] + \
            struct.pack('>HH', body['queryType'], body["queryClassify"])

        res = struct.pack('>HHHLH', self.name, self.type,
                          self.classify, self.ttl, self.datalength)
        fragment = ip_addr.split('.')
        res += struct.pack('BBBB', int(fragment[0]), int(
            fragment[1]), int(fragment[2]), int(fragment[3]))
        msg += res
        return msg

    def query_ext_server(self, server_addr, domain):
        """
            send query to the external dns server
        """
        ext_sever = dns.resolver.Resolver()
        ext_sever.nameservers = [server_addr]
        try:
            response = ext_sever.query(domain, 'A')
            #print("from external DNS server%s"%ip_addr)
            return str(response[0])
        except Exception:
            return None

    def handle(self):
        query, sock = self.request
        query_header, query_body = self.DNS_query_resolver(query)

        if query_body['queryType'] != 1:
            sock.sendto("Sever can't handle this query type.".encode(),
                        self.client_address)
        else:
            if query_body['domain'] in DNSServer.lib:
                """
                    domain name is in local DNSServer's library
                """
                self.Print_Debug_Info(
                    DNSServer.debug_mode, query_header['query_id'], query_body['domain'], DNSServer.lib[query_body['domain']], self.client_address, query_header, query_body)
                sock.sendto(self.create_dnsmsg(query_header, query_body,
                                               DNSServer.lib[query_body['domain']]), self.client_address)

            else:
                """
                    domain name is not in local DNSServer's library
                """
                ip_addr = self.query_ext_server(
                    DNSServer.dns_addr, query_body['domain'])

                if ip_addr is None:
                    self.Print_Debug_Info(DNSServer.debug_mode,
                                          query_header['query_id'], query_body['domain'], "Not Found on external DNS server!", self.client_address, query_header, query_body)
                    sock.sendto(
                        query, self.client_address)
                else:
                    DNSServer.lib.update({query_body['domain']:ip_addr})
                    self.Print_Debug_Info(DNSServer.debug_mode,
                                          query_header['query_id'], query_body['domain'], ip_addr, self.client_address, query_header, query_body)
                    sock.sendto(self.create_dnsmsg(
                        query_header, query_body, ip_addr), self.client_address)


class DNSServer:
    def __init__(self, port=53, lib={}, debug_mode=0, dns_addr=''):
        DNSServer.lib = lib
        self.port = port
        DNSServer.debug_mode = debug_mode
        DNSServer.dns_addr = dns_addr
        self.server = ThreadingUDPServer((HOST_IP, self.port), DNSHandler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", action="store_true", help="Level-1")
    parser.add_argument("-dd", action="store_true", help="Level-2")
    parser.add_argument("--server_addr", type=str,
                        help="IP address of external DNS server", default="223.6.6.6")
    parser.add_argument("--config_path", type=str,
                        help="path of the configure file", default="./example.txt")
    FLAGS = parser.parse_args()

    lib, debug_mode, dns_addr = debugger_config(FLAGS)
    dnsServer = DNSServer(lib=lib, debug_mode=debug_mode, dns_addr=dns_addr)
    dnsServer.server.serve_forever()
