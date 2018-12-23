# A simple DNS server
This is a simple dns server implemented with python



## Functions
This DNS server takes a domain name as input and sends back an IP address as return according to that domain name. 

If the IP address of the domain name has been already recorded in the local database of the DNS server, it will send back the IP address directly.

If not, this DNS server will turn to the external DNS server for help and then sends back the IP address.

## Environment
OS: macOS Mojave 10.14

Python 3.6.2

Packages: dnspython, socketserver

## Usage
To run this DNS server, simply input the following code in the shell:

    sudo python dnsrelay[-d|-dd] [--server_addr] [--config_path]

-d(optional): Print the query domain name and its IP address to the DNS server's shell.

-dd(optional): Print more information( part of DNS message, IP address and port of DNS server, ... ) to the DNS server's shell.

--server_addr(optional): Use specified DNS server as the external server.

--config_path(optional): Use specified file to configure the DNS server's database.

## Demos
![](https://github.com/hangyhan/dns_server/blob/master/Xnip2018-12-23_21-18-28.jpg)
![](https://github.com/hangyhan/dns_server/blob/master/Xnip2018-12-23_21-18-56.jpg)
