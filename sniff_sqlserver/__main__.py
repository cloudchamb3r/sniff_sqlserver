from scapy.all import * 
from scapy.layers.inet import IP
def sniff_main(dest_ip: str, port: int):
    local_ip = get_if_addr(conf.iface)

    def logger(pkt : Packet):
        
        if pkt.haslayer(IP):
            ip : IP = pkt[IP]
            src_ip = ip.src 
            dst_ip = ip.dst

            if src_ip == local_ip: src_ip = '<local>'
            if dst_ip == local_ip: dst_ip = '<local>'
        print(f'{src_ip} => {dst_ip}')
        hexdump(pkt)

    sniff(filter = 'tcp', prn = logger)
    ...

if __name__ == "__main__":
    import argparse
    from . import ascii_logo

    parser = argparse.ArgumentParser(
        description=ascii_logo, 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage= 'sniff_sqlserver <ip> [-p port] [-h]'
    )

    parser.add_argument(
        'ip' , 
        type = str, 
        help= 'SqlServer IPAddress to Sniff'
    )

    parser.add_argument(
        '-p', '--port',
        type = int,
        default = 1433, 
        help = 'SqlServer Port to Sniff (default: 1433)'
    )
    args = parser.parse_args()

    sniff_main(args.ip, args.port)
