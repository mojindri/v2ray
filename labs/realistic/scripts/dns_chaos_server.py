#!/usr/bin/env python3
import argparse, json, socket, struct, time
from pathlib import Path

TYPE_A=1; TYPE_AAAA=28; CLASS_IN=1
RCODE_NOERROR=0; RCODE_NXDOMAIN=3; RCODE_SERVFAIL=2

def parse_qname(data, off):
    labels=[]
    while True:
        ln=data[off]; off+=1
        if ln==0: break
        labels.append(data[off:off+ln].decode(errors='ignore')); off+=ln
    return '.'.join(labels).lower(), off

def encode_name(name):
    out=b''
    for part in name.rstrip('.').split('.'):
        b=part.encode(); out += bytes([len(b)]) + b
    return out+b'\x00'

def rr(name, typ, value, ttl=30):
    rdata = socket.inet_aton(value) if typ==TYPE_A else socket.inet_pton(socket.AF_INET6, value)
    return encode_name(name)+struct.pack('!HHIH', typ, CLASS_IN, ttl, len(rdata))+rdata

def response(data, zones, logf):
    tid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
    qname, off = parse_qname(data, 12)
    qtype, qclass = struct.unpack('!HH', data[off:off+4])
    question=data[12:off+4]
    rule=zones.get(qname, {"type":"A", "value":"198.51.100.99"})
    if rule.get('delay_ms'): time.sleep(rule['delay_ms']/1000.0)
    rtype=rule.get('type','A').upper()
    if rtype=='NXDOMAIN': rcode=RCODE_NXDOMAIN; answers=b''
    elif rtype=='SERVFAIL': rcode=RCODE_SERVFAIL; answers=b''
    elif rtype=='AAAA' and qtype in (TYPE_AAAA, 255): rcode=RCODE_NOERROR; answers=rr(qname, TYPE_AAAA, rule['value'])
    elif rtype=='A' and qtype in (TYPE_A, 255): rcode=RCODE_NOERROR; answers=rr(qname, TYPE_A, rule['value'])
    else: rcode=RCODE_NOERROR; answers=b''
    flags_out=0x8000 | 0x0400 | 0x0080 | rcode
    hdr=struct.pack('!HHHHHH', tid, flags_out, 1, 1 if answers else 0, 0, 0)
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {qname} qtype={qtype} -> {rtype} rcode={rcode}", file=logf, flush=True)
    return hdr+question+answers

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=15353)
    ap.add_argument('--zones', default='configs/dns/dns-chaos-zones.json')
    ap.add_argument('--log', default='reports/production/dns-chaos.log')
    args=ap.parse_args()
    zones=json.loads(Path(args.zones).read_text()) if Path(args.zones).exists() else {}
    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    with open(args.log, 'a') as logf:
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((args.host,args.port))
        print(f"dns chaos listening on {args.host}:{args.port}", flush=True)
        while True:
            data, addr=sock.recvfrom(4096)
            try: sock.sendto(response(data,zones,logf), addr)
            except Exception as e: print(f"error: {e}", file=logf, flush=True)
if __name__=='__main__': main()
