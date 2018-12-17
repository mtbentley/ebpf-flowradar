#!/usr/bin/env python3
import sys
import json
import pprint
from cHash import c_hash
pp = pprint.PrettyPrinter(indent=4)

def parse_bloomfilter(bloomfilter):
    print('Tried to parse bloomfilter')
    #pp.pprint(bloomfilter)
    pass

def csv_tuple_to_dict(csv):
    five_tuple = dict((a, b) for a,b in [x.split('=') for x in csv.split(',')])
    return five_tuple

def load_hosts(host_info):
    return json.loads(host_info)

def singledecode(flow_info, hosts):
    hash_count = 5
    for cpu in range(0,3):
        print(f'Running for cpu={cpu}\n')
        identified_flows = set()
        merged_flows = flow_info[str(cpu)]
        for hash_value, flow in merged_flows.items():
            flow_data = csv_tuple_to_dict(flow)
            if flow_data['flow_count'] == '0x1':
                given_hash_as_int = int(hash_value, 16)
                #print(f'Which has a hash value of: {given_hash_as_int}')
                print(f'Which has a hash value of: {hex(given_hash_as_int)}')
                identified_flows.add(json.dumps(flow_data))
                saddr = int(flow_data['saddr'], 16)
                daddr = int(flow_data['daddr'], 16)
                sport = int(flow_data['sport'], 16)
                dport = int(flow_data['dport'], 16)
                proto = int(flow_data['proto'], 16)
                host = int(hosts[cpu], 16)
                #print(f'call to c_hash with: (saddr={saddr}, daddr={daddr}, sport={sport}, dport={dport}, proto={proto}, {host}')
                print(f'call to c_hash with: (saddr={hex(saddr)}, daddr={hex(daddr)}, sport={hex(sport)}, dport={hex(dport)}, proto={hex(proto)}, {hex(host)}')
                hashes = [
                    hex(c_hash(saddr, daddr, sport, dport, proto, host, k))
                    for k in range(0, hash_count+1)
                ]
                print(f'The calculated five hashes for this were.....{hashes}')
                given_hash_in_calculated = given_hash_as_int in hashes
                given_hash_in_calculated = hex(given_hash_as_int) in hashes
                if given_hash_in_calculated:
                    print(f'The given hash was in the calculated hashes.')
                else:
                    print(f'The given hash WAS NOT in the calculated hashes.')
                print('\n')
                for kth_hash in hashes:
                    merged_flows
                    


                       # A.CountTable[l].FlowXOR = CountTable[l].FlowXOR ⊕ flow;
                       # A.CountTable[l].FlowCount -= 1;
                       # A.CountTable[l].PacketCount -= count;
            else:
                print(f'Conflict detected for flow={flow_data}')

def parse_flow_info(flow_info, hosts):
    # for cpu in flow_info:
    #    for  
    print("About to singledecode")
    singledecode(flow_info, hosts)
    #pp.pprint(flow_info)
    #pass

def load_hosts(hosts):
    hosts = dict(
        (int(number), host['0x0'].split('=')[1])
        for number, host in hosts.items()
        )
    return hosts
        
     

def main(flowfile, outfile):
    values = []
    flows = {}
    with open(flowfile, 'r') as f:
        flows = json.load(f)

    if not flows['bloomfilter'] or not flows['flow_info']:
        print('Bloom filter or flow info missing from dumped json')

    hosts = load_hosts(flows['host_info'])
    print(hosts)
    bloomfilter_summary = parse_bloomfilter(flows['bloomfilter'])
    flow_info_summary = parse_flow_info(flows['flow_info'], hosts)

    #pp.pprint(flows)

if __name__ == '__main__':
    if len(sys.argv) < 3:
       print('usage: %s flowdatafile outfile' % sys.argv[0])
       sys.exit(1)
    main(sys.argv[1], sys.argv[2])
    
