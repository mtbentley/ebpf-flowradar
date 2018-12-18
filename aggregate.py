#!/usr/bin/env python3
import sys
import json
import pprint
from cHash import c_hash
pp = pprint.PrettyPrinter(indent=4)

def parse_bloomfilter(bloomfilter):
    print('Tried to parse bloomfilter')
    pass

def csv_tuple_to_dict(csv):
    five_tuple = dict((a, b) for a,b in [x.split('=') for x in csv.split(',')])
    return five_tuple

def load_hosts(host_info):
    return json.loads(host_info)

fields = {'saddr', 'daddr', 'sport', 'dport', 'proto'}
def five_tuples_are_equal(flow1, flow2):
    flow1_d = json.loads(flow1)
    flow2_d = json.loads(flow2)

    for field in fields: 
        if flow1_d[field] != flow2_d[field]:
            # print(f'Flow1: {flow1_d} and {flow2_d} are different due to {field}')
            # print(f'Specificaly, their fields were {flow1_d[field]} and {flow2_d[field]}')
            return False
    # print('Flows were equal!')
    return True

def flow_seen_in_flow_set(flow, flows):
    for seen_flow in flows:
        if five_tuples_are_equal(flow, seen_flow):
            return True
    return False

def hex_flow_counts_to_integers(flow):
    to_modify = json.loads(flow)
    to_modify['packet_count'] = int(to_modify['packet_count'], 16)
    to_modify['flow_count'] = int(to_modify['flow_count'], 16)
    return json.dumps(to_modify)

def merge_flows(flow1, flow2):
    flow1_d = json.loads(flow1)
    flow2_d = json.loads(flow2)
    flow1_d['packet_count'] += flow2_d['packet_count']
    flow1_d['flow_count'] += flow2_d['flow_count']
    return json.dumps(flow1_d)

def merge_cpu_flows(cpu_flows):
    merged_flows = set()
    seen = set()
    for flow in cpu_flows:
        same_flows_different_cpus = set(filter(lambda f: flow_seen_in_flow_set(f, seen), cpu_flows.difference(flow)))
        merged_flow = f'{flow}'
        for matching_flow in same_flows_different_cpus:
            merged_flow = merge_flows(merged_flow, matching_flow)
            seen.add(matching_flow)

        if not flow_seen_in_flow_set(flow, seen):
            merged_flows.add(merged_flow)
            seen.add(flow)
    return merged_flows


def singledecode(flow_info, hosts):
    hash_count = 6
    cpus = 4
    all_cpus_identified_flows = set()
    for cpu in range(0, cpus):
        identified_flows = set()
        merged_flows = flow_info[str(cpu)]

        usable_flows = dict((hash_value, csv_tuple_to_dict(flow)) for hash_value, flow in merged_flows.items())
        for hash_value, flow in usable_flows.items():
            if flow['flow_count'] == '0x1':
                identified_flows.add(json.dumps(flow))
                packet_count = int(flow['packet_count'], 16)
                saddr, daddr = int(flow['saddr'], 16), int(flow['daddr'], 16)
                sport, dport = int(flow['sport'], 16), int(flow['dport'], 16)
                proto, host = int(flow['proto'], 16), int(hosts[cpu], 16)
                fields = {'saddr': saddr, 'daddr': daddr, 'sport': sport, 'dport': dport, 'proto': proto}
                hashes = [
                    c_hash(saddr, daddr, sport, dport, proto, host, k)
                    for k in range(0, hash_count)
                ]
                if not int(hash_value, 16)  in hashes:
                    print(f'The given hash WAS NOT in the calculated hashes.')
                for kth_hash in map(hex, hashes)
                    if usable_flows[kth_hash]:
                        for field, value in fields.items():
                            # A.CountTable[l].FlowXOR = CountTable[l].FlowXOR ⊕ flow;
                            usable_flows[kth_hash][field] = hex(int(usable_flows[kth_hash][field], 16) ^ value)
                        # A.CountTable[l].FlowCount -= 1;
                        usable_flows[kth_hash]['flow_count'] = hex(int(str(usable_flows[kth_hash]['flow_count']), 16) - 1)
                        # A.CountTable[l].PacketCount -= count;
                        usable_flows[kth_hash]['packet_count'] = hex(int(str(usable_flows[kth_hash]['packet_count']), 16) - packet_count)
                    else:
                        print('Hash not found in merged flow')
            elif flow['flow_count'] == '0x0':
                # Completed removing flow count from a bin, skip over this
                pass
            else:
                print(f'Conflict detected for flow={flow}')
        all_cpus_identified_flows |= identified_flows

    print('All CPUs flows:')
    cpu_flows_integers = set(map(hex_flow_counts_to_integers, all_cpus_identified_flows))
    pp.pprint(cpu_flows_integers)
    print('\nAll merged flows:\n')
    merged_flows = merge_cpu_flows(cpu_flows_integers)
    pp.pprint(merged_flows)




def parse_flow_info(flow_info, hosts):
    singledecode(flow_info, hosts)

def load_hosts(hosts):
    hosts = dict(
        (int(number), host['0x0'].split('=')[1])
        for number, host in hosts.items()
        )
    return hosts
        
     
def main(flowfile):
    flows = {}
    with open(flowfile, 'r') as f:
        flows = json.load(f)

    if not flows['bloomfilter'] or not flows['flow_info'] or not flows['host_info']:
        print('Bloom filter, host or flow info missing from dumped json')

    hosts = load_hosts(flows['host_info'])
    bloomfilter_summary = parse_bloomfilter(flows['bloomfilter'])
    flow_info_summary = parse_flow_info(flows['flow_info'], hosts)

if __name__ == '__main__':
    if len(sys.argv) < 2:
       print('usage: %s flow_data_file' % sys.argv[0])
       sys.exit(1)
    main(sys.argv[1])
    
