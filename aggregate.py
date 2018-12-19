#!/usr/bin/env python3
import sys
import json
import pprint
from cHash import c_hash

pp = pprint.PrettyPrinter(indent=4)
HASH_COUNT = 6


def csv_tuple_to_dict(csv):
    return dict((a, b) for a,b in [x.split('=') for x in csv.split(',')])

fields = {'saddr', 'daddr', 'sport', 'dport', 'proto'}
def five_tuples_are_equal(flow1, flow2):
    flow1_d, flow2_d = json.loads(flow1), json.loads(flow2)
    return all(flow1_d[field] == flow2_d[field] for field in fields)

def flow_seen_in_flow_set(flow, flows):
    return any(five_tuples_are_equal(flow, seen_flow) for seen_flow in flows)

def hex_flow_counts_to_integers(flow):
    to_modify = json.loads(flow)
    to_modify['packet_count'] = int(to_modify['packet_count'], 16)
    to_modify['flow_count'] = int(to_modify['flow_count'], 16)

    return json.dumps(to_modify)

def merge_flows(flow1, flow2):
    flow1_d, flow2_d = json.loads(flow1), json.loads(flow2)
    flow1_d['packet_count'] += flow2_d['packet_count']
    flow1_d['flow_count'] += flow2_d['flow_count']

    return json.dumps(flow1_d)

def merge_cpu_flows(cpu_flows):
    merged_flows = []
    for flow in cpu_flows:
        matching_flows = list(filter(lambda f: five_tuples_are_equal(f, flow), cpu_flows))
        matching_flows.remove(flow) # The current flow should not match itself
        merged_flow = f'{flow}'
        for matching_flow in matching_flows:
            merged_flow = merge_flows(merged_flow, matching_flow)
        merged_flows.append(merged_flow)

    return set(merged_flows) # Remove duplicate merged flows


def singledecode(flow_info, hosts):
    all_cpus_identified_flows = set()
    for cpu in flow_info.keys():
        identified_flows = set()
        merged_flows = flow_info[str(cpu)]
        usable_flows = {hash_value:  csv_tuple_to_dict(flow) for hash_value, flow in merged_flows.items()}

        for hash_value, flow in usable_flows.items():
            if flow['flow_count'] == '0x1':
                identified_flows.add(json.dumps(flow))
                packet_count = int(flow['packet_count'], 16)
                saddr, daddr = int(flow['saddr'], 16), int(flow['daddr'], 16)
                sport, dport = int(flow['sport'], 16), int(flow['dport'], 16)
                proto, host = int(flow['proto'], 16), int(hosts[int(cpu)], 16)
                fields = {'saddr': saddr, 'daddr': daddr, 'sport': sport, 'dport': dport, 'proto': proto}
                hashes = [
                    c_hash(saddr, daddr, sport, dport, proto, host, k)
                    for k in range(0, HASH_COUNT)
                ]
                print(f'Hashes were: {list(map(hex, hashes))}')
                if not int(hash_value, 16)  in hashes:
                    print(f'The given hash WAS NOT in the calculated hashes.')
                for kth_hash in map(hex, hashes):
                    if usable_flows[kth_hash]:
                        for field, value in fields.items():
                            usable_flows[kth_hash][field] = hex(int(usable_flows[kth_hash][field], 16) ^ value)

                        usable_flows[kth_hash]['flow_count'] = hex(int(str(usable_flows[kth_hash]['flow_count']), 16) - 1)
                        usable_flows[kth_hash]['packet_count'] = hex(int(str(usable_flows[kth_hash]['packet_count']), 16) - packet_count)
                    else:
                        print('Hash not found in merged flow')
            elif flow['flow_count'] == '0x0':
                # Completed removing flow count from a bin, skip over this
                pass
            else:
                # unresolvable conflict (within a CPU) detected
                # We should probably combine info from multiple CPUs here
                # Here we need to handle flows with conflicts
                # Probably repeat the loop with the remaining items?
                print(f'Conflict detected for flow={flow}')
        all_cpus_identified_flows |= identified_flows

    print('All CPUs flows:')
    cpu_flows_integers = list(map(hex_flow_counts_to_integers, all_cpus_identified_flows))
    pp.pprint(cpu_flows_integers)
    print('\nAll merged flows:')
    merged_flows = merge_cpu_flows(cpu_flows_integers)
    pp.pprint(merged_flows)


def parse_flow_info(flow_info, hosts):
    singledecode(flow_info, hosts)

def load_hosts(hosts):
    return dict((int(number), host['0x0'].split('=')[1]) for number, host in hosts.items())
        
def parse_bloomfilter(bloomfilter):
    print('Tried to parse bloomfilter')
    pass

def main(flowfile, outfile):
    flows = {}
    with open(flowfile, 'r') as f:
        flows = json.load(f)

    if not flows['bloomfilter'] or not flows['flow_info'] or not flows['host_info']:
        print('Bloom filter, host or flow info missing from dumped json')

    # bloomfilter_summary = parse_bloomfilter(flows['bloomfilter'])
    hosts = load_hosts(flows['host_info'])
    parse_flow_info(flows['flow_info'], hosts)

    # Write output in useful format to outfile

if __name__ == '__main__':
    if len(sys.argv) < 2:
       print('usage: %s flow_data_file' % sys.argv[0])
       sys.exit(1)
    main(sys.argv[1], sys.argv[2])
