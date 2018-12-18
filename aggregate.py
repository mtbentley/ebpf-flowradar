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

fields = {'saddr', 'daddr', 'sport', 'dport', 'proto'}
def five_tuples_are_equal(flow1, flow2):
    # print('Checking if 5 flows are equal;....')
    # print(flow1)
    # print(flow2)
    # print(type(flow1))
    # print(type(flow2))
    flow1_d = json.loads(flow1)
    flow2_d = json.loads(flow2)
    # print(f'Type of flow1 is {type(flow1_d)}')
    # print(f'Type of flow2 is {type(flow2_d)}')

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
    # print('Merging flows')
    # print(flow1)
    # print(flow2)
    # print(type(flow1))
    # print(type(flow2))
    flow1_d = json.loads(flow1)
    flow2_d = json.loads(flow2)
    # print(f'Type of flow1 is {type(flow1_d)}')
    # print(f'Type of flow2 is {type(flow2_d)}')
    flow1_d['packet_count'] += flow2_d['packet_count']
    flow1_d['flow_count'] += flow2_d['flow_count']
    return json.dumps(flow1_d)

def merge_cpu_flows(cpu_flows):
    merged_flows = set()
    seen = set()
    # print(list(map(type, cpu_flows_integers)))
    # print(f'cpu flows integers: {cpu_flows_integers}')
    i = 0
    i += 1
    for flow in cpu_flows:
        # print(f'Processing flow {i}\n\n')
        same_flows_different_cpus = set(filter(
                        lambda f: flow_seen_in_flow_set(f, seen),
                        cpu_flows.difference(flow)
                        ))
        # print("Generated same flows different cpus")
        # print(list(map(type, same_flows_different_cpus)))
        # print(f'Number of matching flows: {len(same_flows_different_cpus)}')
        merged_flow = f'{flow}'
        for matching_flow in same_flows_different_cpus:
            # print(f'Passing into merge flows: {type(merged_flow)} and {type(matching_flow)}')
            # print(f'With first: {merged_flow} and second: {matching_flow}')
            merged_flow = merge_flows(merged_flow, matching_flow)
            # print(f'Adding to seen: {matching_flow} with type {type(matching_flow)}')
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
        #print(f'Running for cpu={cpu}\n')
        identified_flows = set()
        merged_flows = flow_info[str(cpu)]

        usable_flows = dict((hash_value, csv_tuple_to_dict(flow)) for hash_value, flow in merged_flows.items())
        for hash_value, flow in usable_flows.items():
            #flow_data = csv_tuple_to_dict(flow)
            flow_data = flow
            if flow_data['flow_count'] == '0x1':
                given_hash_as_int = int(hash_value, 16)
                #print(f'Which has a hash value of: {given_hash_as_int}')
                # print(f'Which has a hash value of: {hex(given_hash_as_int)}') # hex version
                packet_count = int(flow_data['packet_count'], 16)
                identified_flows.add(json.dumps(flow_data))
                saddr = int(flow_data['saddr'], 16)
                daddr = int(flow_data['daddr'], 16)
                sport = int(flow_data['sport'], 16)
                dport = int(flow_data['dport'], 16)
                proto = int(flow_data['proto'], 16)
                host = int(hosts[cpu], 16)
                fields = {'saddr': saddr, 'daddr': daddr, 'sport': sport, 'dport': dport, 'proto': proto}
                #print(f'call to c_hash with: (saddr={saddr}, daddr={daddr}, sport={sport}, dport={dport}, proto={proto}, {host}')
                #print(f'call to c_hash with: (saddr={hex(saddr)}, daddr={hex(daddr)}, sport={hex(sport)}, dport={hex(dport)}, proto={hex(proto)}, {hex(host)}') # hex version
                hashes = [
                    c_hash(saddr, daddr, sport, dport, proto, host, k)
                    # hex(c_hash(saddr, daddr, sport, dport, proto, host, k)) # hex version
                    for k in range(0, hash_count)
                ]
                #print(f'The calculated five hashes for this were.....{hashes}')
                given_hash_in_calculated = given_hash_as_int in hashes
                # given_hash_in_calculated = hex(given_hash_as_int) in hashes # hex version
                if not given_hash_in_calculated:
                    print(f'The given hash WAS NOT in the calculated hashes.')
                hex_hashes = map(hex,hashes)
                for kth_hash in hex_hashes:
                    if usable_flows[kth_hash]:
                        for field, value in fields.items():
                            # For each field, since ours are split up
                            # A.CountTable[l].FlowXOR = CountTable[l].FlowXOR ⊕ flow;
                            usable_flows[kth_hash][field] = hex(int(usable_flows[kth_hash][field], 16) ^ value)

                        # A.CountTable[l].FlowCount -= 1;
                        usable_flows[kth_hash]['flow_count'] = hex(int(str(usable_flows[kth_hash]['flow_count']), 16) - 1)

                        # A.CountTable[l].PacketCount -= count;
                        usable_flows[kth_hash]['packet_count'] = hex(int(str(usable_flows[kth_hash]['packet_count']), 16) - packet_count)

                    else:
                        print('Hash not found in merged flow')
            elif flow_data['flow_count'] == '0x0':
                # Completed removing flow count from a bin
                pass
                #print(f'Completed removing flow count from a bin with id={kth_hash}')
            else:
                print(f'Conflict detected for flow={flow_data}')
        #pp.pprint(usable_flows)
        #pp.pprint(identified_flows)
        #print('\n')
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
    
