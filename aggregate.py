#!/usr/bin/env python3
import sys
import json
import pprint
pp = pprint.PrettyPrinter(indent=4)

def parse_bloomfilter(bloomfilter):
    #pp.pprint(bloomfilter)
    pass

def csv_tuple_to_dict(csv):
    five_tuple = dict((a, int(b,16)) for a,b in [x.split('=') for x in csv.split(',')])
    return five_tuple

def singledecode(flow_info):
    cpu = '0' # temp for testing
    flows = flow_info[cpu]
    for _, flow in flows.items():
        flow_data = csv_tuple_to_dict(flow)
        if int(flow_data['flow_count']) == 1:
            print(f'No conflict  detected for flow={flow_data}')
        else:
            print(f'Conflict detected for flow={flow_data}')
        for key in flow_data.items():
            pass

def parse_flow_info(flow_info):
    # for cpu in flow_info:
    #    for  
    singledecode(flow_info)
    #pp.pprint(flow_info)
    #pass
     

def main(flowfile, outfile):
    values = []
    flows = {}
    with open(flowfile, 'r') as f:
        flows = json.load(f)

    if not flows['bloomfilter'] or not flows['flow_info']:
        print('Bloom filter or flow info missing from dumped json')

    bloomfilter_summary = parse_bloomfilter(flows['bloomfilter'])
    flow_info_summary = parse_flow_info(flows['flow_info'])

    #pp.pprint(flows)

if __name__ == '__main__':
    if len(sys.argv) < 3:
       print('usage: %s flowdatafile outfile' % sys.argv[0])
       sys.exit(1)
    main(sys.argv[1], sys.argv[2])
