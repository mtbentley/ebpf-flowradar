#!/usr/bin/env python3
import sys
import numpy as np
import matplotlib.mlab as mlab
import matplotlib.pyplot as plt


def main(hash_file, outfile):
    values = []
    with open(hash_file, 'r') as f:
        for line in f:
            values.append(int(line.strip(), 16))

    num_bins = 50
    n, bins, patches = plt.hist(values, num_bins, facecolor='blue', alpha=0.5)
    plt.savefig(outfile)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("usage: %s infile outfile" % sys.argv[0])
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
