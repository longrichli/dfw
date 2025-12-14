#!/bin/bash
/opt/env/dpdk24.11/bin/dpdk-hugepages.py --clear
/opt/env/dpdk24.11/bin/dpdk-hugepages.py -p 2M -r 1G
/opt/env/dpdk24.11/bin/dpdk-hugepages.py --show
