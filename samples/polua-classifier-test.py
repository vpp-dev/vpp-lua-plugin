# do this in the shell
# virtualenv/bin/pip install scapy
# sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH virtualenv/bin/scapy
# You also can do this from within scapy:
# execfile("polua-classifier-test.py")

# The rest is in the scapy CLI

import vpp_papi
v = vpp_papi

v.connect("pytest")

def cli(cmd):
  print("Running " + cmd)
  reply = vpp_papi.cli_inband(len(cmd), cmd)
  print("Reply: ", reply)
  return reply


import re
import binascii

def pad_to_vector(s):
  ls = len(s)
  lsp = ls - ls%16 + 16
  return s + (chr(0)*(lsp-ls))



# Full mask for matching on ICMP protocol for IPv4
ipv4_proto_mask_spaces = "000000000000 000000000000 0000 00 00 0000 0000 0000 00 FF 0000 00000000 00000000  00 00 0000 00 00"
# Full value for this match
ipv4_proto_valu_spaces = "000000000000 000000000000 0000 00 00 0000 0000 0000 00 01 0000 00000000 00000000  00 00 0000 00 00"

ipv4_proto_dport_mask_spaces = "000000000000 000000000000 0000 00 00 0000 0000 0000 00 FF 0000 00000000 00000000  0000 FFFF 00000000 00000000 0000 0000 0000 0000"
ipv4_proto_dport_valu_spaces = "000000000000 000000000000 0000 00 00 0000 0000 0000 00 06 0000 00000000 00000000  0000 0016 00000000 00000000 0000 0000 0000 0000"

ipv6_proto_mask_spaces = "000000000000 000000000000 0000 0 00 00000 0000 FF 00 00000000000000000000000000000000 00000000000000000000000000000000 00 00 0000 0000"
ipv6_proto_valu_spaces = "000000000000 000000000000 0000 0 00 00000 0000 3A 00 00000000000000000000000000000000 00000000000000000000000000000000 00 00 0000 0000"

ipv6_proto_dport_mask_spaces = "000000000000 000000000000 0000 0 00 00000 0000 FF 00 00000000000000000000000000000000 00000000000000000000000000000000 0000 FFFF 00000000 00000000 0000 0000 0000 0000"
ipv6_proto_dport_valu_spaces = "000000000000 000000000000 0000 0 00 00000 0000 06 00 00000000000000000000000000000000 00000000000000000000000000000000 0000 0016 00000000 00000000 0000 0000 0000 0000"


# Array of unprocessed masks and values
masks_spaces = [ ipv4_proto_mask_spaces, ipv4_proto_dport_mask_spaces, ipv6_proto_mask_spaces, ipv6_proto_dport_mask_spaces ]
valus_spaces = [ ipv4_proto_valu_spaces, ipv4_proto_dport_valu_spaces, ipv6_proto_valu_spaces, ipv6_proto_dport_valu_spaces ]

# Remove spaces
masks = map(lambda obj: obj.replace(" ",""), masks_spaces)

# Convert from hex representation to binary
masks_bin = map(lambda obj: binascii.unhexlify(obj), masks)

# Pad the masks to overall vector length
masks_bin_padded = map(pad_to_vector, masks_bin)

# Create naive tables
### tables = map(lambda s: v.classify_add_del_table(True, 0, 32, 20000, 0, len(s)/16, 4294967295, 4294967295, s), masks_bin_padded)

# check the result
cli("show classify tables")

## Now let's get rid of trying to match on the leading empty vectors - there is no point in doing that

# tell how many vectors are all-zero in the beginning of s
def n_leading_empty_vectors(s):
  hs = re.sub("[^\x00].+$","", s)
  lhs = len(hs)
  vlhs = (lhs - (lhs%16))/16
  return vlhs

# return s without the nv starting vectors
def strip_leading_vectors(s, nv):
  ts = s[16*nv:]
  return ts

### tables2 = map(lambda s : v.classify_add_del_table(True, 0, 32, 20000, n_leading_empty_vectors(s), len(s)/16 - n_leading_empty_vectors(s), 4294967295, 4294967295, strip_leading_vectors(s, n_leading_empty_vectors(s))), masks_bin_padded)

# Get rid of unnecessary zeroes in the end
def strip_trailing_zeroes(s):
  return re.sub("[\x00]+$", "", s)

# create binary masks with no trailing zeroes
masks_bin_notrailzero = map(strip_trailing_zeroes, masks_bin)

# pad them to vector lengths
masks_bin_notrailzero_padded = map(pad_to_vector, masks_bin_notrailzero)

# Create the good tables

### tables3 = map(lambda s: v.classify_add_del_table(True, 0, 32, 20000, n_leading_empty_vectors(s), len(s)/16 - n_leading_empty_vectors(s), 4294967295, 4294967295, strip_leading_vectors(s, n_leading_empty_vectors(s))), masks_bin_notrailzero_padded)

# The tables above are good, but we need to link them and define the default action being deny


#
# the next action is the index of one of the next actions, as per "show vlib graph":
# 
# for this case it is 0..15:
# 
# l2-input-classify               error-drop [0]                 l2-rw
#                            ethernet-input-not-l2 [1]         l2-learn
#                                  ip4-input [2]             l2-input-vtr
#                                  ip6-input [3]               l2-input
#                                   li-hit [4]               l2-input-acl
#                             feature-bitmap-drop [5]          l2-flood
#                                  l2-output [6]           l2-input-classify
#                                  l2-flood [7]              arp-term-l2bd
#                                arp-term-l2bd [8]        l2-policer-classify
#                                   l2-fwd [9]
#                                   l2-rw [10]
#                                  l2-learn [11]
#                                l2-input-vtr [12]
#                                l2-input-acl [13]
#                            l2-policer-classify [14]
#                             l2-input-classify [15]

action_drop = 0
action_cont = 4294967295
action_acl_match = 4294967295

link_with_prev = [ False, True, False, True ]
miss_idx = [ action_drop, action_cont, action_drop, action_cont ]

final_tables = []
for i in range(0, len(masks_bin_notrailzero_padded)):
  s = masks_bin_notrailzero_padded[i]
  arg_nbuckets = 32
  arg_mem = 20000
  arg_skip = n_leading_empty_vectors(s)
  arg_match = len(s)/16 - n_leading_empty_vectors(s)
  arg_next = 4294967295
  if link_with_prev[i]:
    # the final_tables previous has been already added in the last iteration
    arg_next = final_tables[i-1].new_table_index
  arg_miss_idx = miss_idx[i]
  print("skip: ", arg_skip, " match: ", arg_match)
  final_tables.append(v.classify_add_del_table(True, 0, arg_nbuckets, arg_mem, arg_skip, arg_match, arg_next, arg_miss_idx, strip_leading_vectors(s, arg_skip)))


sessions = []
for i in range(0, len(masks_bin_notrailzero_padded)):
  a_valu_spaces = valus_spaces[i]
  a_valu = a_valu_spaces.replace(" ", "")
  a_valu_bin =  binascii.unhexlify(a_valu)
  a_valu_bin_notrailzero = strip_trailing_zeroes(a_valu_bin)
  a_valu_bin_notrailzero_padded = pad_to_vector(a_valu_bin_notrailzero)
  a_skip = n_leading_empty_vectors(masks_bin_notrailzero_padded[i])
  # classify_add_del_session(is_add, table_index, hit_next_index, opaque_index, advance, match, async=False)
  ###
  ### WRONG !!!  
  ### a_match = strip_leading_vectors(a_valu_bin_notrailzero_padded, a_skip)
  ### match needs to be packet contents "as is". 
  ### 
  a_match = a_valu_bin_notrailzero_padded
  # classify_add_del_session(is_add, table_index, hit_next_index, opaque_index, advance, match, async=False)
  sessions.append(v.classify_add_del_session(True, final_tables[i].new_table_index, action_acl_match, 42, 0, a_match))


# Let's now open some shell sessions to send the pings from

# First define a class for it
from subprocess import Popen, PIPE
import time

class ShellSession:
  def __init__(self, name):
    self.description = "Interactive shell session"
    self.name = name
    self.fname = "/tmp/session-" + name + "-output.txt"
    self.fw = open(self.fname, "wb")
    self.fr = open(self.fname, "r")
    self.p = Popen("/bin/bash",  stdin = PIPE, stdout = self.fw, stderr = self.fw, bufsize = 1)
  def write(self, data):
    self.p.stdin.write(data)
  def read(self):
    return self.fr.read()
  def close(self):
    self.fr.close()
    self.fw.close()
  def connect_with(self, other):
    this_end = self.name + "_" + other.name
    other_end =  other.name + "_" + self.name
    self.write("ip link add name " + this_end + " type veth peer name " + other_end + "\n")
    self.write("ip link set dev " + this_end + " up promisc on\n")
    other.write("echo $$\n")
    time.sleep(0.5)
    thepid = int(other.read())
    self.write("ip link set dev " + other_end + " up promisc on netns /proc/"+str(thepid)+"/ns/net\n")
    print("netns of " + other_end + " is /proc/"+str(thepid)+"/ns/net\n")
    time.sleep(0.3)



# Three sessions, first s0 in the same net namespace as VPP
s0 = ShellSession("s0")

# s1 in its separate namespace and s2 in yet another one

s1 = ShellSession("s1")
# jump into a separate network namespace. 
s1.write("unshare -n /bin/bash\n")

# check we have no interfaces other than lo
s1.write("/sbin/ifconfig -a\n")
# wait a second or two here because otherwise there is no output
time.sleep(1)
s1.read()


s2 = ShellSession("s2")
# jump into a separate network namespace. 
s2.write("unshare -n /bin/bash\n")

# check we have no interfaces other than lo
s2.write("/sbin/ifconfig -a\n")
# wait a second or two here because otherwise there is no output
time.sleep(1)
s2.read()


# Connect the sessions using the veth pairs
s0.connect_with(s1)
s0.connect_with(s2)

# we now should have lo and s1_s0 interfaces here
s1.write("/sbin/ifconfig -a\n")
# wait a second or two here because otherwise there is no output
time.sleep(1)
print(s1.read())

# we now should have s0_s1 and s0_s2 interfaces here
s0.write("/sbin/ifconfig -a\n")
# wait a second or two here because otherwise there is no output
time.sleep(1)
s0.read()

# Now let's go back to our two sessions, s1 and s2 and configure them

# the s1 gets the address x::1
s1.write("ip -6 addr add dev s1_s0 2001:db8:1::1/64\n")
s1.write("ip -4 addr add dev s1_s0 192.0.2.1/24\n")
s1.write("ip link set dev s1_s0 up promisc on\n")

# the s2 gets the x::2 and x::3
s2.write("ip -6 addr add dev s2_s0 2001:db8:1::2/64\n")
s2.write("ip -6 addr add dev s2_s0 2001:db8:1::3/64\n")
s2.write("ip -4 addr add dev s2_s0 192.0.2.2/24\n")
s2.write("ip link set dev s2_s0 up promisc on\n")


# check the addresses
s1.write("ip addr\n")
s2.write("ip addr\n")
time.sleep(1)
s1.read()
s2.read()



# create the VPP interfaces via CLI and add them to the bridge

cli("create host-interface name s0_s1")
cli("create host-interface name s0_s2")
cli("set interface state host-s0_s1 up")
cli("set interface state host-s0_s2 up")
cli("set interface l2 bridge host-s0_s1 42")
cli("set interface l2 bridge host-s0_s2 42")

if False:
  # create the interfaces on the VPP corresponding to the s0_s1 and s0_s2 interfaces
  vpp_if_to_s1 = v.af_packet_create("s0_s1", "AAAAAA", True)
  vpp_if_to_s2 = v.af_packet_create("s0_s2", "AAAAAA", True)

  ifaces = [ vpp_if_to_s1, vpp_if_to_s2 ]

  # bring the interfaces up
  for i in ifaces:
    up = True
    v.sw_interface_set_flags(i.sw_if_index, up, False, False)

  # Let's add the bridge
  bd_id = 42
  v.bridge_domain_add_del(bd_id, True, True, True, True, 0, True)

  # Now lets add the interfaces to the bridge
  for i in ifaces:
    sw_if_index = i.sw_if_index
    v.sw_interface_set_l2_bridge(sw_if_index, bd_id, False, False, True)

# ping!
s1.write("ping6 -c 3 2001:db8:1::2\n")
s1.write("ping -c 3 192.0.2.2\n")

# wait for a while here
time.sleep(10)
s1.read()
# the ping must succeed

# Now let's apply the policy outbound on s2
# classify_set_interface_l2_tables(sw_if_index, ip4_table_index, ip6_table_index, other_table_index, is_input, async=False)

# remember those tables ?
ip4_table_index = final_tables[1].new_table_index
ip6_table_index = final_tables[3].new_table_index
minus_one = 4294967295


# classify table mask l3 ip6 proto buckets 64
# vl_api_classify_add_del_session_t_handler
# LUA:
# call classify add del session is_add 1 table_index 0 hit_next_index 5 opaque_index 42 match \x00\x00\x00\x00\x3A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
# call classify add del session is_add 1 table_index 0 hit_next_index 5 opaque_index 43 match \x00\x00\x00\x00\x3A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
# call classify add del session table_index 0 hit_next_index 5 opaque_index 43 match \x3A\x00\x00\x00\x3A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
# classify session hit-next 5 table-index 0 match l3 ip6 proto 58 opaque-index 42
# classify session del hit-next 5 table-index 0 match l3 ip6 proto 58 opaque-index 42
# classify session hit-next 5 table-index 2 match l3 ip6 proto 58 opaque-index 42
#  classify session hit-next 0 table-index 14 match l3 ip6 proto 58 opaque-index 123
# classify session hit-next -1 table-index 14 match l3 ip6 proto 58 opaque-index 123
# classify session hit-next 5 table-index 14 match l3 ip6 proto 58 opaque-index 123
# classify session del hit-next -1 table-index 14 match l3 ip6 proto 58 opaque-index 123
# classify session del hit-next 0 table-index 14 match l3 ip6 proto 58 opaque-index 123
# classify session del hit-next 5 table-index 14 match l3 ip6 proto 58 opaque-index 123

# v.classify_add_del_session(True, 14, 5, 123, 0, '\x00\x00\x00\x00:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
# v.classify_add_del_session(True, 1, 5, 123, 0, '\x00\x00\x00\x00:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
# v.classify_add_del_session(False, 14, 5, 123, 0, '\x00\x00\x00\x00:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

# Put egress policy onto target-facing interface
# v.classify_set_interface_l2_tables(vpp_if_to_s2.sw_if_index, ip4_table_index, ip6_table_index, minus_one, False)
# v.classify_set_interface_l2_tables(vpp_if_to_s1.sw_if_index, ip4_table_index, ip6_table_index, minus_one, True)
# classify session hit-next -1 table-index 2 match l3 ip6 proto 58 opaque-index 123

cli("lua run plugins/lua-plugin/samples/polua.lua")
cli("lua polua host-s0_s1 in permit")
cli("lua polua host-s0_s2 in")

testIPv6 = False
testIPv4 = True

if testIPv6:

  print("IPv6 ping with filter")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  s1.write("ping6 -c 3 2001:db8:1::2\n")
  time.sleep(10)
  cli("show trace max 1")
  time.sleep(1)

  print("IPv6 ping to another host with filter")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  s1.write("ping6 -c 3 2001:db8:1::3\n")
  time.sleep(10)
  cli("show trace max 1")
  time.sleep(1)

if testIPv4:
  print("IPv4 ping with filter")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  s1.write("ping -c 3 192.0.2.2\n")
  time.sleep(5)
  cli("show trace max 1")

  print("IPv4 udp with filter")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  s1.write("perl -e \"print('X' x 4000);\" >/tmp/test\n")
  s1.write("nc -u -w 1 192.0.2.2 4444 </tmp/test\n")
  time.sleep(5)
  cli("show trace max 1")

if True:
  print("IPv4 slow udp with filter")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  s1.write("perl -e \"print('X' x 100);\" >/tmp/test\n")
  s1.write("nc -u -w 1 -p 5554 192.0.2.2 4444 </tmp/test\n")
  time.sleep(1)
  s1.write("nc -u -w 1 -p 5554 192.0.2.2 4444 </tmp/test\n")
  time.sleep(5)
  cli("show trace max 1")

if True:
  print("IPv4 tcp port 3333 with filter")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  # s2.write("nc -w 4 -l -p 3333\n")
  s1.write("nc -w 1 192.0.2.2 3333 </dev/zero\n")
  time.sleep(5)
  cli("show trace max 1")

if True:
  print("IPv4 tcp port 3333 with filter in the other direction")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  # s2.write("nc -w 4 -l -p 3333\n")
  s1.write("nc -w 1 192.0.2.2 3333 </dev/zero\n")
  time.sleep(5)
  cli("show trace max 1")

if True:
  print("IPv4 tcp port 22 with filter")
  cli("clear trace")
  cli("trace add af-packet-input 100")
  s1.write("nc -w 1 192.0.2.2 22 </dev/zero\n")
  time.sleep(5)
  cli("show trace max 1")
  time.sleep(1)


# cancel the filters
# v.classify_set_interface_l2_tables(vpp_if_to_s2.sw_if_index, minus_one, minus_one, minus_one, False)
# v.classify_set_interface_l2_tables(vpp_if_to_s1.sw_if_index, minus_one, minus_one, minus_one, True)

# 
# Not supported yet in python API...
# >>> v.classify_session_dump(15)
# Message decode failed 322 <function classify_session_details_decode at 0x7fd41b84e758>
# Traceback (most recent call last):
#   File "/home/ubuntu/vpp/virtualenv/local/lib/python2.7/site-packages/vpp_papi-1.2-py2.7-linux-x86_64.egg/vpp_papi/vpp_papi.py", line 49, in msg_handler
#     r = api_func_table[id[0]](msg)
#   File "/home/ubuntu/vpp/virtualenv/local/lib/python2.7/site-packages/vpp_papi-1.2-py2.7-linux-x86_64.egg/vpp_papi/vpe.py", line 7653, in classify_session_details_decode
#    tr = unpack_from('>' + str(c) + 's', msg[30:])
# struct.error: unpack_from requires a buffer of at least 48 bytes
# []

