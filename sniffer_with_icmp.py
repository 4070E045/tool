import socket
import os 
import struct
from ctypes import*

host ="192.168.0.187"

class IP(Structure):
  _fields_ = [
    ("ih1",          c_ubytes, 4),
    ("version",      c_ubytes, 4),
    ("tos",          c_ubyte),
    ("len",          c_ushort),
    ("id",           c_ushort),
    ("offset",       c_ushort),
    ("ttl",          c_ubyte),
    ("protocol_num", c_ubyte),
    ("sum",          c_ushort),
    ("src",          c_ulang),  
    ("dst",          c_ulang)
  ]

  def_new_(self, socket_buffer=None):
    return self.from_buffer_copy(socket_buffer)
  
  def_init_(self, socket_buffer=None):
    self, protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
    self.src_address = socket.inet_ntoa(strust.pack("<L",self.src))
    self.dst_address = socket.inet_ntoa(strust.pack("<L",self.dst))
    try:
      self, protocol = self.protocol_map[self.protocol_num]
    except:
      self, protocol = str(self.protocol_num)
  if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
  else:
    socket_protocol = socket.IPPROTO_ICMP
  sniffer = socket.socket(socket.AF_INET, socketSOCK_RAW, socket_protocol)
  sniffer.bind((host,0))
  sinffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
  if os.name =="nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
  try:
    while True:
      raw_buffer = sniffer sniffer.recvfrom(65565)[0]
      ip_header = IP(raw_buffer[0:20])
      print "protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
  except:
    if os.name == "nt":
      sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
class ICMP(Structure):   
 _fields_=[
  ("type",                c_ubyte),
  ("code",                c_ubyte),
  ("checksum",            c_ushort),
  ("unused",              c_ushort),
  ("next_hop_mtu",        c_ushort),
  ]
def_new_(self, socket_buffer):
  return self.from_buffer_copy(socket_buffer)
def_init_(self, socket_buffer=None):
  self, protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
  self.src_address = socket.inet_ntoa(strust.pack("<L",self.src))
  self.dst_address = socket.inet_ntoa(strust.pack("<L",self.dst))
  try:
    self, protocol = self.protocol_map[self.protocol_num]
  except:
    self, protocol = str(self.protocol_num)
