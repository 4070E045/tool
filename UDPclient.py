import socket
target_host="IP"
target_port=80

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.sendto("AAABBBCCC",(target_host,target_port))
data, addr = client.recvform(4096
print data
