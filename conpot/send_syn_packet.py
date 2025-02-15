from scapy.all import *

# Dirección IP de Conpot (servidor S7Comm)
ip = "172.17.0.3"

# Puerto S7Comm (por defecto 10201)
port = 10201

# Crear un paquete TCP SYN
pkt = IP(dst=ip)/TCP(dport=port, flags="S")

# Enviar el paquete
send(pkt)
