from scapy.all import sniff, TCP

def mostrar_paquete(paquete):
    if paquete.haslayer(TCP):
        tcp_layer = paquete.getlayer(TCP)
        if tcp_layer.dport == 21 or tcp_layer.sport == 21:
            datos = bytes(tcp_layer.payload).decode('utf-8', errors='ignore')
            if "USER" in datos or "PASS" in datos:
                print(f"Paquete FTP Capturado: {paquete.summary()}")
                print(f"Datos: {datos.strip()}")

sniff(iface="eth0", prn=mostrar_paquete, filter="tcp port 21", store=0)
