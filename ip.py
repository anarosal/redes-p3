from socket import IPPROTO_ICMP, IPPROTO_TCP
from iputils import *
from ipaddress import ip_address, ip_network
import struct

from tcputils import str2addr

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0

    """
    20 bytes de header 
    IHL default = 5
    DSCP , ECN, Flags, frag_offset  = 0
    Tam = ipHeader + payload (segmento - pacote contendo o cabeço tcp + dados da aplicação)
    Identification = número tem que ser diferente para cada pacote ip 
    Ttl  = 64 (linux default) - matar pacotes perdidos para evitar overflow da rede
    Proto (o que tem dentro do payload) - valor 6 - assumindo que a camada superior seja o protocolo TCP
    Ip do remetente: self.meu_endereco = meu_endereco    
    Endereco_ip destino: argumento
    """
    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            ttl = ttl - 1
            proto = IPPROTO_TCP
            if (ttl == 0):
                proto = IPPROTO_ICMP  
                checksum = calc_checksum(struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:28])
                mensagem = struct.pack('!BBHI', 11, 0, checksum, 0) + datagrama[:28]              
                datagrama_corrigir = struct.pack('!BBHHHBBH', 69, 0, 20+len(mensagem), identification, flags+frag_offset, 64, proto, 0) + str2addr(self.meu_endereco) + str2addr(src_addr)
                checksum = calc_checksum(datagrama_corrigir)
                datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(mensagem), identification, flags+frag_offset, 64, proto, checksum) + str2addr(self.meu_endereco) + str2addr(src_addr) + mensagem
                next_hop = self._next_hop(self.meu_endereco)
            else:
                datagrama_corrigir = struct.pack('!BBHHHBBH', 69, 0, 20+len(payload), identification, flags+frag_offset, ttl, proto, 0) + str2addr(src_addr) + str2addr(dst_addr)
                checksum = calc_checksum(datagrama_corrigir)
                datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(payload), identification, flags+frag_offset, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dst_addr) + payload
            self.enlace.enviar(datagrama, next_hop)
    
    """
    Pega um endereço do tipo x.y.z.w e verifica se o endereço está contido no cidr
    cidr faixa de endereços ips
    """

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        next_hop = None
        maior_n = 0
        ip_dst = ip_address(dest_addr)
        for valor in self.tabela:
            ip_rede = ip_network(valor[0])
            n_atual = int(valor[0].split('/')[1])
            if (ip_dst in ip_rede and n_atual >= maior_n):
                next_hop = valor[1]
                maior_n = n_atual
        return next_hop
       

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia o segmento para dest_addr
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr = 69, 0, 20+len(segmento), self.id, 0, 64, 6, 0, self.meu_endereco
        datagrama_corrigir = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dest_addr)
        checksum = calc_checksum(datagrama_corrigir)
        datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dest_addr) + segmento
        self.enlace.enviar(datagrama, next_hop)
        """
        OBS: por algum motivo dá problema com ('!BBHHHBBHII'), já tentei de várias formas e não consegui arrumar, então resolvi tirar a parte inteira 'II' e concatenar
        """
    
