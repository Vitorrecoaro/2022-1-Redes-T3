# 2022 - 1 - UFSCar - Departamento de Computação..
# Trabalho de Redes 2 - Camada de transporte TCP.
# Alunos:.
# Bruno Leandro Pereira - RA: 791067.
# Bruno Luis Rodrigues Medri - RA: 790004.
# Thiago Roberto Albino - RA: 790034.
# Vitor de Almeida Recoaro - RA: 790035.

from iputils import *


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
        self.tabela = []

    def __raw_recv(self, datagrama):
        (
            dscp,
            ecn,
            identificacao,
            flags,
            frag_offset,
            ttl,
            proto,
            endFonte,
            endDestino,
            payload,
        ) = read_ipv4_header(datagrama)
        if endDestino == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(endFonte, endDestino, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(endDestino)

            # Recuperando cabeçalho para decrementar TTL
            (
                dscp,
                ecn,
                identificacao,
                flags,
                frag_offset,
                ttl,
                proto,
                endFonte,
                endDestino,
                payload,
            ) = read_ipv4_header(datagrama)

            if ttl == 1:
                self._icmp_time_limit_exceeded(datagrama, endFonte)
                return  # Descartando datagrama
            else:
                ttl -= 1

            # Refazendo cabeçalho com ttl decrementado
            hdr = (
                struct.pack(
                    "!BBHHHBBH",
                    0x45,
                    dscp | ecn,
                    20 + len(payload),
                    identificacao,
                    (flags << 13) | frag_offset,
                    ttl,
                    proto,
                    0,
                )
                + str2addr(endFonte)
                + str2addr(endDestino)
            )

            # Corrigindo checksum
            checksum = calc_checksum(hdr)

            hdr = (
                struct.pack(
                    "!BBHHHBBH",
                    0x45,
                    dscp | ecn,
                    20 + len(payload),
                    identificacao,
                    (flags << 13) | frag_offset,
                    ttl,
                    proto,
                    checksum,
                )
                + str2addr(endFonte)
                + str2addr(endDestino)
            )

            datagrama = hdr + payload

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):

        enderecoAnteriorEncontrado = {"bits": -1, "next_hop": None}

        for cidr, next_hop in self.tabela:
            bitsIgnorados = self._addr_match(cidr, dest_addr)
            if bitsIgnorados > enderecoAnteriorEncontrado["bits"]:
                enderecoAnteriorEncontrado["bits"] = bitsIgnorados
                enderecoAnteriorEncontrado["next_hop"] = next_hop

        return enderecoAnteriorEncontrado["next_hop"]

    def _addr_match(self, cidr, addr):
        # Recortando os valores
        cidr_base, no_matching_bits = cidr.split("/", 1)

        # Convertendo para inteiros e string de bits
        no_matching_bits = int(no_matching_bits)
        cidr_base = addr2bitstring(cidr_base)
        addr = addr2bitstring(addr)

        if cidr_base[:no_matching_bits] == addr[:no_matching_bits]:
            return no_matching_bits
        else:
            return -1

    def _icmp_time_limit_exceeded(self, datagrama, dst_addr):
        payload = struct.pack("!BBHI", 11, 0, 0, 0) + datagrama[:28]
        checksum = calc_checksum(payload)
        payload = struct.pack("!BBHI", 11, 0, checksum, 0) + datagrama[:28]

        self.enviar(payload, dst_addr, IPPROTO_ICMP)

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, proto=IPPROTO_TCP):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """

        next_hop = self._next_hop(dest_addr)

        # Gerando cabeçalho.
        identificacao = 0
        flags = (0 << 13) | 0
        vihl = (4 << 4) | 5
        dscpecn = 0 | 0
        tamTotal = 20 + len(segmento)
        ttl = 64

        hdr = (
            struct.pack(
                "!BBHHHBBH",
                vihl,
                dscpecn,
                tamTotal,
                identificacao,
                flags,
                ttl,
                proto,
                0,
            )
            + str2addr(self.meu_endereco)
            + str2addr(dest_addr)
        )

        # Adequando o checksum.
        checksum = calc_checksum(hdr)
        hdr = (
            struct.pack(
                "!BBHHHBBH",
                vihl,
                dscpecn,
                tamTotal,
                identificacao,
                flags,
                ttl,
                proto,
                checksum,
            )
            + str2addr(self.meu_endereco)
            + str2addr(dest_addr)
        )

        datagrama = hdr + segmento
        self.enlace.enviar(datagrama, next_hop)


def addr2bitstring(addr):
    vetor = list(int(x) for x in addr.split("."))
    enderecoFormatado = ""

    for endereco in vetor:
        enderecoFormatado += "{0:08b}".format(endereco)

    return enderecoFormatado
