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

        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        (
            codePoint,
            ecn,
            identificacao,
            flags,
            deslocamento,
            ttl,
            proto,
            endFonte,
            endDestino,
            dadosCarregados,
        ) = read_ipv4_header(datagrama)

        if endDestino != self.meu_endereco:
            # atua como roteador
            next_hop = self._next_hop(endDestino)

            # Decrementar TTL
            (
                codePoint,
                ecn,
                identificacao,
                flags,
                deslocamento,
                ttl,
                proto,
                endFonte,
                endDestino,
                dadosCarregados,
            ) = read_ipv4_header(datagrama)

            if ttl == 1:
                self._icmp_time_limit_exceeded(datagrama, endFonte)
                return
            else:
                ttl -= 1

            # Regerando o cabeçalho.
            hdr = (
                struct.pack(
                    "!BBHHHBBH",
                    0x45,
                    codePoint | ecn,
                    20 + len(dadosCarregados),
                    identificacao,
                    (flags << 13) | deslocamento,
                    ttl,
                    proto,
                    0,
                )
                + str2addr(endFonte)
                + str2addr(endDestino)
            )

            # Ajustando o checksum
            checksum = calc_checksum(hdr)

            hdr = (
                struct.pack(
                    "!BBHHHBBH",
                    0x45,
                    codePoint | ecn,
                    20 + len(dadosCarregados),
                    identificacao,
                    (flags << 13) | deslocamento,
                    ttl,
                    proto,
                    checksum,
                )
                + str2addr(endFonte)
                + str2addr(endDestino)
            )

            datagrama = hdr + dadosCarregados

            self.enlace.enviar(datagrama, next_hop)
        else:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(endFonte, endDestino, dadosCarregados)

    def _next_hop(self, dest_addr):

        enderecoAnteriorEncontrado = {"bits": -1, "next_hop": None}

        for cidr, next_hop in self.tabela:
            bitsIgnorados = self._addr_match(cidr, dest_addr)
            if bitsIgnorados > enderecoAnteriorEncontrado["bits"]:
                enderecoAnteriorEncontrado["bits"] = bitsIgnorados
                enderecoAnteriorEncontrado["next_hop"] = next_hop

        return enderecoAnteriorEncontrado["next_hop"]

    def _addr_match(self, cidr, addr):
        cidr_base, no_matching_bits = cidr.split("/", 1)

        # Converter os para bit strings.
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

        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):

        self.tabela = tabela

    def registrar_recebedor(self, callback):

        self.callback = callback

    def enviar(self, segmento, dest_addr, proto=IPPROTO_TCP):

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
