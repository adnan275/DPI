import struct
from typing import Optional


class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @staticmethod
    def _read_u16be(data: bytes, offset: int) -> int:
        return (data[offset] << 8) | data[offset + 1]

    @staticmethod
    def _read_u24be(data: bytes, offset: int) -> int:
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

    @staticmethod
    def is_tls_client_hello(payload: bytes, length: int) -> bool:
        if length < 9:
            return False
        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False
        version = SNIExtractor._read_u16be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
        record_length = SNIExtractor._read_u16be(payload, 3)
        if record_length > length - 5:
            return False
        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload, length):
            return None

        offset = 5
        if offset + 4 > length:
            return None
        offset += 4
        offset += 2
        offset += 32

        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length

        if offset + 2 > length:
            return None
        cipher_suites_length = SNIExtractor._read_u16be(payload, offset)
        offset += 2 + cipher_suites_length

        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        if offset + 2 > length:
            return None
        extensions_length = SNIExtractor._read_u16be(payload, offset)
        offset += 2

        extensions_end = min(offset + extensions_length, length)

        while offset + 4 <= extensions_end:
            ext_type = SNIExtractor._read_u16be(payload, offset)
            ext_length = SNIExtractor._read_u16be(payload, offset + 2)
            offset += 4

            if offset + ext_length > extensions_end:
                break

            if ext_type == SNIExtractor.EXTENSION_SNI:
                if ext_length < 5:
                    break
                sni_list_length = SNIExtractor._read_u16be(payload, offset)
                if sni_list_length < 3:
                    break
                sni_type = payload[offset + 2]
                sni_length = SNIExtractor._read_u16be(payload, offset + 3)
                if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME:
                    break
                if sni_length > ext_length - 5:
                    break
                return payload[offset + 5: offset + 5 + sni_length].decode("ascii", errors="replace")

            offset += ext_length

        return None


class HTTPHostExtractor:
    HTTP_METHODS = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI"]

    @staticmethod
    def is_http_request(payload: bytes, length: int) -> bool:
        if length < 4:
            return False
        prefix = payload[:4]
        return any(prefix == m for m in HTTPHostExtractor.HTTP_METHODS)

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not HTTPHostExtractor.is_http_request(payload, length):
            return None

        i = 0
        while i + 5 < length:
            if (payload[i:i+4].lower() == b"host") and payload[i + 4] == ord(":"):
                start = i + 5
                while start < length and payload[start] in (ord(" "), ord("\t")):
                    start += 1
                end = start
                while end < length and payload[end] not in (ord("\r"), ord("\n")):
                    end += 1
                if end > start:
                    host = payload[start:end].decode("ascii", errors="replace")
                    colon_pos = host.find(":")
                    if colon_pos != -1:
                        host = host[:colon_pos]
                    return host
            i += 1

        return None


class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes, length: int) -> bool:
        if length < 12:
            return False
        if payload[2] & 0x80:
            return False
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount > 0

    @staticmethod
    def extract_query(payload: bytes, length: int) -> Optional[str]:
        if not DNSExtractor.is_dns_query(payload, length):
            return None

        offset = 12
        labels = []
        while offset < length:
            label_length = payload[offset]
            if label_length == 0:
                break
            if label_length > 63:
                break
            offset += 1
            if offset + label_length > length:
                break
            labels.append(payload[offset:offset + label_length].decode("ascii", errors="replace"))
            offset += label_length

        domain = ".".join(labels)
        return domain if domain else None


class QUICSNIExtractor:
    @staticmethod
    def is_quic_initial(payload: bytes, length: int) -> bool:
        if length < 5:
            return False
        return (payload[0] & 0x80) != 0

    @staticmethod
    def extract(payload: bytes, length: int) -> Optional[str]:
        if not QUICSNIExtractor.is_quic_initial(payload, length):
            return None
        for i in range(length - 50):
            if payload[i] == 0x01:
                start = max(0, i - 5)
                result = SNIExtractor.extract(payload[start:], length - start)
                if result:
                    return result
        return None
