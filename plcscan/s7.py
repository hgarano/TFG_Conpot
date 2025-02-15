import struct
import socket
import string
import binascii
from random import randint
from optparse import OptionGroup


__FILTER = "".join([' '] + [' ' if chr(x) not in string.printable or chr(x) in string.whitespace else chr(x) for x in range(1, 256)])

def StripUnprintable(msg):
    return msg.translate(__FILTER)

class S7ProtocolError(Exception):
    def __init__(self, message, packet=''):
        self.message = message
        self.packet = packet

    def __str__(self):
        return f"[ERROR][S7Protocol] {self.message}"

class S7Error(Exception):
    _errors = {
        0x05: 'Address Error',
        0x0a: 'Item not available',
        0x8104: 'Context not supported',
        0x8500: 'Wrong PDU size'
    }

    def __init__(self, code):
        self.code = code

    def __str__(self):
        message = self._errors.get(self.code, 'Unknown error')
        return f"[ERROR][S7][0x{self.code:x}] {message}"

class TPKTPacket:
    """ TPKT packet. RFC 1006 """
    def __init__(self, data=b''):
        self.data = data

    
    def pack(self):
        if hasattr(self.data, 'pack'):
            data_packed = self.data.pack()
        elif isinstance(self.data, bytes):
            data_packed = self.data
        else:
            raise TypeError(f"Invalid type for COTPDataPacket.data: {type(self.data)}")
        
        return struct.pack('!BBB', 2, 0xf0, 0x80) + data_packed




    def unpack(self, packet):
        try:
            header = struct.unpack('!BBH', packet[:4])
        except struct.error:
            raise S7ProtocolError("Unknown TPKT format")

        self.data = packet[4:4 + header[2]]
        return self

    def __str__(self):
        # Para debug, si se necesita ver el contenido de los bytes
        return binascii.hexlify(self.data).decode()


class COTPConnectionPacket:
    """ COTP Connection Request or Connection Confirm packet (ISO on TCP). RFC 1006 """
    def __init__(self, dst_ref=0, src_ref=0, dst_tsap=0, src_tsap=0, tpdu_size=0):
        self.dst_ref = dst_ref
        self.src_ref = src_ref
        self.dst_tsap = dst_tsap
        self.src_tsap = src_tsap
        self.tpdu_size = tpdu_size

    def pack(self):
        # Retorna los bytes empaquetados directamente
        return struct.pack('!BBHHBBBHBBHBBB',
            17,             # size
            0xe0,           # pdu type: CR
            self.dst_ref,
            self.src_ref,
            0,              # flag
            0xc1, 2, self.src_tsap,
            0xc2, 2, self.dst_tsap,
            0xc0, 1, self.tpdu_size
        )

    def __str__(self):
        return binascii.hexlify(self.pack()).decode()

    def unpack(self, packet):
        try:
            size, pdu_type, self.dst_ref, self.src_ref, flags = struct.unpack('!BBHHB', packet[:7])
        except struct.error:
            raise S7ProtocolError("Wrong CC packet format")
        if len(packet) != size + 1:
            raise S7ProtocolError("Wrong CC packet size")
        if pdu_type != 0xd0:
            raise S7ProtocolError("Not a CC packet")

        return self


class COTPDataPacket:
    """ COTP Data packet (ISO on TCP). RFC 1006 """
    def __init__(self, data=b''):
        self.data = data

    def pack(self):
        return struct.pack('!BBB',
            2,                      # header len
            0xf0,                   # data packet
            0x80) + self.data

    def unpack(self, packet):
        self.data = packet[packet[0] + 1:]
        return self

    def __str__(self):
        return binascii.hexlify(self.data).decode()

class S7Packet:
    """ S7 packet """
    def __init__(self, type=1, req_id=0, parameters=b'', data=b''):
        self.type = type
        self.req_id = req_id
        self.parameters = parameters
        self.data = data
        self.error = 0

    def pack(self):
        if self.type not in [1, 7]:
            raise S7ProtocolError("Unknown pdu type")
        return (struct.pack('!BBHHHH',
            0x32,               # protocol s7 magic
            self.type,          # pdu-type
            0,                  # reserved
            self.req_id,        # request id
            len(self.parameters),  # parameters length
            len(self.data)) + self.parameters + self.data)

    def unpack(self, packet):
        try:
            if packet[1] in [3, 2]:  # pdu-type = response
                header_size = 12
                magic0x32, self.type, reserved, self.req_id, parameters_length, data_length, self.error = struct.unpack('!BBHHHHH', packet[:header_size])
                if self.error:
                    raise S7Error(self.error)
            elif ord(packet[1]) in [1, 7]:
                header_size = 10
                magic0x32, self.type, reserved, self.req_id, parameters_length, data_length = struct.unpack('!BBHHHH', packet[:header_size])
            else:
                raise S7ProtocolError(f"Unknown pdu type ({ord(packet[1])})")
        except struct.error:
            raise S7ProtocolError("Wrong S7 packet format")

        self.parameters = packet[header_size:header_size + parameters_length]
        self.data = packet[header_size + parameters_length:header_size + parameters_length + data_length]
        return self

    def __str__(self):
        return binascii.hexlify(self.data).decode()

class s7:
    def __init__(self, ip, port, src_tsap=0x200, dst_tsap=0x201, timeout=8):
        self.ip = ip
        self.port = port
        self.req_id = 0
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.dst_ref = 0
        self.src_ref = 0x04
        self.dst_tsap = dst_tsap
        self.src_tsap = src_tsap
        self.timeout = timeout

    def Connect(self):
        self.src_ref = randint(1, 20)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(self.timeout)
        self.s.connect((self.ip, self.port))
        self.s.send(TPKTPacket(COTPConnectionPacket(self.dst_ref, self.src_ref, self.dst_tsap, self.src_tsap, 0x0a)).pack())
        reply = self.s.recv(1024)
        response = COTPConnectionPacket().unpack(TPKTPacket().unpack(reply).data)
        self.NegotiatePDU()

    def Request(self, type, parameters=b'', data=b''):
        packet = TPKTPacket(COTPDataPacket(S7Packet(type, self.req_id, parameters, data))).pack()
        self.s.send(packet)
        reply = self.s.recv(1024)
        response = S7Packet().unpack(COTPDataPacket().unpack(TPKTPacket().unpack(reply).data).data)
        if self.req_id != response.req_id:
            raise S7ProtocolError('Sequence ID not correct')
        return response

    def NegotiatePDU(self, pdu=480):
        response = self.Request(0x01, struct.pack('!BBHHH',
            0xf0,  # function NegotiatePDU
            0x00,  # unknown
            0x01,  # max number of parallel jobs
            0x01,  # max number of parallel jobs
            pdu))  # pdu length
        func, unknown, pj1, pj2, pdu = struct.unpack('!BBHHH', response.parameters)
        return pdu

    def Function(self, type, group, function, data=b''):
        parameters = struct.pack('!LBBBB',
            0x00011200 +  # parameter head (magic)
            0x04,          # parameter length
            0x11,          # unknown
            type * 0x10 + group,  # type, function group
            function,      # function
            0x00)          # sequence

        data = struct.pack('!BBH', 0xFF, 0x09, len(data)) + data
        response = self.Request(0x07, parameters, data)

        code, transport_size, data_len = struct.unpack('!BBH', response.data[:4])
        if code != 0xFF:
            raise S7Error(code)
        return response.data[4:]

    def ReadSZL(self, szl_id):
        szl_data = self.Function(
            0x04,           # request
            0x04,           # szl-functions
            0x01,           # read szl
            struct.pack('!HH',
                szl_id,     # szl id
                1))         # szl index

        szl_id, szl_index, element_size, element_count = struct.unpack('!HHHH', szl_data[:8])
        return Split(szl_data[8:], element_size)

def BruteTsap(ip, port, src_tsaps=(0x100, 0x200), dst_tsaps=(0x102, 0x200, 0x201)):
    print(f"Probando TSAPs en {ip}:{port} - src_tsaps={src_tsaps}, dst_tsaps={dst_tsaps}")

    for src_tsap in src_tsaps:
        for dst_tsap in dst_tsaps:
            try:
                print(f"......Intentando conexión con src_tsap=0x{src_tsap:x}, dst_tsap=0x{dst_tsap:x}")
                con = s7.Scan(ip, port)
                con.src_tsap = src_tsap
                con.dst_tsap = dst_tsap
                con.Connect()

                if con:
                    print(f" GOOOOOODDDD>!!!!! Conexión exitosa con src_tsap=0x{src_tsap:x}, dst_tsap=0x{dst_tsap:x}")
                    return (src_tsap, dst_tsap)

            except S7ProtocolError as e:
                print(f"!!!!!!!!!!!! Error de protocolo S7 en {ip}:{port} -> {e}")
            except socket.error as e:
                print(f"!!!!!!!!!!!!!! Error de socket en {ip}:{port} -> {e}")

    return None


def GetIdentity(ip, port, src_tsap, dst_tsap):
    res = []

    szl_dict = {
        0x11: {
            'title': 'Module Identification',
            'indexes': {
                1: 'Module',
                6: 'Basic Hardware',
                7: 'Basic Firmware'
            },
            'packer': {
                (1, 6): lambda packet: "{0:s} v.{2:d}.{3:d}".format(*struct.unpack('!20sHBBH', packet)),
                (7,): lambda packet: "{0:s} v.{3:d}.{4:d}.{5:d}".format(*struct.unpack('!20sHBBBB', packet))
            }
        },
        0x1c: {
            'title': 'Component Identification',
            'indexes': {
                1: 'Name of the PLC',
                2: 'Name of the module',
                3: 'Plant identification',
                4: 'Copyright',
                5: 'Serial number of module',
                6: 'Reserved for operating system',
                7: 'Module type name',
                8: 'Serial number of memory card',
                9: 'Manufacturer and profile of a CPU module',
                10: 'OEM ID of a module',
                11: 'Location designation of a module'
            },
            'packer': {
                (1, 2, 5): lambda packet: "%s" % packet[:24],
                (3, 7, 8): lambda packet: "%s" % packet[:32],
                (4,): lambda packet: "%s" % packet[:26]
            }
        }
    }

    con = s7(ip, port, src_tsap, dst_tsap)
    con.Connect()

    for szl_id in szl_dict.keys():
        try:
            entities = con.ReadSZL(szl_id)
        except S7Error:
            continue

        indexes = szl_dict[szl_id]['indexes']
        packers = szl_dict[szl_id]['packer']
        for item in entities:
            if len(item) > 2:
                n, = struct.unpack('!H', item[:2])
                item = item[2:]
                title = indexes[n] if indexes.get(n) else f"Unknown ({n})"

                try:
                    packers_keys = [i for i in packers.keys() if n in i]
                    formated_item = packers[packers_keys[0]](item).strip('\x00')
                except (struct.error, IndexError):
                    formated_item = StripUnprintable(item).strip('\x00')

                res.append(f"{title.ljust(25)}: {formated_item.ljust(30)}\t({binascii.hexlify(item).decode()})")

    return res

def Scan(ip, port, options):
    src_tsaps = [int(n.strip(), 0) for n in options.src_tsap.split(',')] if options.src_tsap else [0x100, 0x200]
    dst_tsaps = [int(n.strip(), 0) for n in options.dst_tsap.split(',')] if options.dst_tsap else [0x102, 0x200, 0x201]

    print(f" Escaneando {ip}:{port} con src_tsaps={src_tsaps}, dst_tsaps={dst_tsaps}")

    res = ()
    try:
        res = BruteTsap(ip, port, src_tsaps, dst_tsaps)
    except socket.error as e:
        print(f" Error en conexión con {ip}:{port} -> {e}")

    if not res:
        print(f" No se pudo establecer conexión con {ip}:{port}.")
        return False

    print(f"✅{ip}:{port} S7comm encontrado (src_tsap=0x{res[0]:x}, dst_tsap=0x{res[1]:x})")

    identities = []
    for attempt in [0, 1]:
        try:
            identities = GetIdentity(ip, port, res[0], res[1])
            break
        except (S7ProtocolError, socket.error) as e:
            print(f"⚠️  Error obteniendo identidad en {ip}:{port} -> {e}")

    for line in identities:
        print(f"🆔 {line}")

    return True


def AddOptions(parser):
    group = OptionGroup(parser, "S7 scanner options")
    group.add_option("--src-tsap", help="Try this src-tsap (list) (default: 0x100,0x200)", type="string", metavar="LIST")
    group.add_option("--dst-tsap", help="Try this dst-tsap (list) (default: 0x102,0x200,0x201)", type="string", metavar="LIST")
    parser.add_option_group(group)
