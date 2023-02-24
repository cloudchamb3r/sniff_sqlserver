from enum import Enum 
from typing import Optional

def get_flags(byte, candidate_flags):
    flags = []
    bit = 1
    for flag in candidate_flags:
        if (byte & bit) != 0: 
            flags.append(flag)
        bit = bit << 1
    return flags


class TDS_TYPE(Enum):
    SQL_BATCH                       = 0x01 
    PRE_TDS7_LOGIN                  = 0x02
    RPC                             = 0x03
    TABULAR_RESULT                  = 0x04
    ATTENTION_SINGAL                = 0x06
    BULK_LOAD_DATA                  = 0x07
    FEDERATED_AUTHENTICATION_TOKEN  = 0x08
    TRANSACTION_MANAGER_REQUEST     = 0x0E
    TDS7_LOGIN                      = 0x10
    SSPI                            = 0x11
    PRE_LOGIN                       = 0x12

    def is_unused(self) -> bool:
        _unused = [5,9,10,11,12,13,15]
        return self.value in _unused

    def is_unknown(self) -> bool:
        return self.value > 0x12
    
    def has_data(self) -> bool:
        _avail_values = [
            TDS_TYPE.SQL_BATCH.value,
            TDS_TYPE.PRE_TDS7_LOGIN.value,
            TDS_TYPE.RPC.value,
            TDS_TYPE.TABULAR_RESULT.value,
            TDS_TYPE.BULK_LOAD_DATA.value,
            TDS_TYPE.FEDERATED_AUTHENTICATION_TOKEN.value,
            TDS_TYPE.TRANSACTION_MANAGER_REQUEST.value,
            TDS_TYPE.TDS7_LOGIN.value,
            TDS_TYPE.SSPI.value,
            TDS_TYPE.PRE_LOGIN.value
        ]
        return self.value in _avail_values

class TDS_STATUS(Enum):
    NORMAL                      = 0b0000_0000
    EOM                         = 0b0000_0001
    IGNORE_THIS                 = 0b0000_0010
    RESET_CONNECTION            = 0b0000_1000
    RESET_CONNCETION_SKIP_TRAN  = 0b0001_0000


    def get_flags(self):
        flags = [] 
        if flags & TDS_STATUS.EOM: 
            flags.append(TDS_STATUS.EOM)
        if flags & TDS_STATUS.IGNORE_THIS: 
            flags.append(TDS_STATUS.IGNORE_THIS)
        if flags & TDS_STATUS.RESET_CONNECTION:
            flags.append(TDS_STATUS.RESET_CONNECTION)
        if flags & TDS_STATUS.RESET_CONNCETION_SKIP_TRAN:
            flags.append(TDS_STATUS.RESET_CONNCETION_SKIP_TRAN)
        return flags if len(flags) != 0 else [TDS_STATUS.NORMAL]

class TDS_TOKEN(Enum):
    ALTMETADATA_TOKEN           = 0x88
    ALTROW_TOKEN                = 0xD3
    COLMETADATA_TOKEN           = 0x81
    COLINFO_TOKEN               = 0xA5
    DATACLASSIFICATION_TOKEN    = 0xA3
    DONE_TOKEN                  = 0xFD
    DONEPROC_TOKEN              = 0xFE
    DONEINPROC_TOKEN            = 0xFF
    ENVCHANGE_TOKEN             = 0xE3
    ERROR_TOKEN                 = 0xAA
    FEATUREEXTACK_TOKEN         = 0xAE
    FEDAUTHINFO_TOKEN           = 0xEE
    INFO_TOKEN                  = 0xAB
    LOGINACK_TOKEN              = 0xAD
    NBCROW_TOKEN                = 0xD2
    OFFSET_TOKEN                = 0x78
    ORDER_TOKEN                 = 0xA9
    RETURNSTATUS_TOKEN          = 0x79
    RETURNVALUE_TOKEN           = 0xAC
    ROW_TOKEN                   = 0xD1
    SESSIONSTATE_TOKEN          = 0xE4 
    SSPI_TOKEN                  = 0xED
    TABNAME_TOKEN               = 0xA4
    TVP_ROW_TOKEN               = 0x01

    value : int
    def __init__(self, byte) -> None:
        self.value = byte
    
    def get_token_length(self):
        check_zero      = lambda b: ((b & 0b001100) >> 2) == 0b0010
        check_one       = lambda b: ((b & 0b111100) >> 2) == 0b0011
        check_two       = lambda b: ((b & 0b111100) >> 2) == 0b1011
        check_three     = lambda b: ((b & 0b111100) >> 2) == 0b0111
        check_four      = lambda b: ((b & 0b111100) >> 2) == 0b1111
        __check_variable  = lambda b: ((b & 0b000100) >> 2) == 0b0001

        if check_zero(self.value): return 0
        if check_one(self.value): return 1
        if check_two(self.value): return 2
        if check_three(self.value): return 3
        if check_four(self.value): return 4

        # TODO: handle variable length token length
        return 0            



class TDS_HEADER:
    type        : TDS_TYPE
    status      : TDS_STATUS
    length      : int
    server_pid  : int
    packet_id   : int
    window      : int
    def __init__(
            self, 
            type : TDS_TYPE, 
            status : TDS_STATUS, 
            length : int, 
            server_pid : int, 
            packet_id : int, 
            window : int
        ):
        self.type = type
        self.status = status
        self.length = length
        self.server_pid = server_pid
        self.packet_id = packet_id
        self.window = window

"""
    Parse MS-TDS Packet

    - Packet Header
    - Packet Data
"""
def parse_packet(packet_stream, idx = 0):
    header = parse_packet_header(packet_stream)
    if header == None: return  #  Invalid Ms-TDS Packet


    if not header.type.has_data():
        # TODO: Log Packet 
        print(">> ", header)
        return
    print('[check same!]>> ',len(packet_stream), header.length)

"""
    Parse MS-TDS PacketHeader (Total 8 bytes)
    - Type     : 1byte
    - Status   : 1byte
    - Length   : 2byte (big endian order)
    - Spid     : 2byte (big endian order)
    - PacketId : 1byte 
    - Window   : 1byte (unused = 0x00)
"""
def parse_packet_header(packet_stream : bytes)-> Optional[TDS_HEADER]:
    if len(packet_stream) < 8: return None

    type = TDS_TYPE(packet_stream[0])
    status = TDS_STATUS(packet_stream[1])
    length = int.from_bytes(packet_stream[2:4], 'big')
    server_pid =  int.from_bytes(packet_stream[4:6], 'big')
    pakcet_id = packet_stream[6]
    window = packet_stream[7]


    if type.is_unknown(): return None
    #  why my captured packets' TDS length does not in range [512, 4096]??
    return TDS_HEADER(
            type, 
            status, 
            length, 
            server_pid,
            pakcet_id, 
            window
        )
