#################################################################
# MPLS Network Actions Framework Library                        #
# Created by Fabian Ihle, 25.04.2024                            #
# github: https://github.com/uni-tue-kn/P4-MNA                  #
#                                                               #
# Description:                                                  #
# This library contains structures to encode the MNA framework  #
# ------------------------------------------------------------- #
# Changelog:                                                    #
# 25.04.2024 - Initial version                                  #
# 05.07.2024 - Update encoding to mpls-mna-hdr-07               #
# 25.10.2024 - Bug fixes introduced with latest encoding        #
#################################################################

from enum import Enum

class Scope(Enum):
    I2E = 0
    HBH = 1
    SELECT = 2
    RESERVED = 3

class UnkownActionHandling(Enum):
    IGNORE = 0
    DROP = 1

class MPLS_LSE():
    def __init__(self, label: int, tc: int, bos=None, ttl=None) -> None:
        self.label = label
        self.tc = tc
        self.bos = bos if bos else 0
        self.ttl = ttl if ttl else 64

    def __str__(self) -> str:
        return f"| LSE Label: {self.label}, BoS: {self.bos} |, {hex(self.get_payload())}"
    
    def get_payload(self):
        label_bits = str(bin(self.label)[2:]).zfill(20)
        tc_bits = str(bin(self.tc)[2:]).zfill(3)
        bos_bits = str(bin(self.bos)[2:]).zfill(1)
        ttl_bits = str(bin(self.ttl)[2:]).zfill(8)

        s = label_bits + tc_bits + bos_bits + ttl_bits
        s_h = ""
        assert len(s) == 32

        for i in range(0, len(s), 8):
            b = s[i: i + 8]
            s_h += hex(int(b, 2))[2:].zfill(2)
        int_payload = int(s_h, 16)
        return int_payload

    def to_hex_payload(self):
        return self.get_payload()


class InitialLSE():

    def __init__(self, opcode, data, p_bit, scope: Scope, bos, unknown_action_handling: UnkownActionHandling) -> None:
        self.opcode = opcode
        self.data = data
        self.p_bit = p_bit # PSD present
        self.ihs = scope
        self.bos = bos if bos else 0 # will be computed later 
        self.unknown_action_handling = unknown_action_handling
        self.NASL = 0  # will be computed later 
        self.NAL = 0
        self.ancillary_data = []

    def add_ancillary_data(self, data, mutable_data):
        try:
            assert len(self.ancillary_data) <= 7
        except AssertionError:
            print("Only 7 AD LSEs per opcode allowed!")
            return        
        ad_lse = AncillaryDataLSE(data, 0, mutable_data)
        self.ancillary_data.append(ad_lse)

        self.NAL = len(self.ancillary_data)
        self.NASL += 1

    def __str__(self) -> str:
        s = [f"|  Initial opcode: {self.opcode}, Scope: {self.ihs.name}, NASL: {self.NASL}, NAL: {self.NAL}, BoS: {self.bos}, P: {self.p_bit} |, {hex(self.get_payload())}"]
        [s.append(str(ad)) for ad in self.ancillary_data]
        return "\n".join(s)
    
    def get_payload(self):
        opcode_bits = str(bin(self.opcode)[2:]).zfill(7)
        data_bits = str(bin(self.data)[2:]).zfill(13)
        p_bits = str(bin(self.p_bit)[2:]).zfill(1)
        ihs_bits = str(bin(self.ihs.value)[2:]).zfill(2)
        bos_bits = str(bin(self.bos)[2:]).zfill(1)
        unknown_action_bits = str(bin(self.unknown_action_handling.value)[2:]).zfill(1)
        NASL_bits = str(bin(self.NASL)[2:]).zfill(4)
        NAL_bits = str(bin(self.NAL)[2:]).zfill(3)

        s = opcode_bits + data_bits + p_bits + ihs_bits + bos_bits + unknown_action_bits + NASL_bits + NAL_bits
        s_h = ""
        assert len(s) == 32

        for i in range(0, len(s), 8):
            b = s[i: i + 8]
            s_h += hex(int(b, 2))[2:].zfill(2)
        int_payload = int(s_h, 16)
        return int_payload

    def to_hex_payload(self):
        return self.get_payload()

class SubsequentOpcodeLSE():
    def __init__(self, nas, opcode, data=0, bos=0, unknown_action_handling=UnkownActionHandling.IGNORE, mutable_data=0) -> None:
        self.nas = nas
        self.opcode = opcode
        self.data = data 
        self.bos = bos if bos else 0
        self.unknown_action_handling = unknown_action_handling
        self.mutable_data = mutable_data
        self.NAL = 0 # will be computed later 
        self.ancillary_data = []

    def add_ancillary_data(self, data, mutable_data):
        ad_lse = AncillaryDataLSE(data, 0, mutable_data)
        self.ancillary_data.append(ad_lse)
        self.NAL = len(self.ancillary_data)
        self.nas.initial_lse.NASL += 1

        if self == self.nas.subsequent_opcodes[-1]:
            ad_lse.bos = 0

    def __str__(self) -> str:
        s = [f"|     Subsq. opcode: {self.opcode}, NAL: {self.NAL} BoS: {self.bos} |, {hex(self.get_payload())}"]
        [s.append(str(ad)) for ad in self.ancillary_data]
        return "\n".join(s)

    def get_payload(self):
        opcode_bits = str(bin(self.opcode)[2:]).zfill(7)
        data_bits = str(bin(self.data)[2:]).zfill(16)
        bos_bits = str(bin(self.bos)[2:]).zfill(1)
        unknown_action_bits = str(bin(self.unknown_action_handling.value)[2:]).zfill(1)
        data2_bits = str(bin(self.mutable_data)[2:]).zfill(4)
        NAL_bits = str(bin(self.NAL)[2:]).zfill(3)

        s = opcode_bits + data_bits + bos_bits + unknown_action_bits + data2_bits + NAL_bits
        s_h = ""
        assert len(s) == 32

        for i in range(0, len(s), 8):
            b = s[i: i + 8]
            s_h += hex(int(b, 2))[2:].zfill(2)
        int_payload = int(s_h, 16)
        return int_payload

    def to_hex_payload(self):
        # Collect ancillary data belonging to this opcode
        full_payload = [self.get_payload()]
        for ad in self.ancillary_data:
            full_payload.append(ad.to_hex_payload())
        return full_payload

class AncillaryDataLSE():
    def __init__(self, data, bos, mutable_data) -> None:
        self.data = data
        self.bos = bos
        self.mutable_data = mutable_data

    def __str__(self) -> str:
        return f"|          Data entry BoS {self.bos} |, {hex(self.get_payload())}"
    
    def get_payload(self):
        data_bits = str(bin(self.data)[2:]).zfill(22)
        bos_bits = str(bin(self.bos)[2:]).zfill(1)
        data2_bits = str(bin(self.mutable_data)[2:]).zfill(8)

        s = "1" + data_bits + bos_bits + data2_bits
        s_h = ""
        assert len(s) == 32

        for i in range(0, len(s), 8):
            b = s[i: i + 8]
            s_h += hex(int(b, 2))[2:].zfill(2)
        int_payload = int(s_h, 16)
        return int_payload

    def to_hex_payload(self):
        return self.get_payload()

class NAS():
    def __init__(self, initial_opcode, initial_data, scope: Scope, unknown_action_handling: UnkownActionHandling, p_bit=0) -> None:
        self.NSI = MPLS_LSE(label=4, tc=7, bos=0, ttl=64)
        self.initial_lse = InitialLSE(initial_opcode, initial_data, p_bit, scope, 0, unknown_action_handling)
        self.subsequent_opcodes = []

    def add_subsequent_opcode(self, opcode, data, unknown_action_handling, mutable_data, bos=0):
        sub_op = SubsequentOpcodeLSE(self, opcode, data, bos, unknown_action_handling, mutable_data)
        self.subsequent_opcodes.append(sub_op)

        # Recalculate NASL
        nasl = self.initial_lse.NAL
        if self.subsequent_opcodes:
            for sub_op_lse in self.subsequent_opcodes:
                nasl += 1
                for ad_lse in sub_op_lse.ancillary_data:
                    nasl += 1
            self.initial_lse.NASL = nasl

    def __str__(self) -> str:
        s = [str(self.NSI), str(self.initial_lse)]
        s += [str(lse) for lse in self.subsequent_opcodes]
        
        return "\n".join(s)
            

    def to_hex_payload(self):
        payload = []

        nsi_payload = [self.NSI.to_hex_payload()]
        init_lse_payload = [self.initial_lse.to_hex_payload()]
        subsequent_opcode_data_payload = [lse.to_hex_payload() for lse in self.subsequent_opcodes]

        payload = [nsi_payload, init_lse_payload] + subsequent_opcode_data_payload

        flat_list = [item for sublist in payload for item in sublist]

        return flat_list

class PSDTopHeader():
    def __init__(self):
        self.first_nibble = 10
        self.version = 0
        self.ps_mna_len = 0 # will be computed later
        self.type = 42
        self.ps_network_actions = []

    def add_ps_network_action(self, opcode, data):
        ps_na = PSDNetworkAction(self, opcode, data)
        self.ps_network_actions.append(ps_na)
        nal = 0
        if self.ps_network_actions:
            for ps_a in self.ps_network_actions:
                nal += 1
                for psd in ps_a.psd:
                    nal += 1
            self.ps_mna_len = nal
        else:
            self.ps_mna_len = 0

    def __str__(self) -> str:
        s = [f"| PSD Top header Len: {self.ps_mna_len} |, {hex(self.get_payload())}"]
        s += [str(lse) for lse in self.ps_network_actions]
        
        return "\n".join(s)

    def get_payload(self):
        first_nibble_bits = str(bin(self.first_nibble)[2:]).zfill(4)
        version_bits = str(bin(self.version)[2:]).zfill(4)
        len_bits = str(bin(self.ps_mna_len)[2:]).zfill(8)
        type_bits = str(bin(self.type)[2:]).zfill(16)

        s = first_nibble_bits + version_bits + len_bits + type_bits
        s_h = ""
        assert len(s) == 32

        for i in range(0, len(s), 8):
            b = s[i: i + 8]
            s_h += hex(int(b, 2))[2:].zfill(2)
        int_payload = int(s_h, 16)
        return int_payload

    def to_hex_payload(self):
        return self.get_payload()

class PSDNetworkAction():
    def __init__(self, top_header, opcode, ps_data):
        self.top_header = top_header
        self.opcode = opcode
        self.reserved = 0
        self.ps_nal = 0 # will be computed later
        self.ps_data = ps_data
        self.psd = []

    def add_psd(self, data):
        psd_lse = PSDData(data)
        self.psd.append(psd_lse)
        self.ps_nal = len(self.psd)
        self.top_header.ps_mna_len += 1        

    def __str__(self) -> str:
        s = [f"|  PSD Network action opcode: {self.opcode}, NAL: {self.ps_nal} |, {hex(self.get_payload())}"]
        if self.psd:
            for p in self.psd:
                s.append(str(p))
        return "\n".join(s)

    def get_payload(self):
        opcode_bits = str(bin(self.opcode)[2:]).zfill(7)
        reserved_bits = str(bin(self.reserved)[2:]).zfill(2)
        nal_bits = str(bin(self.ps_nal)[2:]).zfill(7)
        data_bits = str(bin(self.ps_data)[2:]).zfill(16)

        s = opcode_bits + reserved_bits + nal_bits + data_bits
        s_h = ""
        assert len(s) == 32

        for i in range(0, len(s), 8):
            b = s[i: i + 8]
            s_h += hex(int(b, 2))[2:].zfill(2)
        int_payload = int(s_h, 16)
        return int_payload

    def to_hex_payload(self):
        return self.get_payload()
    
class PSDData():
    def __init__(self, data):
        self.data = data

    def __str__(self) -> str:
        return f"|          PSD Data: {self.data} |, {hex(self.get_payload())}"        

    def get_payload(self):
        data_bits = str(bin(self.data)[2:]).zfill(32)

        s = data_bits
        s_h = ""
        assert len(s) == 32

        for i in range(0, len(s), 8):
            b = s[i: i + 8]
            s_h += hex(int(b, 2))[2:].zfill(2)
        int_payload = int(s_h, 16)
        return int_payload

    def to_hex_payload(self):
        return self.get_payload()        
