--[[
#################################################################
# MPLS Network Actions Framework Wireshark Dissector            #
# Created by Fabian Ihle, 25.04.2024                            #
# github: https://github.com/uni-tue-kn/P4-MNA                  #
#                                                               #
# Description:                                                  #
# This script adds network actions as ISD and PSD to wireshark  #
# Place it in your lua plugin folder of wireshark               #
# ------------------------------------------------------------- #
# Changelog:                                                    #
# 25.04.2024 - Initial version                                  #
# 05.07.2024 - Update encoding to mpls-mna-hdr-07               #
# 25.10.2024 - Bug fixes introduced with latest encoding        #
# 17.04.2026 - Adapted new PSD encoding, Added DetNet CW        #
#################################################################
--]]  

mna_protocol = Proto("MNA", "MPLS Network Actions")

-- Initial opcode (Format B)
init_opcode = ProtoField.uint32("MNA.initial_opcode", "Opcode", base.DEC, NULL,
                                4261412864)
init_data1 = ProtoField.uint32("MNA.data1", "Data1", base.DEC, NULL, 33550336)
init_p = ProtoField.uint32("MNA.p_bit", "P Bit", base.DEC, NULL, 2048)
init_scope = ProtoField.uint32("MNA.scope", "Scope", base.DEC, NULL, 1536)
bos = ProtoField.uint32("MNA.bos", "Bottom of Stack", base.DEC, NULL, 256)
init_unknown_action = ProtoField.uint32("MNA.unknown_action",
                                        "Unknown Action Handling", base.DEC,
                                        NULL, 8)
init_nasl = ProtoField.uint32("MNA.nasl", "NASL", base.DEC, NULL, 240)
init_nal = ProtoField.uint32("MNA.nal", "NAL", base.DEC, NULL, 7)

-- Sub opcode (Format C)
sub_opcode = ProtoField.uint32("MNA.sub_opcode", "Opcode", base.DEC, NULL,
                               4261412864)
sub_data1 = ProtoField.uint32("MNA.sub_data1", "Data1", base.DEC, NULL, 33553920)
sub_unknown_action = ProtoField.uint32("MNA.sub_unknown_action", "Unknown Action Handling", base.DEC, NULL, 8)
sub_data2 = ProtoField.uint32("MNA.sub_data2", "Data2", base.DEC, NULL, 240)
sub_nal = ProtoField.uint32("MNA.nal", "NAL", base.DEC, NULL, 7)

-- AD LSE (Format D)
ad_one = ProtoField.uint32("MNA.ad_one", "Constant", base.DEC, NULL, 2147483648)
ad_data1 =
    ProtoField.uint32("MNA.ad_data1", "Data1", base.DEC, NULL, 2147483136)
ad_data2 = ProtoField.uint32("MNA.ad_data2", "Data2", base.DEC, NULL, 255)

-- MPLS label (Format A)
label = ProtoField.uint32("MNA.label", "Label", base.DEC, NULL, 4294963200)
tc = ProtoField.uint32("MNA.tc", "Traffic Class", base.DEC, NULL, 3584)
ttl = ProtoField.uint32("MNA.ttl", "TTL", base.DEC, NULL, 255)

-- TODO fix the uint32 types

mna_protocol.fields = {
    label, tc, ttl, ad_one, init_opcode, sub_opcode, init_data1, sub_unknown_action, ad_data1,
    sub_data1, init_p, init_scope, bos, sub_data2,
    init_unknown_action, ad_data2, init_nasl, init_nal, sub_nal
}

psd_protocol = Proto("PSM", "MNA Post-Stack Data")

-- Post-Stack MNA Header (PSMHT)
psmh_pfn = ProtoField.uint32("PSM.pfn", "PFN", base.DEC, NULL, 0xF0000000)
psmh_reserved = ProtoField.uint32("PSM.psmh_reserved", "Reserved", base.DEC,
                                  NULL, 0x0F000000)
psmh_len = ProtoField.uint32("PSM.psmh_len", "PSMH-Len", base.DEC, NULL,
                             0x00FF0000)
psmh_type = ProtoField.uint32("PSM.type", "Type", base.DEC, NULL, 0x0000FFFF)

-- Post-Stack Network Action (PSNA)
psna_opcode = ProtoField.uint32("PSM.opcode", "Opcode", base.DEC, NULL,
                                0xFE000000)
psna_reserved = ProtoField.uint32("PSM.psna_reserved", "Reserved", base.DEC,
                                  NULL, 0x01800000)
psna_ps_nal = ProtoField.uint32("PSM.ps_nal", "PS-NAL", base.DEC, NULL,
                                0x007F0000)
psna_data = ProtoField.uint32("PSM.data16", "Data", base.DEC, NULL, 0x0000FFFF)

-- 32 bits treated as continuation data
psd_full_data = ProtoField.uint32("PSM.data", "Data", base.DEC)

psd_protocol.fields = {
    psmh_pfn, psmh_reserved, psmh_len, psmh_type, psna_opcode,
    psna_reserved, psna_ps_nal, psna_data, psd_full_data
}

detnet_cw_protocol = Proto("DetNetCW", "DetNet Control Word")

detnet_cw_version = ProtoField.uint32("DetNetCW.version", "Version", base.DEC,
                                      NULL, 4026531840)
detnet_cw_sequence_number = ProtoField.uint32("DetNetCW.sequence_number",
                                              "DetNet Sequence Number",
                                              base.DEC, NULL, 268435455)

detnet_cw_protocol.fields = {detnet_cw_version, detnet_cw_sequence_number}

local MNA_BSPL = 4;
local MPLS_MNA_PSMHT_TYPE = 1

local MPLS_ETHER_TYPE = 0x8847;
local DETNET_CONTROL_WORD_FIRST_NIBBLE = 0
local IPV4_VERSION = 4
local IPV6_VERSION = 6

local function has_bytes(buffer, byte_offset, byte_length)
    return byte_offset + byte_length <= buffer:len()
end

local function get_first_nibble(buffer, byte_offset)
    if not has_bytes(buffer, byte_offset, 1) then
        return nil
    end

    local first_byte = buffer(byte_offset, 1)
    return bit.rshift(bit.band(first_byte:uint(), 0xF0), 4)
end

local function is_psmht(buffer, byte_offset)
    if not has_bytes(buffer, byte_offset, 4) then
        return false
    end

    local word = buffer(byte_offset, 4):uint()
    local pfn = bit.rshift(bit.band(word, 0xF0000000), 28)
    local reserved = bit.rshift(bit.band(word, 0x0F000000), 24)
    local psmht_type = bit.band(word, 0x0000FFFF)

    return pfn == 0 and reserved == 0 and psmht_type == MPLS_MNA_PSMHT_TYPE
end

local function dissect_post_stack_payload(buffer, byte_offset, pinfo, tree)
    if byte_offset >= buffer:len() then return end

    if is_psmht(buffer, byte_offset) then
        psd_protocol.dissector(buffer:range(byte_offset):tvb(), pinfo, tree)
        return
    end

    local first_nibble = get_first_nibble(buffer, byte_offset)
    if first_nibble == nil then return end

    if first_nibble == DETNET_CONTROL_WORD_FIRST_NIBBLE then
        if not has_bytes(buffer, byte_offset, 4) then return end

        local detnet_cw = buffer(byte_offset, 4)
        local detnet_cw_subtree = tree:add(detnet_cw_protocol, detnet_cw,
                                           "DetNet Control Word")

        detnet_cw_subtree:add(detnet_cw_version, detnet_cw)
        detnet_cw_subtree:add(detnet_cw_sequence_number, detnet_cw)

        byte_offset = byte_offset + 4
        if byte_offset >= buffer:len() then return end

        first_nibble = get_first_nibble(buffer, byte_offset)
        if first_nibble == nil then return end
    end

    if first_nibble == IPV4_VERSION then
        ipv4_dissector = Dissector.get("ip")
        ipv4_dissector:call(buffer:range(byte_offset):tvb(), pinfo, tree)
    elseif first_nibble == IPV6_VERSION then
        ipv6_dissector = Dissector.get("ipv6")
        ipv6_dissector:call(buffer:range(byte_offset):tvb(), pinfo, tree)
    end
end

function mna_protocol.dissector(buffer, pinfo, tree)

    length = buffer:len()
    if length == 0 then return end

    -- set the protocol column
    pinfo.cols.protocol = mna_protocol.name;
    -- create the protocol item tree
    subtree = tree:add(mna_protocol, buffer(), "MPLS Stack")

    local lookahead_bos = 0
    local lse_number = 0

    max_depth = 64

    -- buffer(offset, length):uint()

    while (lookahead_bos == 0) do

        if lse_number == max_depth then return end

        local lse = buffer(lse_number * 4, 4)

        -- Mask the S bit of this LSE
        lookahead_bos = bit.band(lse:int(), 256);
        lookahead_label = bit.rshift(bit.band(lse:int(), 4294963200), 12)

        if (lookahead_label == MNA_BSPL) then
            -- Do MNA

            -- Get the initial opcode   
            lse_number = lse_number + 1
            initial_opcode_lse = buffer(lse_number * 4, 4)
            scope = bit.rshift(bit.band(initial_opcode_lse:uint(), 1536), 9)

            local scope_str
            if scope == 1 then
                scope_str = "HBH"
            elseif scope == 2 then
                scope_str = "Select"
            elseif scope == 0 then
                scope_str = "I2E"
            else
                scope_str = "Undefined"
            end

            nasl = bit.rshift(bit.band(initial_opcode_lse:uint(), 240), 4)

            init_nal_lookahead = bit.band(initial_opcode_lse:uint(), 7)

            nas_subtree = subtree:add(mna_protocol, buffer(), "NAS " ..
                                          scope_str .. ", Length: " .. nasl)

            nasi_subtree = nas_subtree:add(mna_protocol, buffer(),
                                           "MNA bSPL NAS Indicator")

            nasi_subtree:add(label, lse)
            nasi_subtree:add(tc, lse)
            nasi_subtree:add(bos, lse)
            nasi_subtree:add(ttl, lse)

            local lookahead_opcode = bit.rshift(bit.band(
                                                    initial_opcode_lse:uint(),
                                                    4261412864), 25)
            local lookahead_data = bit.rshift(bit.band(
                                                  initial_opcode_lse:uint(),
                                                  33550336), 12)
            lookahead_bos = bit.band(initial_opcode_lse:int(), 256);

            init_opcode_subtree = nas_subtree:add(mna_protocol, buffer(),
                                                  "MNA NAS Initial Opcode LSE, Opcode: " ..
                                                      lookahead_opcode,
                                                  " Data: " .. lookahead_data)
            init_opcode_subtree:add(init_opcode, initial_opcode_lse)
            init_opcode_subtree:add(init_data1, initial_opcode_lse)
            init_opcode_subtree:add(init_p, initial_opcode_lse)
            init_opcode_subtree:add(init_scope, initial_opcode_lse)
            init_opcode_subtree:add(bos, initial_opcode_lse)
            init_opcode_subtree:add(init_unknown_action, initial_opcode_lse)
            init_opcode_subtree:add(init_nasl, initial_opcode_lse)
            init_opcode_subtree:add(init_nal, initial_opcode_lse)
            lse_number = lse_number + 1

            -- TODO NAL for init opcode here
            if init_nal_lookahead > 0 then
                for a = 1, init_nal_lookahead do
                    -- Get Ancillary Data for initial opcode LSE
                    ad_lse = buffer(lse_number * 4, 4)
                    ad_subtree =
                        nas_subtree:add(mna_protocol, buffer(),
                                        "MNA NAS Ancillary data LSE")
                    lookahead_bos = bit.band(ad_lse:int(), 256);

                    ad_subtree:add(ad_one, ad_lse)
                    ad_subtree:add(ad_data1, ad_lse)
                    ad_subtree:add(bos, ad_lse)
                    ad_subtree:add(ad_data2, ad_lse)

                    lse_number = lse_number + 1
                end
            end

            if nasl - init_nal_lookahead > 0 then
                local s = 0
                while s < nasl - init_nal_lookahead do
                    -- Get subsequent opcode
                    sub_opcode_lse = buffer(lse_number * 4, 4)

                    local lookahead_opcode =
                        bit.rshift(bit.band(sub_opcode_lse:uint(), 4261412864),
                                   25)
                    local lookahead_data1 =
                        bit.rshift(bit.band(sub_opcode_lse:uint(), 33553920), 9)
                    local lookahead_data2 =
                        bit.rshift(bit.band(sub_opcode_lse:uint(), 240), 4)
                    lookahead_bos = bit.band(sub_opcode_lse:int(), 256);

                    sub_opcode_subtree =
                        nas_subtree:add(mna_protocol, buffer(),
                                        "MNA NAS Subsequent Opcode LSE, Opcode: " ..
                                            lookahead_opcode .. " Data1: " ..
                                            lookahead_data1,
                                        " Data2: " .. lookahead_data2)

                    nal = bit.band(sub_opcode_lse:uint(), 7)
                    sub_opcode_subtree:add(sub_opcode, sub_opcode_lse)
                    sub_opcode_subtree:add(sub_data1, sub_opcode_lse)
                    sub_opcode_subtree:add(bos, sub_opcode_lse)
                    sub_opcode_subtree:add(sub_unknown_action, sub_opcode_lse)
                    sub_opcode_subtree:add(sub_data2, sub_opcode_lse)
                    sub_opcode_subtree:add(sub_nal, sub_opcode_lse)
                    lse_number = lse_number + 1
                    s = s + 1

                    if nal > 0 then
                        -- Get Ancillary Data
                        for a = 1, nal do
                            ad_lse = buffer(lse_number * 4, 4)
                            ad_subtree =
                                nas_subtree:add(mna_protocol, buffer(),
                                                "MNA NAS Ancillary data LSE")
                            lookahead_bos = bit.band(ad_lse:int(), 256);

                            ad_subtree:add(ad_one, ad_lse)
                            ad_subtree:add(ad_data1, ad_lse)
                            ad_subtree:add(bos, ad_lse)
                            ad_subtree:add(ad_data2, ad_lse)

                            lse_number = lse_number + 1
                            s = s + 1
                        end
                    end
                end
            end

        else
            -- MPLS Label
            subsubtree = subtree:add(mna_protocol, buffer(),
                                     "MPLS Forwarding Label " .. lookahead_label)

            subsubtree:add(label, lse)
            subsubtree:add(tc, lse)
            subsubtree:add(bos, lse)
            subsubtree:add(ttl, lse)

            lse_number = lse_number + 1
        end
    end

    dissect_post_stack_payload(buffer, lse_number * 4, pinfo, tree)

end

function psd_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    -- set the protocol column
    pinfo.cols.protocol = psd_protocol.name;
    -- create the protocol item tree
    subtree = tree:add(psd_protocol, buffer(), "MNA Post-Stack data")

    local lse_number = 0

    if not has_bytes(buffer, lse_number * 4, 4) then return end
    local lse = buffer(lse_number * 4, 4)

    lookahead_psd_length = bit.rshift(bit.band(lse:uint(), 0x00FF0000), 16)

    top_header_subtree = subtree:add(psd_protocol, buffer(),
                                     "Post-Stack MNA Header, Length: " ..
                                         lookahead_psd_length)
    top_header_subtree:add(psmh_pfn, lse)
    top_header_subtree:add(psmh_reserved, lse)
    top_header_subtree:add(psmh_len, lse)
    top_header_subtree:add(psmh_type, lse)

    lse_number = lse_number + 1

    if lookahead_psd_length > 0 then
        local words_consumed = 0
        while words_consumed < lookahead_psd_length do
            if not has_bytes(buffer, lse_number * 4, 4) then return end

            psd_na = buffer(lse_number * 4, 4)

            local lookahead_opcode = bit.rshift(
                                         bit.band(psd_na:uint(), 0xFE000000), 25)
            local lookahead_nal = bit.rshift(bit.band(psd_na:uint(), 0x007F0000),
                                             16)
            local lookahead_data = bit.band(psd_na:uint(), 0x0000FFFF)
            psd_na_subtree = subtree:add(psd_protocol, buffer(),
                                         "Post-Stack Network Action, Opcode: " ..
                                             lookahead_opcode .. " Length: " ..
                                             lookahead_nal,
                                         " Data: " .. lookahead_data)

            psd_na_subtree:add(psna_opcode, psd_na)
            psd_na_subtree:add(psna_reserved, psd_na)
            psd_na_subtree:add(psna_ps_nal, psd_na)
            psd_na_subtree:add(psna_data, psd_na)

            lse_number = lse_number + 1
            words_consumed = words_consumed + 1

            if lookahead_nal > 0 then
                for a = 1, lookahead_nal do
                    if words_consumed >= lookahead_psd_length then return end
                    if not has_bytes(buffer, lse_number * 4, 4) then return end

                    ad_lse = buffer(lse_number * 4, 4)
                    local lookahed_data_psd = ad_lse:uint()

                    ad_subtree = subtree:add(psd_protocol, buffer(),
                                             "Post-Stack Data, Data: " ..
                                                 lookahed_data_psd)

                    ad_subtree:add(psd_full_data, ad_lse)

                    lse_number = lse_number + 1
                    words_consumed = words_consumed + 1
                end
            end
        end
    end

    dissect_post_stack_payload(buffer, lse_number * 4, pinfo, tree)

end

local ether_type = DissectorTable.get("ethertype")
ether_type:add(MPLS_ETHER_TYPE, mna_protocol)
