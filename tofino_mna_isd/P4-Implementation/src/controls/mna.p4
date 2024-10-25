#include "mna/mna_first_nas.p4"
#include "mna/mna_second_nas.p4"

control MNA(inout header_t hdr, 
            inout ingress_metadata_t ig_md, 
            inout ingress_intrinsic_metadata_for_tm_t ig_tm_md, 
            in ingress_intrinsic_metadata_t ig_intr_md, 
            inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    MNA_FIRST_NAS() mna_first_nas_c;
    MNA_SECOND_NAS() mna_second_nas_c;

    action drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action invalidate_first_nas(){
        hdr.mna_nasi.setInvalid();

        hdr.mna_initial_opcode.setInvalid();

        hdr.mna_subsequent_opcodes[0].setInvalid();
        hdr.mna_subsequent_opcodes[1].setInvalid();
        hdr.mna_subsequent_opcodes[2].setInvalid();
        hdr.mna_subsequent_opcodes[3].setInvalid();
        hdr.mna_subsequent_opcodes[4].setInvalid();
        hdr.mna_subsequent_opcodes[5].setInvalid();
        hdr.mna_subsequent_opcodes[6].setInvalid();
        hdr.mna_subsequent_opcodes[7].setInvalid();
        hdr.mna_subsequent_opcodes[8].setInvalid();
        hdr.mna_subsequent_opcodes[9].setInvalid();
        hdr.mna_subsequent_opcodes[10].setInvalid();
        hdr.mna_subsequent_opcodes[11].setInvalid();
        hdr.mna_subsequent_opcodes[12].setInvalid();
        hdr.mna_subsequent_opcodes[13].setInvalid();
        hdr.mna_subsequent_opcodes[14].setInvalid();
    }

    action invalidate_second_nas(){
        hdr.nasi_second_nas.setInvalid();

        hdr.mna_initial_opcode_second_nas.setInvalid();

        hdr.mna_subsequent_opcodes_second_nas[0].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[1].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[2].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[3].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[4].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[5].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[6].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[7].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[8].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[9].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[10].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[11].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[12].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[13].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[14].setInvalid();
    }     

    action set_resubmit(){
        ig_dprsr_md.resubmit_type = 1;
    }

    // Keeps track of the current color.
    // If the color changes, a digest will be triggered (return value 1) with the packet counters
    Register<bit<8>, bit<18>>(65535) amm_packet_loss_last_color;
    RegisterAction<bit<8>, bit<18>, bit<8>>(amm_packet_loss_last_color) store_last_received_color = {
        void apply(inout bit<8> value, out bit<8> read_value){
            if (ig_md.amm.color == value){
                // Keep the color
                read_value = 0;
            } else {
                // Switch the color
                value = ig_md.amm.color;
                read_value = 1;
            }
            
        }
    };
    
    // Keeps track of packets colored in color a
    Register<bit<32>, bit<18>>(65535) amm_packet_loss_counter_color_a;
    RegisterAction<bit<32>, bit<18>, bit<32>>(amm_packet_loss_counter_color_a) increment_color_a = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + 1;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<18>, bit<32>>(amm_packet_loss_counter_color_a) read_color_a = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };    

    // Keeps track of packets colored in color b
    Register<bit<32>, bit<18>>(65535) amm_packet_loss_counter_color_b;
    RegisterAction<bit<32>, bit<18>, bit<32>>(amm_packet_loss_counter_color_b) increment_color_b = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + 1;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<18>, bit<32>>(amm_packet_loss_counter_color_b) read_color_b = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };    


    apply {

        if (ig_md.resubmit.processing_stage == 0 && hdr.mna_initial_opcode.isValid()){
            // Processing stage 0, packet see for the firsttime
            mna_first_nas_c.apply(hdr, ig_md, ig_tm_md, ig_intr_md, ig_dprsr_md);
        }
        else if (ig_md.resubmit.processing_stage == 1 || (ig_md.resubmit.processing_stage == 0 && hdr.mna_initial_opcode_second_nas.isValid())){
            // Processing stage 2, either after resubmit, or if no first NAS was present
            mna_second_nas_c.apply(hdr, ig_md, ig_tm_md, ig_intr_md, ig_dprsr_md);
        }

        @stage(18){
            if (ig_md.amm.active){
                ig_md.amm.generate_amm_digest = store_last_received_color.execute(ig_md.amm.flow_identifier);
                if (ig_md.amm.color == 0){
                    ig_md.amm.packets_color_a = increment_color_a.execute(ig_md.amm.flow_identifier);
                    ig_md.amm.packets_color_b = read_color_b.execute(ig_md.amm.flow_identifier);
                } else {
                    ig_md.amm.packets_color_a = read_color_a.execute(ig_md.amm.flow_identifier);
                    ig_md.amm.packets_color_b = increment_color_b.execute(ig_md.amm.flow_identifier);
                }
            }
        }

        if (ig_md.resubmit_needed == 1){
            // This packet will be resubmitted to process the second NAS
            set_resubmit();
        } else {
            // This packet will exit the switch now

            // First NAS follows directly after the top-of-stack label
            // --> Always exposed --> pop it
            invalidate_first_nas();

            if (!hdr.mpls_inbetween_0.isValid()){
                // Invalidate Second NAS if no inbetween labels, i.e., exposed to the top
                invalidate_second_nas();

                if (ig_md.bos_reached == 1){
                    // All MNA and MPLS labels are popped, repair the ether type
                    hdr.ethernet.ether_type = ether_type_t.IPV4;
                }

            }
        };
    }
}