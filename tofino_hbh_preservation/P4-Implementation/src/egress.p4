control egress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_counter2;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_counter3;
    
    action drop(){
        eg_intr_md_for_dprsr.drop_ctl = 0x1;
    }

    action move_1_label_up(){
        debug_counter3.count();

        // Move the mpls forwarding label up that succeeds the last NAS
        hdr.shifted_mpls_segments[0].setValid();
        hdr.shifted_mpls_segments[0] = hdr.intermediate_segments_stack[0];
        hdr.intermediate_segments_stack[0].setInvalid();

        eg_md.moved_bos_value = hdr.shifted_mpls_segments[0].bos;

    }
    action move_2_label_up(){
        debug_counter3.count();
        hdr.shifted_mpls_segments[0].setValid();
        hdr.shifted_mpls_segments[0] = hdr.intermediate_segments_stack[0];
        hdr.intermediate_segments_stack[0].setInvalid();

        hdr.shifted_mpls_segments[1].setValid();
        hdr.shifted_mpls_segments[1] = hdr.intermediate_segments_stack[1];
        hdr.intermediate_segments_stack[1].setInvalid();

        eg_md.moved_bos_value = hdr.shifted_mpls_segments[1].bos;        
    }

    action move_3_label_up(){
        debug_counter3.count();
        hdr.shifted_mpls_segments[0].setValid();
        hdr.shifted_mpls_segments[0] = hdr.intermediate_segments_stack[0];
        hdr.intermediate_segments_stack[0].setInvalid();

        hdr.shifted_mpls_segments[1].setValid();
        hdr.shifted_mpls_segments[1] = hdr.intermediate_segments_stack[1];
        hdr.intermediate_segments_stack[1].setInvalid();

        hdr.shifted_mpls_segments[2].setValid();
        hdr.shifted_mpls_segments[2] = hdr.intermediate_segments_stack[2];
        hdr.intermediate_segments_stack[2].setInvalid();        

        eg_md.moved_bos_value = hdr.shifted_mpls_segments[2].bos;               
    }
    action move_4_label_up(){
        debug_counter3.count();

        hdr.shifted_mpls_segments[0].setValid();
        hdr.shifted_mpls_segments[0] = hdr.intermediate_segments_stack[0];
        hdr.intermediate_segments_stack[0].setInvalid();

        hdr.shifted_mpls_segments[1].setValid();
        hdr.shifted_mpls_segments[1] = hdr.intermediate_segments_stack[1];
        hdr.intermediate_segments_stack[1].setInvalid();

        hdr.shifted_mpls_segments[2].setValid();
        hdr.shifted_mpls_segments[2] = hdr.intermediate_segments_stack[2];
        hdr.intermediate_segments_stack[2].setInvalid();        

        hdr.shifted_mpls_segments[3].setValid();
        hdr.shifted_mpls_segments[3] = hdr.intermediate_segments_stack[3];
        hdr.intermediate_segments_stack[3].setInvalid();         

        eg_md.moved_bos_value = hdr.shifted_mpls_segments[3].bos;   

    }


    action unset_bos_0(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[0].bos = 0;
    }   

    action unset_bos_1(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[1].bos = 0;
    }   

    action unset_bos_2(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[2].bos = 0;
    }  
    action unset_bos_3(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[3].bos = 0;
    }   

    action unset_bos_4(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[4].bos = 0;
    }   

    action unset_bos_5(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[5].bos = 0;
    }  
    action unset_bos_6(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[6].bos = 0;
    }  
    action unset_bos_7(){
        debug_counter2.count();
        hdr.shifted_mpls_segments[7].bos = 0;
    }      

    action set_bos_0(){
        hdr.mna_initial_opcode.bos = 1;
    }

    action set_bos_1(){
        hdr.mna_subsequent_opcodes[0].bos = 1;
    }    

    action set_bos_2(){
        hdr.mna_subsequent_opcodes[1].bos = 1;
    }    

    action set_bos_3(){
        hdr.mna_subsequent_opcodes[2].bos = 1;
    }    

    action set_bos_4(){
        hdr.mna_subsequent_opcodes[3].bos = 1;
    }    
    action set_bos_5(){
        hdr.mna_subsequent_opcodes[4].bos = 1;
    }

    action set_bos_6(){
        hdr.mna_subsequent_opcodes[5].bos = 1;
    }    

    action set_bos_7(){
        hdr.mna_subsequent_opcodes[6].bos = 1;
    }    

    action set_bos_8(){
        hdr.mna_subsequent_opcodes[7].bos = 1;
    }    

    action set_bos_9(){
        hdr.mna_subsequent_opcodes[8].bos = 1;
    }      
    action set_bos_10(){
        hdr.mna_subsequent_opcodes[9].bos = 1;
    }

    action set_bos_11(){
        hdr.mna_subsequent_opcodes[10].bos = 1;
    }    

    action set_bos_12(){
        hdr.mna_subsequent_opcodes[11].bos = 1;
    }    

    action set_bos_13(){
        hdr.mna_subsequent_opcodes[12].bos = 1;
    }    

    action set_bos_14(){
        hdr.mna_subsequent_opcodes[13].bos = 1;
    }      

    action set_bos_15(){
        hdr.mna_subsequent_opcodes[14].bos = 1;
    }          
   

    table hbh_label_preservation {
        key = {
            hdr.i2e_bridge.number_of_shifted_mpls_labels: exact;
        }
        actions = {
            move_1_label_up;
            move_2_label_up;
            move_3_label_up;
            move_4_label_up;
        }
        size = 8;
        default_action = move_1_label_up;
        counters = debug_counter3;
    }

    table unset_bos_in_mpls {
        key = {
            hdr.i2e_bridge.number_of_shifted_mpls_labels: exact;
        }
        size = 8;
        actions = {
            unset_bos_0;
            unset_bos_1;
            unset_bos_2;
            unset_bos_3;
            unset_bos_4;
            unset_bos_5;
            unset_bos_6;
            unset_bos_7;
        }
        counters = debug_counter2;
    }

    table set_bos_in_hbh {
        key = {
            hdr.mna_initial_opcode.nasl: exact;
        }
        size = 16;
        actions = {
            set_bos_0;
            set_bos_1;
            set_bos_2;
            set_bos_3;
            set_bos_4;
            set_bos_5;
            set_bos_6;
            set_bos_7;
            set_bos_8;
            set_bos_9;
            set_bos_10;
            set_bos_11;
            set_bos_12;
            set_bos_13;
            set_bos_14;
            set_bos_15;
        }
    }

    apply {
        if (hdr.i2e_bridge.do_hbh_preservation == 1){

            hbh_label_preservation.apply();

            if (eg_md.moved_bos_value == 1){
                // The BoS was moved to the top. We need to fix it by unsetting it in the shifted segment and by setting it in the HBH NAS
                set_bos_in_hbh.apply();
                unset_bos_in_mpls.apply();
            }
        }
    }
}
