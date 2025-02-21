control MNA_FIRST_NAS(inout header_t hdr, 
            inout ingress_metadata_t ig_md, 
            inout ingress_intrinsic_metadata_for_tm_t ig_tm_md, 
            in ingress_intrinsic_metadata_t ig_intr_md, 
            inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_initial_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_0_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_1_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_2_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_3_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_4_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_5_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_6_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_7_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_8_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_9_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_10_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_11_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_12_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_13_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mna_action_index_14_counter;

   action drop(){
      ig_dprsr_md.drop_ctl = 0x1;
   }

   /*
   The following actions are placeholder actions describing all possible combinations of AD LSEs per opcode
   */
   action action_initial_with_0_ad(){
      debug_mna_initial_counter.count();
      hdr.mna_initial_opcode.data = 1;
   }
   action action_initial_with_1_ad(){
      debug_mna_initial_counter.count();
      hdr.mna_initial_opcode.data = 1;

      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[0].data2 = 15;
   }
   action action_initial_with_2_ad(){
      debug_mna_initial_counter.count();
      hdr.mna_initial_opcode.data = 1;

      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[0].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
   }
   action action_initial_with_3_ad(){
      debug_mna_initial_counter.count();
         hdr.mna_initial_opcode.data = 1;

      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[0].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
   }
   action action_initial_with_4_ad(){
      debug_mna_initial_counter.count();
         hdr.mna_initial_opcode.data = 1;

      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[0].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
   }
   action action_initial_with_5_ad(){
      debug_mna_initial_counter.count();
      hdr.mna_initial_opcode.data = 1;

      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[0].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
   }
   action action_initial_with_6_ad(){
      debug_mna_initial_counter.count();
         hdr.mna_initial_opcode.data = 1;

      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[0].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
   }
   action action_initial_with_7_ad(){
      debug_mna_initial_counter.count();
      hdr.mna_initial_opcode.data = 1;

      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[0].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
   }       

   action action_0_with_0_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
   }
   action action_0_with_1_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
   }
   action action_0_with_2_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
   }
   action action_0_with_3_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
   }
   action action_0_with_4_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
   }
   action action_0_with_5_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
   }
   action action_0_with_6_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
   }
   action action_0_with_7_ad(){
      debug_mna_action_index_0_counter.count();
      hdr.mna_subsequent_opcodes[0].data2 = 1;
      ig_md.processed_subopcodes.index0 = 1;
      hdr.mna_subsequent_opcodes[1].data2 = 15;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
   }

   action action_1_with_0_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
   }
   action action_1_with_1_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
   }
   action action_1_with_2_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
   }
   action action_1_with_3_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
   }
   action action_1_with_4_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
   }
   action action_1_with_5_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
   }
   action action_1_with_6_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
   }
   action action_1_with_7_ad(){
      debug_mna_action_index_1_counter.count();
      hdr.mna_subsequent_opcodes[1].data2 = 1;
      ig_md.processed_subopcodes.index1 = 1;
      hdr.mna_subsequent_opcodes[2].data2 = 15;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_2_with_0_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
   }
   action action_2_with_1_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
   }
   action action_2_with_2_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
   }
   action action_2_with_3_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
   }
   action action_2_with_4_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
   }
   action action_2_with_5_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
   }
   action action_2_with_6_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_2_with_7_ad(){
      debug_mna_action_index_2_counter.count();
      hdr.mna_subsequent_opcodes[2].data2 = 1;
      ig_md.processed_subopcodes.index2 = 1;
      hdr.mna_subsequent_opcodes[3].data2 = 15;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_3_with_0_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
   }
   action action_3_with_1_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
   }
   action action_3_with_2_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
   }
   action action_3_with_3_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
   }
   action action_3_with_4_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
   }
   action action_3_with_5_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_3_with_6_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_3_with_7_ad(){
      debug_mna_action_index_3_counter.count();
      hdr.mna_subsequent_opcodes[3].data2 = 1;
      ig_md.processed_subopcodes.index3 = 1;
      hdr.mna_subsequent_opcodes[4].data2 = 15;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_4_with_0_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
   }
   action action_4_with_1_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
   }
   action action_4_with_2_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
   }
   action action_4_with_3_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
   }
   action action_4_with_4_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_4_with_5_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_4_with_6_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_4_with_7_ad(){
      debug_mna_action_index_4_counter.count();
      hdr.mna_subsequent_opcodes[4].data2 = 1;
      ig_md.processed_subopcodes.index4 = 1;
      hdr.mna_subsequent_opcodes[5].data2 = 15;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
   }

   action action_5_with_0_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
   }
   action action_5_with_1_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
   }
   action action_5_with_2_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
   }
   action action_5_with_3_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_5_with_4_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_5_with_5_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_5_with_6_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
   }
   action action_5_with_7_ad(){
      debug_mna_action_index_5_counter.count();
      hdr.mna_subsequent_opcodes[5].data2 = 1;
      ig_md.processed_subopcodes.index5 = 1;
      hdr.mna_subsequent_opcodes[6].data2 = 15;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
   }

   action action_6_with_0_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
   }
   action action_6_with_1_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
   }
   action action_6_with_2_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_6_with_3_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_6_with_4_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_6_with_5_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
   }
   action action_6_with_6_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
   }
   action action_6_with_7_ad(){
      debug_mna_action_index_6_counter.count();
      hdr.mna_subsequent_opcodes[6].data2 = 1;
      ig_md.processed_subopcodes.index6 = 1;
      hdr.mna_subsequent_opcodes[7].data2 = 15;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
   }

   action action_7_with_0_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
   }
   action action_7_with_1_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_7_with_2_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_7_with_3_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_7_with_4_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
   }
   action action_7_with_5_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
   }
   action action_7_with_6_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
   }
   action action_7_with_7_ad(){
      debug_mna_action_index_7_counter.count();
      hdr.mna_subsequent_opcodes[7].data2 = 1;
      ig_md.processed_subopcodes.index7 = 1;
      hdr.mna_subsequent_opcodes[8].data2 = 15;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
      hdr.mna_subsequent_opcodes[14].data2 = 15;
      ig_md.processed_subopcodes.index14 = 1;
   }
   action action_8_with_0_ad(){
      debug_mna_action_index_8_counter.count();
      hdr.mna_subsequent_opcodes[8].data2 = 1;
      ig_md.processed_subopcodes.index8 = 1;
   }
   action action_8_with_1_ad(){
      debug_mna_action_index_8_counter.count();
      hdr.mna_subsequent_opcodes[8].data2 = 1;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_8_with_2_ad(){
      debug_mna_action_index_8_counter.count();
      hdr.mna_subsequent_opcodes[8].data2 = 1;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_8_with_3_ad(){
      debug_mna_action_index_8_counter.count();
      hdr.mna_subsequent_opcodes[8].data2 = 1;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
   }
   action action_8_with_4_ad(){
      debug_mna_action_index_8_counter.count();
      hdr.mna_subsequent_opcodes[8].data2 = 1;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
   }
   action action_8_with_5_ad(){
      debug_mna_action_index_8_counter.count();
      hdr.mna_subsequent_opcodes[8].data2 = 1;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
   }
   action action_8_with_6_ad(){
      debug_mna_action_index_8_counter.count();
      hdr.mna_subsequent_opcodes[8].data2 = 1;
      ig_md.processed_subopcodes.index8 = 1;
      hdr.mna_subsequent_opcodes[9].data2 = 15;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
      hdr.mna_subsequent_opcodes[14].data2 = 15;
      ig_md.processed_subopcodes.index14 = 1;
   }
   action action_9_with_0_ad(){
      debug_mna_action_index_9_counter.count();
      hdr.mna_subsequent_opcodes[9].data2 = 1;
      ig_md.processed_subopcodes.index9 = 1;
   }
   action action_9_with_1_ad(){
      debug_mna_action_index_9_counter.count();
      hdr.mna_subsequent_opcodes[9].data2 = 1;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_9_with_2_ad(){
      debug_mna_action_index_9_counter.count();
      hdr.mna_subsequent_opcodes[9].data2 = 1;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
   }
   action action_9_with_3_ad(){
      debug_mna_action_index_9_counter.count();
      hdr.mna_subsequent_opcodes[9].data2 = 1;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
   }
   action action_9_with_4_ad(){
      debug_mna_action_index_9_counter.count();
      hdr.mna_subsequent_opcodes[9].data2 = 1;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
   }
   action action_9_with_5_ad(){
      debug_mna_action_index_9_counter.count();
      hdr.mna_subsequent_opcodes[9].data2 = 1;
      ig_md.processed_subopcodes.index9 = 1;
      hdr.mna_subsequent_opcodes[10].data2 = 15;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
      hdr.mna_subsequent_opcodes[14].data2 = 15;
      ig_md.processed_subopcodes.index14 = 1;
   }
   action action_10_with_0_ad(){
      debug_mna_action_index_10_counter.count();
      hdr.mna_subsequent_opcodes[10].data2 = 1;
      ig_md.processed_subopcodes.index10 = 1;
   }
   action action_10_with_1_ad(){
      debug_mna_action_index_10_counter.count();
      hdr.mna_subsequent_opcodes[10].data2 = 1;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
   }
   action action_10_with_2_ad(){
      debug_mna_action_index_10_counter.count();
      hdr.mna_subsequent_opcodes[10].data2 = 1;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
   }
   action action_10_with_3_ad(){
      debug_mna_action_index_10_counter.count();
      hdr.mna_subsequent_opcodes[10].data2 = 1;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
   }
   action action_10_with_4_ad(){
      debug_mna_action_index_10_counter.count();
      hdr.mna_subsequent_opcodes[10].data2 = 1;
      ig_md.processed_subopcodes.index10 = 1;
      hdr.mna_subsequent_opcodes[11].data2 = 15;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
      hdr.mna_subsequent_opcodes[14].data2 = 15;
      ig_md.processed_subopcodes.index14 = 1;
   }
   action action_11_with_0_ad(){
      debug_mna_action_index_11_counter.count();
      hdr.mna_subsequent_opcodes[11].data2 = 1;
      ig_md.processed_subopcodes.index11 = 1;
   }
   action action_11_with_1_ad(){
      debug_mna_action_index_11_counter.count();
      hdr.mna_subsequent_opcodes[11].data2 = 1;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
   }
   action action_11_with_2_ad(){
      debug_mna_action_index_11_counter.count();
      hdr.mna_subsequent_opcodes[11].data2 = 1;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
   }
   action action_11_with_3_ad(){
      debug_mna_action_index_11_counter.count();
      hdr.mna_subsequent_opcodes[11].data2 = 1;
      ig_md.processed_subopcodes.index11 = 1;
      hdr.mna_subsequent_opcodes[12].data2 = 15;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
      hdr.mna_subsequent_opcodes[14].data2 = 15;
      ig_md.processed_subopcodes.index14 = 1;
   }
   action action_12_with_0_ad(){
      debug_mna_action_index_12_counter.count();
      hdr.mna_subsequent_opcodes[12].data2 = 1;
      ig_md.processed_subopcodes.index12 = 1;
   }
   action action_12_with_1_ad(){
      debug_mna_action_index_12_counter.count();
      hdr.mna_subsequent_opcodes[12].data2 = 1;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
   }
   action action_12_with_2_ad(){
      debug_mna_action_index_12_counter.count();
      hdr.mna_subsequent_opcodes[12].data2 = 1;
      ig_md.processed_subopcodes.index12 = 1;
      hdr.mna_subsequent_opcodes[13].data2 = 15;
      ig_md.processed_subopcodes.index13 = 1;
      hdr.mna_subsequent_opcodes[14].data2 = 15;
      ig_md.processed_subopcodes.index14 = 1;
   }
   action action_13_with_0_ad(){
      debug_mna_action_index_13_counter.count();
      hdr.mna_subsequent_opcodes[13].data2 = 1;
      ig_md.processed_subopcodes.index13 = 1;
   }
   action action_13_with_1_ad(){
      debug_mna_action_index_13_counter.count();
      hdr.mna_subsequent_opcodes[13].data2 = 1;
      ig_md.processed_subopcodes.index13 = 1;
      hdr.mna_subsequent_opcodes[14].data2 = 15;
      ig_md.processed_subopcodes.index14 = 1;
   }
   action action_14_with_0_ad(){
      debug_mna_action_index_14_counter.count();
      hdr.mna_subsequent_opcodes[14].data2 = 1;
      ig_md.processed_subopcodes.index14 = 1;
   }

   /* 
   Actions for network slicing
   */
   action action_initial_nrp_with_0_ad(){
      debug_mna_initial_counter.count();
      ig_md.nrp.active = true;
      ig_md.nrp.identifier = (bit<16>)hdr.mna_initial_opcode.data;
   }

   action action_0_nrp_with_0_ad(){
      debug_mna_action_index_0_counter.count();
      ig_md.nrp.active = true;
      ig_md.nrp.identifier = hdr.mna_subsequent_opcodes[0].data;
   }
   action action_1_nrp_with_0_ad(){
      debug_mna_action_index_1_counter.count();
      ig_md.nrp.active = true;
      ig_md.nrp.identifier = hdr.mna_subsequent_opcodes[1].data;
   }
   action action_2_nrp_with_0_ad(){
      debug_mna_action_index_2_counter.count();
      ig_md.nrp.active = true;
      ig_md.nrp.identifier = hdr.mna_subsequent_opcodes[2].data;
   }

   /*
   Actions for packet loss measurement with AMM
   */
   action action_0_AMM_color_a_with_0_ad(){
      debug_mna_action_index_0_counter.count();
      ig_md.amm.color = 0;
      ig_md.amm.active = true;
      ig_md.amm.flow_identifier = hdr.mna_subsequent_opcodes[0].data ++ hdr.mna_subsequent_opcodes[0].data2[3:2];
   }
   action action_0_AMM_color_b_with_0_ad(){
      debug_mna_action_index_0_counter.count();
      ig_md.amm.color = 1;
      ig_md.amm.active = true;
      ig_md.amm.flow_identifier = hdr.mna_subsequent_opcodes[0].data ++ hdr.mna_subsequent_opcodes[0].data2[3:2];      
   }
   
    
   action action_1_AMM_color_a_with_0_ad(){
      debug_mna_action_index_1_counter.count();
      ig_md.amm.color = 0;
      ig_md.amm.active = true;
      ig_md.amm.flow_identifier = hdr.mna_subsequent_opcodes[1].data ++ hdr.mna_subsequent_opcodes[1].data2[3:2];
   }
   action action_1_AMM_color_b_with_0_ad(){
      debug_mna_action_index_1_counter.count();
      ig_md.amm.color = 1;
      ig_md.amm.active = true;
      ig_md.amm.flow_identifier = hdr.mna_subsequent_opcodes[1].data ++ hdr.mna_subsequent_opcodes[1].data2[3:2];      
   }

   action drop_initial(){
      ig_dprsr_md.drop_ctl = 0x1;

      debug_mna_initial_counter.count();
   }

   table mna_initial_opcode {
      key = {
            hdr.mna_initial_opcode.opcode: exact;
            hdr.mna_initial_opcode.nal: exact;
            hdr.mna_initial_opcode.data: ternary;
      }
     actions = {
           action_initial_nrp_with_0_ad;
           action_initial_with_0_ad;
           action_initial_with_1_ad;
           action_initial_with_2_ad;
           action_initial_with_3_ad;
           action_initial_with_4_ad;
           action_initial_with_5_ad;
           action_initial_with_6_ad;
           action_initial_with_7_ad;          
            drop_initial;
      }
      size = 128;
      counters = debug_mna_initial_counter;
   }

   table mna_subsequent_opcode_14 {
      key = {
            hdr.mna_subsequent_opcodes[14].opcode: exact;
            hdr.mna_subsequent_opcodes[14].nal: exact;
            hdr.mna_subsequent_opcodes[14].data: ternary;
            hdr.mna_subsequent_opcodes[14].data2: ternary;
      }
     actions = {
           action_14_with_0_ad;            
      }
      size = 128;
      counters = debug_mna_action_index_14_counter;
   }

   table mna_subsequent_opcode_13 {
      key = {
            hdr.mna_subsequent_opcodes[13].opcode: exact;
            hdr.mna_subsequent_opcodes[13].nal: exact;
            hdr.mna_subsequent_opcodes[13].data: ternary;
            hdr.mna_subsequent_opcodes[13].data2: ternary;
      }
     actions = {
           action_13_with_0_ad;
           action_13_with_1_ad;             
      }
      size = 128;
      counters = debug_mna_action_index_13_counter;
   }

   table mna_subsequent_opcode_12 {
      key = {
            hdr.mna_subsequent_opcodes[12].opcode: exact;
            hdr.mna_subsequent_opcodes[12].nal: exact;
            hdr.mna_subsequent_opcodes[12].data: ternary;
            hdr.mna_subsequent_opcodes[12].data2: ternary;
      }
     actions = {
           action_12_with_0_ad;
           action_12_with_1_ad;
           action_12_with_2_ad;             
      }
      size = 128;
      counters = debug_mna_action_index_12_counter;
   }

   table mna_subsequent_opcode_11 {
      key = {
            hdr.mna_subsequent_opcodes[11].opcode: exact;
            hdr.mna_subsequent_opcodes[11].nal: exact;
            hdr.mna_subsequent_opcodes[11].data: ternary;
            hdr.mna_subsequent_opcodes[11].data2: ternary;
      }
     actions = {
           action_11_with_0_ad;
           action_11_with_1_ad;
           action_11_with_2_ad;
           action_11_with_3_ad;             
      }
      size = 128;
      counters = debug_mna_action_index_11_counter;
   }

   table mna_subsequent_opcode_10 {
      key = {
            hdr.mna_subsequent_opcodes[10].opcode: exact;
            hdr.mna_subsequent_opcodes[10].nal: exact;
            hdr.mna_subsequent_opcodes[10].data: ternary;
            hdr.mna_subsequent_opcodes[10].data2: ternary;
      }
     actions = {
           action_10_with_0_ad;
           action_10_with_1_ad;
           action_10_with_2_ad;
           action_10_with_3_ad;
           action_10_with_4_ad;            
      }
      size = 128;
      counters = debug_mna_action_index_10_counter;
   }

   table mna_subsequent_opcode_9 {
      key = {
            hdr.mna_subsequent_opcodes[9].opcode: exact;
            hdr.mna_subsequent_opcodes[9].nal: exact;
            hdr.mna_subsequent_opcodes[9].data: ternary;
            hdr.mna_subsequent_opcodes[9].data2: ternary;
      }
     actions = {
           action_9_with_0_ad;
           action_9_with_1_ad;
           action_9_with_2_ad;
           action_9_with_3_ad;
           action_9_with_4_ad;
           action_9_with_5_ad;           
      }
      counters = debug_mna_action_index_9_counter;
      size = 128;
   }

   table mna_subsequent_opcode_8 {
      key = {
            hdr.mna_subsequent_opcodes[8].opcode: exact;
            hdr.mna_subsequent_opcodes[8].nal: exact;
            hdr.mna_subsequent_opcodes[8].data: ternary;
            hdr.mna_subsequent_opcodes[8].data2: ternary;
      }
     actions = {
           action_8_with_0_ad;
           action_8_with_1_ad;
           action_8_with_2_ad;
           action_8_with_3_ad;
           action_8_with_4_ad;
           action_8_with_5_ad;
           action_8_with_6_ad;             
      }
      size = 128;
      counters = debug_mna_action_index_8_counter;
   }

   table mna_subsequent_opcode_7 {
      key = {
            hdr.mna_subsequent_opcodes[7].opcode: exact;
            hdr.mna_subsequent_opcodes[7].nal: exact;
            hdr.mna_subsequent_opcodes[7].data: ternary;
            hdr.mna_subsequent_opcodes[7].data2: ternary;
      }
     actions = {
           action_7_with_0_ad;
           action_7_with_1_ad;
           action_7_with_2_ad;
           action_7_with_3_ad;
           action_7_with_4_ad;
           action_7_with_5_ad;
           action_7_with_6_ad;
           action_7_with_7_ad;          
      }
      size = 128;
      counters = debug_mna_action_index_7_counter;
   }

   table mna_subsequent_opcode_6 {
      key = {
            hdr.mna_subsequent_opcodes[6].opcode: exact;
            hdr.mna_subsequent_opcodes[6].nal: exact;
            hdr.mna_subsequent_opcodes[6].data: ternary;
            hdr.mna_subsequent_opcodes[6].data2: ternary;
      }
     actions = {
           action_6_with_0_ad;
           action_6_with_1_ad;
           action_6_with_2_ad;
           action_6_with_3_ad;
           action_6_with_4_ad;
           action_6_with_5_ad;
           action_6_with_6_ad;
           action_6_with_7_ad;         
      }
      size = 128;
      counters = debug_mna_action_index_6_counter;
   }


   table mna_subsequent_opcode_5 {
      key = {
            hdr.mna_subsequent_opcodes[5].opcode: exact;
            hdr.mna_subsequent_opcodes[5].nal: exact;
            hdr.mna_subsequent_opcodes[5].data: ternary;
            hdr.mna_subsequent_opcodes[5].data2: ternary;
      }
     actions = {
           action_5_with_0_ad;
           action_5_with_1_ad;
           action_5_with_2_ad;
           action_5_with_3_ad;
           action_5_with_4_ad;
           action_5_with_5_ad;
           action_5_with_6_ad;
           action_5_with_7_ad;           
      }
      size = 128;
      counters = debug_mna_action_index_5_counter;
   }

   table mna_subsequent_opcode_4 {
      key = {
            hdr.mna_subsequent_opcodes[4].opcode: exact;
            hdr.mna_subsequent_opcodes[4].nal: exact;
            hdr.mna_subsequent_opcodes[4].data: ternary;
            hdr.mna_subsequent_opcodes[4].data2: ternary;
      }
     actions = {
           action_4_with_0_ad;
           action_4_with_1_ad;
           action_4_with_2_ad;
           action_4_with_3_ad;
           action_4_with_4_ad;
           action_4_with_5_ad;
           action_4_with_6_ad;
           action_4_with_7_ad;          
      }
      size = 128;
      counters = debug_mna_action_index_4_counter;
   }

   table mna_subsequent_opcode_3 {
      key = {
            hdr.mna_subsequent_opcodes[3].opcode: exact;
            hdr.mna_subsequent_opcodes[3].nal: exact;
            hdr.mna_subsequent_opcodes[3].data: ternary;
            hdr.mna_subsequent_opcodes[3].data2: ternary;
      }
     actions = {
           action_3_with_0_ad;
           action_3_with_1_ad;
           action_3_with_2_ad;
           action_3_with_3_ad;
           action_3_with_4_ad;
           action_3_with_5_ad;
           action_3_with_6_ad;
           action_3_with_7_ad;
      }
      size = 128;
      counters = debug_mna_action_index_3_counter;
   }

   table mna_subsequent_opcode_2 {
      key = {
            hdr.mna_subsequent_opcodes[2].opcode: exact;
            hdr.mna_subsequent_opcodes[2].nal: exact;
            hdr.mna_subsequent_opcodes[2].data: ternary;
            hdr.mna_subsequent_opcodes[2].data2: ternary;
      }
     actions = {
           action_2_with_0_ad;
           action_2_with_1_ad;
           action_2_with_2_ad;
           action_2_with_3_ad;
           action_2_with_4_ad;
           action_2_with_5_ad;
           action_2_with_6_ad;
           action_2_with_7_ad;
           action_2_nrp_with_0_ad;
      }
      size = 128;
      counters = debug_mna_action_index_2_counter;
   }

   table mna_subsequent_opcode_1 {
      key = {
            hdr.mna_subsequent_opcodes[1].opcode: exact;
            hdr.mna_subsequent_opcodes[1].nal: exact;
            hdr.mna_subsequent_opcodes[1].data: ternary;
            hdr.mna_subsequent_opcodes[1].data2: ternary;
      }
     actions = {
           action_1_with_0_ad;
           action_1_with_1_ad;
           action_1_with_2_ad;
           action_1_with_3_ad;
           action_1_with_4_ad;
           action_1_with_5_ad;
           action_1_with_6_ad;
           action_1_with_7_ad;
           action_1_AMM_color_a_with_0_ad;         
           action_1_AMM_color_b_with_0_ad;
           action_1_nrp_with_0_ad;
      }
      size = 128;
      counters = debug_mna_action_index_1_counter;
   }

   table mna_subsequent_opcode_0 {
      key = {
            hdr.mna_subsequent_opcodes[0].opcode: exact;
            hdr.mna_subsequent_opcodes[0].nal: exact;
            hdr.mna_subsequent_opcodes[0].data: ternary;
            hdr.mna_subsequent_opcodes[0].data2: ternary;
      }
     actions = {
           action_0_with_0_ad;
           action_0_with_1_ad;
           action_0_with_2_ad;
           action_0_with_3_ad;
           action_0_with_4_ad;
           action_0_with_5_ad;
           action_0_with_6_ad;
           action_0_with_7_ad;
           action_0_AMM_color_a_with_0_ad;         
           action_0_AMM_color_b_with_0_ad;
           action_0_nrp_with_0_ad;
      }
      size = 128;
      counters = debug_mna_action_index_0_counter;
   }   
        
    apply {

        if (hdr.mna_initial_opcode.isValid()){
            if (mna_initial_opcode.apply().miss){
                  if (hdr.mna_initial_opcode.unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
            }
        }

         if (hdr.mna_subsequent_opcodes[0].isValid()) {
            // If this entry was not already processed by a previous one
            if (ig_md.processed_subopcodes.index0 == 0) {
               if (mna_subsequent_opcode_0.apply().miss){
                  if (hdr.mna_subsequent_opcodes[0].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
               }
            }
         }

         if (hdr.mna_subsequent_opcodes[1].isValid()) {
            if (ig_md.processed_subopcodes.index1 == 0) {
               if (mna_subsequent_opcode_1.apply().miss){
                  if (hdr.mna_subsequent_opcodes[1].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
               }
            }
         }


         if (hdr.mna_subsequent_opcodes[2].isValid()) {
            if (ig_md.processed_subopcodes.index2 == 0) {
               if (mna_subsequent_opcode_2.apply().miss){
                  if (hdr.mna_subsequent_opcodes[2].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
               }
            }
         }
         

         if (hdr.mna_subsequent_opcodes[3].isValid()) {
            if (ig_md.processed_subopcodes.index3 == 0) {
               if(mna_subsequent_opcode_3.apply().miss){
                  if (hdr.mna_subsequent_opcodes[3].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
               }
            }
         }

         if (hdr.mna_subsequent_opcodes[4].isValid()) {
            if (ig_md.processed_subopcodes.index4 == 0) {
               if (mna_subsequent_opcode_4.apply().miss){
                  if (hdr.mna_subsequent_opcodes[4].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
               }
            }
         }


         if (hdr.mna_subsequent_opcodes[5].isValid()) {
            if (ig_md.processed_subopcodes.index5 == 0) {
               if (mna_subsequent_opcode_5.apply().miss){
                  if (hdr.mna_subsequent_opcodes[5].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
               }
            }
         }
            

         if (hdr.mna_subsequent_opcodes[6].isValid()) {
            if (ig_md.processed_subopcodes.index6 == 0) {
               if (mna_subsequent_opcode_6.apply().miss){
                  if (hdr.mna_subsequent_opcodes[6].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
               }
            }
         }

        if (hdr.mna_subsequent_opcodes[7].isValid()) {
            if (ig_md.processed_subopcodes.index7 == 0) {
                if (mna_subsequent_opcode_7.apply().miss) {
                  if (hdr.mna_subsequent_opcodes[7].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }


        if (hdr.mna_subsequent_opcodes[8].isValid()) {
            if (ig_md.processed_subopcodes.index8 == 0) {
                if (mna_subsequent_opcode_8.apply().miss) {
                  if (hdr.mna_subsequent_opcodes[8].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }

        if (hdr.mna_subsequent_opcodes[9].isValid()) {
            if (ig_md.processed_subopcodes.index9 == 0) {
                if (mna_subsequent_opcode_9.apply().miss){
                  if (hdr.mna_subsequent_opcodes[9].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }

        if (hdr.mna_subsequent_opcodes[10].isValid()) {
            if (ig_md.processed_subopcodes.index10 == 0) {
                if (mna_subsequent_opcode_10.apply().miss){
                  if (hdr.mna_subsequent_opcodes[10].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }

        if (hdr.mna_subsequent_opcodes[11].isValid()) {
            if (ig_md.processed_subopcodes.index11 == 0) {
                if (mna_subsequent_opcode_11.apply().miss){
                  if (hdr.mna_subsequent_opcodes[11].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }

        if (hdr.mna_subsequent_opcodes[12].isValid()) {
            if (ig_md.processed_subopcodes.index12 == 0) {
                if (mna_subsequent_opcode_12.apply().miss){
                  if (hdr.mna_subsequent_opcodes[12].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }


        if (hdr.mna_subsequent_opcodes[13].isValid()) {
            if (ig_md.processed_subopcodes.index13 == 0) {
                if (mna_subsequent_opcode_13.apply().miss){
                  if (hdr.mna_subsequent_opcodes[13].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }
        
        if (hdr.mna_subsequent_opcodes[14].isValid()) {
            if (ig_md.processed_subopcodes.index14 == 0) {
                if (mna_subsequent_opcode_14.apply().miss){
                  if (hdr.mna_subsequent_opcodes[14].unknown_action_handling == 1){
                     // Drop
                     ig_dprsr_md.drop_ctl = 1;
                  }
                }
            }
        }

        if (hdr.mna_initial_opcode_second_nas.isValid()){
            // Resubmit for a present second NAS
            ig_md.resubmit.processing_stage = 1;
            ig_md.resubmit_needed = 1;
        }
    }
}