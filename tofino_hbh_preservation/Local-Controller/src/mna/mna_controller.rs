use log::info;
use std::cmp;
use std::{collections::HashMap, sync::Arc};

use rbfrt::{
    table::MatchValue,
    table::{self, ToBytes},
    SwitchConnection,
};

pub const MPLS_LOOKUP_TABLE: &str = "ingress.mpls_c.mpls_lookup_table";
const DEBUG_DIGEST_NAME: &str = "pipe.SwitchIngressDeparser.digest_valid_headers";


#[derive(Clone, Debug)]
pub struct MNAController {
    mpls_label_to_egress_port_mapping: HashMap<u32, u32>,
}

impl MNAController {
    pub fn new(mpls_label_to_egress_port_mapping: HashMap<u32, u32>) -> MNAController {
        MNAController {
            mpls_label_to_egress_port_mapping
        }
    }

    pub fn init_mpls_lookup(&self) -> Vec<table::Request> {
        let mut table_entries = vec![];

        for (mpls_label, egress_port) in &self.mpls_label_to_egress_port_mapping {
            let tbl_request = table::Request::new(MPLS_LOOKUP_TABLE)
                .match_key("ig_md.resubmit_needed", MatchValue::exact(0))
                .match_key("hdr.mpls.label", MatchValue::exact(*mpls_label))
                .action("ingress.mpls_c.forward")
                .action_data("port", *egress_port);

            table_entries.push(tbl_request);

            let tbl_request = table::Request::new("ingress.mpls_c.mpls_table")
                .match_key("hdr.mpls.label", MatchValue::exact(*mpls_label))
                .match_key("ig_md.resubmit_needed", MatchValue::exact(0))
                .action("ingress.mpls_c.mpls_pop_label");
            table_entries.push(tbl_request);
        }

        table_entries
    }

    pub fn init_constant_entries(&self) -> Vec<table::Request> {
        let mut table_entries = vec![];

        // Drop on 0 TTL
        let tbl_request = table::Request::new("ingress.mpls_c.verify_ttl")
            .match_key("hdr.mpls.ttl", MatchValue::exact(0))
            .action("ingress.mpls_c.drop");
        table_entries.push(tbl_request);

        // Scope entries, invalidate Select scopes
        let tbl_request = table::Request::new("ingress.mpls_c.mna_c.mna_scope_first_nas")
            .match_key("hdr.mna_nasi.label",MatchValue::exact(4))
            .match_key("hdr.mna_initial_opcode.ihs",MatchValue::exact(2))
            .action("ingress.mpls_c.mna_c.invalidate_first_nas");
        table_entries.push(tbl_request);
        let tbl_request = table::Request::new("ingress.mpls_c.mna_c.mna_scope_second_nas")
            .match_key("hdr.mna_nasi_second_nas.label",MatchValue::exact(4))
            .match_key("hdr.mna_initial_opcode_second_nas.ihs",MatchValue::exact(2))
            .action("ingress.mpls_c.mna_c.invalidate_second_nas");
        table_entries.push(tbl_request);

        // Bottom Of Stack Repair entries
        for nasl_value in 0..16 {
            let action_name = format!("egress.set_bos_{nasl_value}");

            let tbl_request = table::Request::new("egress.set_bos_in_hbh")
                .match_key("hdr.mna_initial_opcode.nasl",MatchValue::exact(nasl_value))
                .action(&action_name);
            table_entries.push(tbl_request);        
        }
        for shifted_labels in 0..8 {

            let action_name = format!("egress.unset_bos_{shifted_labels}");

            let tbl_request = table::Request::new("egress.unset_bos_in_mpls")
            .match_key("hdr.i2e_bridge.number_of_shifted_mpls_labels", MatchValue::exact(shifted_labels+1))
            .action(&action_name);
            table_entries.push(tbl_request);
        }        

        // HBH NAS Preservation entries
        for shifted_labels in 1..5 {

            let action_name = format!("egress.move_{shifted_labels}_label_up");

            let tbl_request = table::Request::new("egress.hbh_label_preservation")
                .match_key("hdr.i2e_bridge.number_of_shifted_mpls_labels",MatchValue::exact(shifted_labels))
                .action(&action_name);
            table_entries.push(tbl_request);
        } 

        table_entries
    }

    pub fn init_opcode_entries(&self) -> Vec<table::Request> {
        let mut table_entries = vec![];

        // Initial opcode entries
        let tbl_request =
            table::Request::new("ingress.mpls_c.mna_c.mna_first_nas_c.mna_initial_opcode")
                .match_key("hdr.mna_initial_opcode.opcode", MatchValue::exact(64))
                .match_key("hdr.mna_initial_opcode.data", MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                .action("ingress.mpls_c.mna_c.mna_first_nas_c.action_initial_with_0_ad");
        table_entries.push(tbl_request);

        // HBH NAS Preservation: Move more labels to the top
        for no_labels in 1..5 {
            let action_name = format!("ingress.mpls_c.mna_c.mna_first_nas_c.move_{no_labels}_label_up");
            let tbl_request = table::Request::new("ingress.mpls_c.mna_c.mna_first_nas_c.mna_initial_opcode")
                .match_key("hdr.mna_initial_opcode.opcode",MatchValue::exact(52))
                .match_key("hdr.mna_initial_opcode.data", MatchValue::ternary(no_labels, 0b1111111111111))  // Ternary match 1,2^13-1 is an exact match
                .action(&action_name);
            table_entries.push(tbl_request);
        }
        for no_labels in 1..5 {
            let action_name = format!("ingress.mpls_c.mna_c.mna_second_nas_c.move_{no_labels}_label_up");
            let tbl_request = table::Request::new("ingress.mpls_c.mna_c.mna_second_nas_c.mna_initial_opcode")
                .match_key("hdr.mna_initial_opcode_second_nas.opcode",MatchValue::exact(52))
                .match_key("hdr.mna_initial_opcode_second_nas.data", MatchValue::ternary(no_labels, 0b1111111111111))  // Ternary match 1,2^13-1 is an exact match
                .action(&action_name);
            table_entries.push(tbl_request);
        }

        for ad_count in 0..1 {
            let action = format!("ingress.mpls_c.mna_c.mna_second_nas_c.action_initial_with_{ad_count}_ad");
            let tbl_request =
            table::Request::new("ingress.mpls_c.mna_c.mna_second_nas_c.mna_initial_opcode")
                .match_key(
                    "hdr.mna_initial_opcode_second_nas.opcode",
                    MatchValue::exact(64),
                )
                .match_key(
                    "hdr.mna_initial_opcode_second_nas.data",
                    MatchValue::ternary(0, 0),
                ) // Ternary match 0,0 is a wildcard match
                .match_key("hdr.mna_initial_opcode_second_nas.nal", MatchValue::exact(ad_count))
                .action(&action);
        table_entries.push(tbl_request);
        }

        // Default network actions for HBH scope
        for network_action_index in 0..15 {
            let control_hbh = "ingress.mpls_c.mna_c.mna_first_nas_c";

            let table_name = format!("{control_hbh}.mna_subsequent_opcode_{network_action_index}");

            let max_ad = 1; //cmp::min(15 - network_action_index, 8);

            for ad_count in 0..max_ad {
                let action_name =
                    format!("{control_hbh}.action_{network_action_index}_with_{ad_count}_ad");
                let key1 = format!("hdr.mna_subsequent_opcodes${network_action_index}.opcode");
                let key2 = format!("hdr.mna_subsequent_opcodes${network_action_index}.nal");
                let key3 = format!("hdr.mna_subsequent_opcodes${network_action_index}.data");
                let key4 = format!("hdr.mna_subsequent_opcodes${network_action_index}.data2");

                let tbl_request = table::Request::new(&table_name)
                    .match_key(&key1, MatchValue::exact(64))
                    .match_key(&key2, MatchValue::exact(ad_count))
                    .match_key(&key3, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .match_key(&key4, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .action(&action_name);

                table_entries.push(tbl_request);
            }
        }

        // Placeholder network actions
        for network_action_index in 0..15 {
            let control_second_nas = "ingress.mpls_c.mna_c.mna_second_nas_c";

            let table_name =
                format!("{control_second_nas}.mna_subsequent_opcode_{network_action_index}");

            let max_ad = 1; //cmp::min(15 - network_action_index, 8);

            for ad_count in 0..max_ad {
                let action_name = format!(
                    "{control_second_nas}.action_{network_action_index}_with_{ad_count}_ad"
                );
                let key1 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.opcode");
                let key2 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.nal");
                let key3 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.data");
                let key4 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.data2");

                let tbl_request = table::Request::new(&table_name)
                    .match_key(&key1, MatchValue::exact(64))
                    .match_key(&key2, MatchValue::exact(ad_count))
                    .match_key(&key3, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .match_key(&key4, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .action(&action_name);

                table_entries.push(tbl_request);
            }
        }

        table_entries
    }

    pub async fn digest_monitor(&mut self, switch: Arc<SwitchConnection>) {
        info!("Starting listening for digests");
        while let Ok(digest) = &mut switch.digest_queue.recv() {
            if digest.name == DEBUG_DIGEST_NAME {
                let data = &digest.data;

                //let ipv4_dest = data.get("ipv4_dest").unwrap().to_ipv4();
                let mpls_label = data.get("mpls_label").unwrap().to_u32();
                let ether_type: u32 = data.get("ether_type").unwrap().to_u32();
                let nasi_label = data.get("mna_nasi_label").unwrap().to_u32();
                let mna_initial_opcode = data.get("mna_initial_opcode").unwrap().to_u32();
                let nasi_second_nas = data.get("nasi_second_nas").unwrap().to_u32();
                let mna_initial_opcode_second_nas =
                    data.get("mna_initial_opcode_second_nas").unwrap().to_u32();
                let drop_ctl = data.get("drop_ctl").unwrap().to_u32();
                let resubmit_needed = data.get("resubmit_needed").unwrap().to_u32();
                let hbh_sub_opcode_7_label = data.get("hbh_sub_opcode_7_label").unwrap().to_u32();
                let select_sub_opcode_7_label =
                    data.get("select_sub_opcode_7_label").unwrap().to_u32();
                let processing_stage = data.get("processing_stage").unwrap().to_u32();
                let parser_error = data.get("parser_error").unwrap().to_u32();
                let hbh_processing_done = data.get("hbh_processing_done").unwrap().to_bool();

                if ether_type != 34525 && ether_type != 2048 {
                    // info!("ether_type: {}, mpls_label: {}, nasi_label: {}, mna_initial_opcode: {}, nasi_second_nas: {},
                    // mna_initial_opcode_second_nas: {}, drop_ctl: {}, resubmit_needed: {}, hbh_sub_opcode_7_label: {}, select_sub_opcode_7_label: {},
                    // processing_stage: {}, parser_error: {}, hbh_processing_done: {}",
                    //  &ether_type, &mpls_label, &nasi_label, &mna_initial_opcode, &nasi_second_nas,
                    //   &mna_initial_opcode_second_nas, drop_ctl, resubmit_needed, hbh_sub_opcode_7_label, select_sub_opcode_7_label, processing_stage, parser_error, hbh_processing_done);
                }
            }
        }
    }
}
