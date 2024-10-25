/* Copyright 2022-present University of Tuebingen, Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use log::{info, warn};
use rbfrt::register::Register;
use rbfrt::util::port_manager::{AutoNegotiation, Loopback, Port, Speed, FEC};
use rbfrt::util::{PortManager, PrettyPrinter};
use rbfrt::{register, table, SwitchConnection};

mod mna;
use mna::MNAController;

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    info!("Start controller...");

    let mut switch = SwitchConnection::new("localhost", 50052)
        .device_id(0)
        .client_id(1)
        .p4_name("mna_isd")
        .connect()
        .await?;

    switch.clear_table("$PORT").await?;

    let pm = PortManager::new(&mut switch).await;

    let mut port_requests: Vec<Port> = vec![];

    // Frank 5 <-> Pennywise 17:00.0, enp23s0f0np0
    let pm_req = Port::new(5, 0)
        .speed(Speed::BF_SPEED_100G)
        .auto_negotiation(AutoNegotiation::PM_AN_FORCE_DISABLE);
    port_requests.push(pm_req);
    // Frank 3 <-> P4TG Pazuzu 8
    let pm_req = Port::new(3, 0).speed(Speed::BF_SPEED_100G);
    port_requests.push(pm_req);

    let carrie_ports = vec![1, 11, 12, 17];
    for p in carrie_ports {
        let pm_req = Port::new(p, 0).speed(Speed::BF_SPEED_100G);
        port_requests.push(pm_req);
    }

    pm.add_ports(&mut switch, &port_requests).await?;

    info!("Ports of device configured.");

    // Label 50 -> P4TG
    // Label 60 -> Pennywise Host
    let mpls_label_to_egress_port_mapping = HashMap::from([
        (50, 168),
        (60, 168),
        (500, 136),
        (600, 296),
        (700, 168),
        (800, 152),
    ]);
    let mut mna_controller = MNAController::new(mpls_label_to_egress_port_mapping);

    let tables: Vec<&str> = vec![
        mna::mna_controller::MPLS_LOOKUP_TABLE,
        "ingress.mpls_c.verify_ttl",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_0",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_1",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_2",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_3",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_4",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_5",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_6",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_7",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_8",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_9",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_10",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_11",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_12",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_14",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_0",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_1",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_2",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_3",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_4",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_5",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_6",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_7",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_8",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_9",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_10",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_11",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_12",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_14",
        "ingress.probabilistic_packet_drop",
        "ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a",
        "ingress.mpls_c.mna_c.amm_packet_loss_counter_color_b",
        "ingress.mpls_c.mna_c.amm_packet_loss_last_color",
    ];

    switch.clear_tables(tables).await;

    let mut table_entries = mna_controller.init_mpls_lookup();
    table_entries.extend(mna_controller.init_constant_entries());
    table_entries.extend(mna_controller.init_opcode_entries());

    switch.write_table_entries(table_entries).await;

    let switch = Arc::new(switch);
    let switch2 = Arc::clone(&switch);

    tokio::spawn(async move {
        mna_controller.digest_monitor(switch2).await;
    });

    let pp = PrettyPrinter::new();

    loop {
        // Read tables for debugging
        let table_to_check = "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_1";
        let sync =
            table::Request::new(table_to_check).operation(table::TableOperation::SyncCounters);

        if switch.execute_operation(sync).await.is_err() {
            warn! {"Encountered error while synchronizing {}.", table_to_check};
        }

        let req: table::Request = table::Request::new(table_to_check);

        let res = switch.get_table_entry(req).await?;

        pp.print_table(res)?;

        // Read AMM registers for debugging
        let mut requests = vec![];
        requests.push(
            register::Request::new("ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a").index(8),
        );

        let sync = table::Request::new("ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a")
            .operation(table::TableOperation::SyncRegister);
        if switch.execute_operation(sync).await.is_err() {
            warn!(
                "Error in synchronization for register {}.",
                "ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a"
            );
        }
        let fut = switch.get_register_entries(requests.clone()).await;
        info!("{:?}", fut);

        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> () {
    env_logger::init();

    match run().await {
        Ok(_) => {}
        Err(e) => {
            warn!("Error: {}", e);
        }
    }
}
