import requests
import time
import json
import os
import numpy as np

MPLS_ONLY = {
    "streams": [
        {
            "stream_id": 2,
            "app_id": 1,
            "frame_size": 1518,
            "encapsulation": 3,
            "number_of_lse": 3,
            "traffic_rate": 400,
            "burst": 100,
            "vxlan": False,
            "ip_version": 4,
            "number_of_srv6_sids": 0,
            "srv6_ip_tunneling": False
        }
    ],
    "stream_settings": [
        {
            "port": 176,
            "stream_id": 2,
            "vlan": {
                "vlan_id": 1,
                "pcp": 0,
                "dei": 0,
                "inner_vlan_id": 1,
                "inner_pcp": 0,
                "inner_dei": 0
            },
            "mpls_stack": [
                {
                    "label": 500,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 600,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 700,
                    "tc": 7,
                    "ttl": 63
                }
            ],
            "ethernet": {
                "eth_src": "32:D5:42:2A:F6:92",
                "eth_dst": "81:E7:9D:E3:AD:47"
            },
            "ip": {
                "ip_src": "192.168.178.10",
                "ip_dst": "192.168.178.11",
                "ip_tos": 0,
                "ip_src_mask": "0.0.0.0",
                "ip_dst_mask": "0.0.0.0"
            },
            "active": True
        }
    ],
    "port_tx_rx_mapping": {
        "176": 176
    },
    "mode": 1
}

AMM_STACK_MINIMUM_COLOR_B = {
    "streams": [
        {
            "stream_id": 2,
            "app_id": 1,
            "frame_size": 1518,
            "encapsulation": 3,
            "number_of_lse": 6,
            "traffic_rate": 400,
            "burst": 100,
            "vxlan": False,
            "ip_version": 4,
            "number_of_srv6_sids": 0,
            "srv6_ip_tunneling": False
        }
    ],
    "stream_settings": [
        {
            "port": 176,
            "stream_id": 2,
            "vlan": {
                "vlan_id": 1,
                "pcp": 0,
                "dei": 0,
                "inner_vlan_id": 1,
                "inner_pcp": 0,
                "inner_dei": 0
            },
            "mpls_stack": [
                {
                    "label": 500,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 600,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 700,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 4,
                    "tc": 7,
                    "ttl": 64
                },
                {
                    "label": 8192,
                    "tc": 1,
                    "ttl": 8
                },
                {
                    "label": 352256,
                    "tc": 0,
                    "ttl": 16
                }
            ],
            "ethernet": {
                "eth_src": "32:D5:42:2A:F6:92",
                "eth_dst": "81:E7:9D:E3:AD:47"
            },
            "ip": {
                "ip_src": "192.168.178.10",
                "ip_dst": "192.168.178.11",
                "ip_tos": 0,
                "ip_src_mask": "0.0.0.0",
                "ip_dst_mask": "0.0.0.0"
            },
            "active": True
        }
    ],
    "port_tx_rx_mapping": {
        "176": 176
    },
    "mode": 1
}

AMM_STACK_MINIMUM_COLOR_A = {
    "streams": [
        {
            "stream_id": 2,
            "app_id": 1,
            "frame_size": 1518,
            "encapsulation": 3,
            "number_of_lse": 6,
            "traffic_rate": 400,
            "burst": 100,
            "vxlan": False,
            "ip_version": 4,
            "number_of_srv6_sids": 0,
            "srv6_ip_tunneling": False
        }
    ],
    "stream_settings": [
        {
            "port": 176,
            "stream_id": 2,
            "vlan": {
                "vlan_id": 1,
                "pcp": 0,
                "dei": 0,
                "inner_vlan_id": 1,
                "inner_pcp": 0,
                "inner_dei": 0
            },
            "mpls_stack": [
                {
                    "label": 500,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 600,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 700,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 4,
                    "tc": 7,
                    "ttl": 64
                },
                {
                    "label": 8192,
                    "tc": 1,
                    "ttl": 8
                },
                {
                    "label": 352256,
                    "tc": 0,
                    "ttl": 0
                }
            ],
            "ethernet": {
                "eth_src": "32:D5:42:2A:F6:92",
                "eth_dst": "81:E7:9D:E3:AD:47"
            },
            "ip": {
                "ip_src": "192.168.178.10",
                "ip_dst": "192.168.178.11",
                "ip_tos": 0,
                "ip_src_mask": "0.0.0.0",
                "ip_dst_mask": "0.0.0.0"
            },
            "active": True
        }
    ],
    "port_tx_rx_mapping": {
        "176": 176
    },
    "mode": 1
}

AMM_STACK_MAXIMUM_COLOR_A = {
    "streams": [
        {
            "stream_id": 2,
            "app_id": 1,
            "frame_size": 1518,
            "encapsulation": 3,
            "number_of_lse": 15,
            "traffic_rate": 400,
            "burst": 100,
            "vxlan": False,
            "ip_version": 4,
            "number_of_srv6_sids": 0,
            "srv6_ip_tunneling": False
        }
    ],
    "stream_settings": [
        {
            "port": 176,
            "stream_id": 2,
            "vlan": {
                "vlan_id": 1,
                "pcp": 0,
                "dei": 0,
                "inner_vlan_id": 1,
                "inner_pcp": 0,
                "inner_dei": 0
            },
            "mpls_stack": [
                {
                    "label": 500,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 600,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 700,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 4,
                    "tc": 7,
                    "ttl": 64
                },
                {
                    "label": 8192,
                    "tc": 1,
                    "ttl": 80
                },
                {
                    "label": 352256,
                    "tc": 0,
                    "ttl": 16
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },  
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },                
            ],
            "ethernet": {
                "eth_src": "32:D5:42:2A:F6:92",
                "eth_dst": "81:E7:9D:E3:AD:47"
            },
            "ip": {
                "ip_src": "192.168.178.10",
                "ip_dst": "192.168.178.11",
                "ip_tos": 0,
                "ip_src_mask": "0.0.0.0",
                "ip_dst_mask": "0.0.0.0"
            },
            "active": True
        }
    ],
    "port_tx_rx_mapping": {
        "176": 176
    },
    "mode": 1
}

AMM_STACK_MAXIMUM_COLOR_B = {
    "streams": [
        {
            "stream_id": 2,
            "app_id": 1,
            "frame_size": 1518,
            "encapsulation": 3,
            "number_of_lse": 15,
            "traffic_rate": 400,
            "burst": 100,
            "vxlan": False,
            "ip_version": 4,
            "number_of_srv6_sids": 0,
            "srv6_ip_tunneling": False
        }
    ],
    "stream_settings": [
        {
            "port": 176,
            "stream_id": 2,
            "vlan": {
                "vlan_id": 1,
                "pcp": 0,
                "dei": 0,
                "inner_vlan_id": 1,
                "inner_pcp": 0,
                "inner_dei": 0
            },
            "mpls_stack": [
                {
                    "label": 500,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 600,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 700,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 4,
                    "tc": 7,
                    "ttl": 64
                },
                {
                    "label": 8192,
                    "tc": 1,
                    "ttl": 80
                },
                {
                    "label": 352256,
                    "tc": 0,
                    "ttl": 0
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },  
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },  
            ],
            "ethernet": {
                "eth_src": "32:D5:42:2A:F6:92",
                "eth_dst": "81:E7:9D:E3:AD:47"
            },
            "ip": {
                "ip_src": "192.168.178.10",
                "ip_dst": "192.168.178.11",
                "ip_tos": 0,
                "ip_src_mask": "0.0.0.0",
                "ip_dst_mask": "0.0.0.0"
            },
            "active": True
        }
    ],
    "port_tx_rx_mapping": {
        "176": 176
    },
    "mode": 1
}

AMM_STACK_MAXIMUM_COLOR_B_WITH_SELECT = {
    "streams": [
        {
            "stream_id": 2,
            "app_id": 1,
            "frame_size": 1518,
            "encapsulation": 3,
            "number_of_lse": 15,
            "traffic_rate": 400,
            "burst": 100,
            "vxlan": False,
            "ip_version": 4,
            "number_of_srv6_sids": 0,
            "srv6_ip_tunneling": False
        }
    ],
    "stream_settings": [
        {
            "port": 176,
            "stream_id": 2,
            "vlan": {
                "vlan_id": 1,
                "pcp": 0,
                "dei": 0,
                "inner_vlan_id": 1,
                "inner_pcp": 0,
                "inner_dei": 0
            },
            "mpls_stack": [
                {
                    "label": 500,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 4,
                    "tc": 7,
                    "ttl": 64
                },                
                {
                    "label": 8192,
                    "tc": 2,
                    "ttl": 8
                },   
                {
                    "label": 352256,
                    "tc": 0,
                    "ttl": 16
                },                                  
                {
                    "label": 600,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 700,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 4,
                    "tc": 7,
                    "ttl": 64
                },
                {
                    "label": 524288,
                    "tc": 1,
                    "ttl": 56
                },
                {
                    "label": 352256,
                    "tc": 0,
                    "ttl": 16
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },  
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                }
            ],
            "ethernet": {
                "eth_src": "32:D5:42:2A:F6:92",
                "eth_dst": "81:E7:9D:E3:AD:47"
            },
            "ip": {
                "ip_src": "192.168.178.10",
                "ip_dst": "192.168.178.11",
                "ip_tos": 0,
                "ip_src_mask": "0.0.0.0",
                "ip_dst_mask": "0.0.0.0"
            },
            "active": True
        }
    ],
    "port_tx_rx_mapping": {
        "176": 176
    },
    "mode": 1
}

STACK_MAXIMUM_TEST = {
    "streams": [
        {
            "stream_id": 2,
            "app_id": 1,
            "frame_size": 1518,
            "encapsulation": 3,
            "number_of_lse": 15,
            "traffic_rate": 400,
            "burst": 100,
            "vxlan": False,
            "ip_version": 4,
            "number_of_srv6_sids": 0,
            "srv6_ip_tunneling": False
        }
    ],
    "stream_settings": [
        {
            "port": 176,
            "stream_id": 2,
            "vlan": {
                "vlan_id": 1,
                "pcp": 0,
                "dei": 0,
                "inner_vlan_id": 1,
                "inner_pcp": 0,
                "inner_dei": 0
            },
            "mpls_stack": [
                {
                    "label": 500,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 600,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 700,
                    "tc": 7,
                    "ttl": 63
                },
                {
                    "label": 4,
                    "tc": 7,
                    "ttl": 64
                },
                {
                    "label": 8192,
                    "tc": 1,
                    "ttl": 80
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },  
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },  
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },   
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },
                {
                    "label": 524288,
                    "tc": 0,
                    "ttl": 0
                },  
            ],
            "ethernet": {
                "eth_src": "32:D5:42:2A:F6:92",
                "eth_dst": "81:E7:9D:E3:AD:47"
            },
            "ip": {
                "ip_src": "192.168.178.10",
                "ip_dst": "192.168.178.11",
                "ip_tos": 0,
                "ip_src_mask": "0.0.0.0",
                "ip_dst_mask": "0.0.0.0"
            },
            "active": True
        }
    ],
    "port_tx_rx_mapping": {
        "176": 176
    },
    "mode": 1
}

NRP_STACK = {
  "streams": [
    {
      "stream_id": 1,
      "app_id": 1,
      "frame_size": 1518,
      "encapsulation": 3,
      "number_of_lse": 3,
      "traffic_rate": 20,
      "burst": 100,
      "vxlan": False,
      "ip_version": 4,
      "number_of_srv6_sids": 0,
      "srv6_ip_tunneling": True
    },
    {
      "stream_id": 2,
      "app_id": 2,
      "frame_size": 1518,
      "encapsulation": 3,
      "number_of_lse": 3,
      "traffic_rate": 30,
      "burst": 100,
      "vxlan": False,
      "ip_version": 4,
      "number_of_srv6_sids": 0,
      "srv6_ip_tunneling": True
    },
    {
      "stream_id": 3,
      "app_id": 3,
      "frame_size": 1518,
      "encapsulation": 3,
      "number_of_lse": 3,
      "traffic_rate": 50,
      "burst": 100,
      "vxlan": False,
      "ip_version": 4,
      "number_of_srv6_sids": 0,
      "srv6_ip_tunneling": True
    },
    {
      "stream_id": 4,
      "app_id": 4,
      "frame_size": 1518,
      "encapsulation": 3,
      "number_of_lse": 3,
      "traffic_rate": 100,
      "burst": 100,
      "vxlan": False,
      "ip_version": 4,
      "number_of_srv6_sids": 0,
      "srv6_ip_tunneling": True
    }
  ],
  "stream_settings": [
    {
      "port": 176,
      "stream_id": 1,
      "vlan": {
        "vlan_id": 1,
        "pcp": 0,
        "dei": 0,
        "inner_vlan_id": 1,
        "inner_pcp": 0,
        "inner_dei": 0
      },
      "mpls_stack": [
        {
          "label": 301,
          "tc": 0,
          "ttl": 64
        },
        {
          "label": 4,
          "tc": 7,
          "ttl": 64
        },
        {
          "label": 41060,
          "tc": 1,
          "ttl": 0
        }
      ],
      "srv6_base_header": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "sid_list": [],
      "ethernet": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47"
      },
      "ip": {
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "ip_src_mask": "0.0.0.0",
        "ip_dst_mask": "0.0.0.0"
      },
      "ipv6": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "active": True,
      "vxlan": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47",
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "udp_source": 49152,
        "vni": 1
      }
    },
    {
      "port": 176,
      "stream_id": 2,
      "vlan": {
        "vlan_id": 1,
        "pcp": 0,
        "dei": 0,
        "inner_vlan_id": 1,
        "inner_pcp": 0,
        "inner_dei": 0
      },
      "mpls_stack": [
        {
          "label": 301,
          "tc": 0,
          "ttl": 64
        },
        {
          "label": 4,
          "tc": 7,
          "ttl": 64
        },
        {
          "label": 41160,
          "tc": 1,
          "ttl": 0
        }
      ],
      "srv6_base_header": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "sid_list": [],
      "ethernet": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47"
      },
      "ip": {
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "ip_src_mask": "0.0.0.0",
        "ip_dst_mask": "0.0.0.0"
      },
      "ipv6": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "active": True,
      "vxlan": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47",
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "udp_source": 49152,
        "vni": 1
      }
    },
    {
      "port": 176,
      "stream_id": 3,
      "vlan": {
        "vlan_id": 1,
        "pcp": 0,
        "dei": 0,
        "inner_vlan_id": 1,
        "inner_pcp": 0,
        "inner_dei": 0
      },
      "mpls_stack": [
        {
          "label": 301,
          "tc": 0,
          "ttl": 64
        },
        {
          "label": 4,
          "tc": 7,
          "ttl": 64
        },
        {
          "label": 41260,
          "tc": 1,
          "ttl": 0
        }
      ],
      "srv6_base_header": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "sid_list": [],
      "ethernet": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47"
      },
      "ip": {
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "ip_src_mask": "0.0.0.0",
        "ip_dst_mask": "0.0.0.0"
      },
      "ipv6": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "active": True,
      "vxlan": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47",
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "udp_source": 49152,
        "vni": 1
      }
    },
    {
      "port": 176,
      "stream_id": 4,
      "vlan": {
        "vlan_id": 1,
        "pcp": 0,
        "dei": 0,
        "inner_vlan_id": 1,
        "inner_pcp": 0,
        "inner_dei": 0
      },
      "mpls_stack": [
        {
          "label": 301,
          "tc": 0,
          "ttl": 64
        },
        {
          "label": 4,
          "tc": 7,
          "ttl": 0
        },
        {
          "label": 41360,
          "tc": 1,
          "ttl": 0
        }
      ],
      "srv6_base_header": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "sid_list": [],
      "ethernet": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47"
      },
      "ip": {
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "ip_src_mask": "0.0.0.0",
        "ip_dst_mask": "0.0.0.0"
      },
      "ipv6": {
        "ipv6_src": "ff80::",
        "ipv6_dst": "ff80::",
        "ipv6_traffic_class": 0,
        "ipv6_src_mask": "::",
        "ipv6_dst_mask": "::",
        "ipv6_flow_label": 0
      },
      "active": True,
      "vxlan": {
        "eth_src": "32:D5:42:2A:F6:92",
        "eth_dst": "81:E7:9D:E3:AD:47",
        "ip_src": "192.168.178.10",
        "ip_dst": "192.168.178.11",
        "ip_tos": 0,
        "udp_source": 49152,
        "vni": 1
      }
    },
  ],
  "port_tx_rx_mapping": {
    "176": 160
  },
  "mode": 1
}    

def start_traffic_gen(data):
    requests.post(URL, json=data)

def stop_traffic_gen():
    requests.delete(URL)
    time.sleep(1.5)

def get_stats():
    req = requests.get(URL_STATS)
    
    data = req.json()
    sent_frames = data["frame_size"][f"{PORT}"]["tx"][2]["packets"]
    received_frames = data["frame_size"][f"{PORT}"]["rx"][1]["packets"]
    min_rtt = data["rtts"][f"{PORT}"]["min"]
    max_rtt = data["rtts"][f"{PORT}"]["max"]
    mean_rtt = data["rtts"][f"{PORT}"]["mean"]
    
    summary = {"sent_frames": sent_frames, "min_rtt": min_rtt, "max_rtt": max_rtt, "mean_rtt": mean_rtt, "received_frames": received_frames}
    return summary

def get_stats_nrp(tx_port, rx_port):
    req = requests.get(URL_STATS)
    
    data = req.json()
    
    streams = {}
    for stream in range(1,5):
        tx_l2 = data["app_tx_l2"][f"{tx_port}"][f"{stream}"]
        rx_l2 = data["app_rx_l2"][f"{rx_port}"][f"{stream}"]
        try:
            packet_loss = 1 - (rx_l2 / tx_l2)
        except ZeroDivisionError:
            print(data["app_tx_l2"])
        mean_rtt = data["rtts"][f"{rx_port}"]["mean"]
        summary = {"mean_rtt": mean_rtt, "packet_loss": packet_loss}
        streams[f"stream_{stream}"] = summary
        
    print(streams)
    return streams


URL = "http://localhost:8000/api/trafficgen"
URL_STATS = "http://localhost:8000/api/statistics"
PORT = 176
DURATION = 6
ALTERNATIONS = 10
ITERATIONS = 3 # change to 3 for E_A

def e(stack):
    stats = []
    stop_traffic_gen()
    color_index = 0
    for a in range(ALTERNATIONS):
        start_traffic_gen(stack[color_index])
        time.sleep(DURATION)
        stop_traffic_gen()
        stats.append(get_stats())
        color_index = 1 if color_index == 0 else 0

    # Trigger the last color change but dont count those packets
    start_traffic_gen(stack[0])
    stop_traffic_gen()
    
    tx_total_frames = 0
    rx_total_frames = 0
    mean_rtt_avg = 0
    for s in stats:
        tx_total_frames += s["sent_frames"]
        rx_total_frames += s["received_frames"]
        mean_rtt_avg += s["mean_rtt"]
    mean_rtt_avg = mean_rtt_avg / len(stats)
    packet_loss = tx_total_frames - rx_total_frames
    
    # We started/ and stopped TG multiple times, aggregate those values
    results = {}
    results["mean_rtt_avg"] = mean_rtt_avg / 1000
    results["sent_frames"] = tx_total_frames 
    results["received_frames"] = rx_total_frames
    results["packet_loss"] = packet_loss
    results["loss_percentage"] = packet_loss / tx_total_frames
    return results

def nrp():
    stats = []
    stop_traffic_gen()
    
    for i in range(10):
        start_traffic_gen(NRP_STACK)
        time.sleep(60)
        stats.append(get_stats_nrp(176, 160))        
        stop_traffic_gen()

    # Iterate over each entry in the list
    stream_loss_data = {}
    for entry in stats:
        for stream, metrics in entry.items():
            if stream not in stream_loss_data:
                stream_loss_data[stream] = {'total_loss': 0, 'count': 0}
            stream_loss_data[stream]['total_loss'] += metrics['packet_loss']
            stream_loss_data[stream]['count'] += 1

    # Calculate the mean packet loss for each stream
    mean_packet_loss = {stream: loss_data['total_loss'] / loss_data['count'] 
                        for stream, loss_data in stream_loss_data.items()}

    # Print the result
    print(mean_packet_loss)




# Start traffic gen with NRP stack
#nrp()


# Start traffic gen with different AMM stacks
#for s in [(MPLS_ONLY, MPLS_ONLY), (AMM_STACK_MINIMUM_COLOR_A, AMM_STACK_MINIMUM_COLOR_B), (AMM_STACK_MAXIMUM_COLOR_A, AMM_STACK_MAXIMUM_COLOR_B)]:
#for s in [(AMM_STACK_MAXIMUM_COLOR_A, AMM_STACK_MAXIMUM_COLOR_A)]:
#     results = []
#     for i in range(ITERATIONS):
#          results.append(e(s))
#     rtts = [d["mean_rtt_avg"] for d in results]
#     packet_loss = [d["packet_loss"] for d in results]
 #    packet_loss_percentage = [d["loss_percentage"] for d in results]
 #    print(f"Mean RTT: {np.round(np.mean(rtts), 2)} us")
 #    print(f"Std RTT: {np.std(rtts)}")
 ##    print(f"Mean Loss: {np.mean(packet_loss)}")
 #    print(f"Std Loss:  {np.std(packet_loss)}")
 #    print(f"Mean Loss%: {np.mean(packet_loss_percentage)} %")
 #    print(f"Std Loss%:  {np.std(packet_loss_percentage)} %")
  #   print(f"Total frames: {results[0]['sent_frames']}")
  #   print(f"----")