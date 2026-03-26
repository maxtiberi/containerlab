"""BGP and BGP-LS protocol constants.

References:
  - RFC 4271: BGP-4
  - RFC 4760: Multiprotocol Extensions for BGP-4
  - RFC 6793: BGP Support for Four-Octet AS Numbers
  - RFC 7752: North-Bound Distribution of Link-State and TE Info Using BGP
  - RFC 8571: BGP-LS Attributes for SR
  - RFC 9085: BGP-LS Extensions for SR Policies
  - RFC 9088: Signaling MSD Using BGP-LS (Flex-Algo)
"""

# ---------------------------------------------------------------------------
# BGP Header
# ---------------------------------------------------------------------------
BGP_MARKER = b"\xff" * 16
BGP_HEADER_LEN = 19          # 16 marker + 2 length + 1 type
BGP_MAX_MSG_LEN = 65535
BGP_PORT = 179

# ---------------------------------------------------------------------------
# BGP Message Types (RFC 4271 §4.1)
# ---------------------------------------------------------------------------
MSG_OPEN = 1
MSG_UPDATE = 2
MSG_NOTIFICATION = 3
MSG_KEEPALIVE = 4

MSG_TYPE_NAMES = {
    MSG_OPEN: "OPEN",
    MSG_UPDATE: "UPDATE",
    MSG_NOTIFICATION: "NOTIFICATION",
    MSG_KEEPALIVE: "KEEPALIVE",
}

# ---------------------------------------------------------------------------
# BGP OPEN Optional Parameter Types
# ---------------------------------------------------------------------------
OPT_PARAM_CAPABILITY = 2

# ---------------------------------------------------------------------------
# BGP Capabilities (RFC 5492)
# ---------------------------------------------------------------------------
CAP_MULTIPROTOCOL = 1        # RFC 4760
CAP_ROUTE_REFRESH = 2        # RFC 2918
CAP_OUTBOUND_ROUTE_FILTER = 3
CAP_GRACEFUL_RESTART = 64    # RFC 4724
CAP_4BYTE_AS = 65            # RFC 6793
CAP_DYNAMIC = 67
CAP_LONG_LIVED_GRACEFUL_RESTART = 71
CAP_FQDN = 73
CAP_ENHANCED_ROUTE_REFRESH = 70
CAP_ROUTE_REFRESH_CISCO = 128  # Cisco-specific pre-standard

# ---------------------------------------------------------------------------
# BGP AFI / SAFI
# ---------------------------------------------------------------------------
AFI_IP = 1
AFI_IP6 = 2
AFI_BGP_LS = 16388           # RFC 7752

SAFI_UNICAST = 1
SAFI_MULTICAST = 2
SAFI_MPLS_LABEL = 4
SAFI_BGPLS = 71              # RFC 7752
SAFI_BGPLS_VPN = 72          # RFC 7752

# ---------------------------------------------------------------------------
# BGP Path Attribute Type Codes (RFC 4271 §5)
# ---------------------------------------------------------------------------
PA_ORIGIN = 1
PA_AS_PATH = 2
PA_NEXT_HOP = 3
PA_MULTI_EXIT_DISC = 4
PA_LOCAL_PREF = 5
PA_ATOMIC_AGGREGATE = 6
PA_AGGREGATOR = 7
PA_COMMUNITIES = 8
PA_ORIGINATOR_ID = 9
PA_CLUSTER_LIST = 10
PA_DPA = 11
PA_ADVERTISER = 12
PA_RCID_PATH = 13
PA_MP_REACH_NLRI = 14        # RFC 4760
PA_MP_UNREACH_NLRI = 15      # RFC 4760
PA_EXT_COMMUNITIES = 16      # RFC 4360
PA_AS4_PATH = 17             # RFC 6793
PA_AS4_AGGREGATOR = 18       # RFC 6793
PA_PMSI_TUNNEL = 22          # RFC 6514
PA_TUNNEL_ENCAP = 23         # RFC 5512
PA_TRAFFIC_ENGINEERING = 24
PA_IPV6_EXT_COMMUNITIES = 25
PA_AIGP = 26                 # RFC 7311
PA_PE_DIST_LABELS = 27
PA_ENTROPY_LABEL_CAP = 28
PA_BGP_LS = 29               # RFC 7752 — BGP-LS attribute
PA_LARGE_COMMUNITIES = 32    # RFC 8092
PA_BGPSEC_PATH = 33
PA_OTC = 35                  # RFC 9234
PA_D_PATH = 36
PA_SFP_ATTR = 37
PA_BGP_PREFIX_SID = 40       # RFC 8669

# Path Attribute Flags
PA_FLAG_OPTIONAL = 0x80
PA_FLAG_TRANSITIVE = 0x40
PA_FLAG_PARTIAL = 0x20
PA_FLAG_EXTENDED_LEN = 0x10

# ORIGIN values
ORIGIN_IGP = 0
ORIGIN_EGP = 1
ORIGIN_INCOMPLETE = 2

# AS_PATH segment types
AS_SET = 1
AS_SEQUENCE = 2
AS_CONFED_SEQUENCE = 3
AS_CONFED_SET = 4

# ---------------------------------------------------------------------------
# BGP-LS NLRI Types (RFC 7752 §3.2)
# ---------------------------------------------------------------------------
NLRI_NODE = 1
NLRI_LINK = 2
NLRI_IPV4_PREFIX = 3
NLRI_IPV6_PREFIX = 4
NLRI_TE_POLICY_V4 = 5        # draft-ietf-idr-te-lsp-distribution
NLRI_TE_POLICY_V6 = 6        # draft-ietf-idr-te-lsp-distribution
NLRI_SRV6_SID = 6            # RFC 9252 (shares value 6 — context-dependent)

NLRI_TYPE_NAMES = {
    NLRI_NODE: "Node",
    NLRI_LINK: "Link",
    NLRI_IPV4_PREFIX: "IPv4 Prefix",
    NLRI_IPV6_PREFIX: "IPv6 Prefix",
}

# ---------------------------------------------------------------------------
# BGP-LS Protocol Identifier (RFC 7752 §3.2)
# ---------------------------------------------------------------------------
PROTO_ISIS_L1 = 1
PROTO_ISIS_L2 = 2
PROTO_OSPFV2 = 3
PROTO_DIRECT = 4
PROTO_STATIC = 5
PROTO_OSPFV3 = 6
PROTO_BGP = 7                # draft-ietf-idr-bgpls-segment-routing-epe

PROTO_NAMES = {
    PROTO_ISIS_L1: "IS-IS Level 1",
    PROTO_ISIS_L2: "IS-IS Level 2",
    PROTO_OSPFV2: "OSPFv2",
    PROTO_DIRECT: "Direct",
    PROTO_STATIC: "Static",
    PROTO_OSPFV3: "OSPFv3",
    PROTO_BGP: "BGP",
}

# ---------------------------------------------------------------------------
# Node Descriptor Sub-TLV Types (RFC 7752 §3.2.1)
# ---------------------------------------------------------------------------
ND_AS_NUMBER = 512           # 4 bytes
ND_BGP_LS_ID = 513           # 4 bytes
ND_OSPF_AREA_ID = 514        # 4 bytes
ND_IGP_ROUTER_ID = 515       # 4/6/7/8 bytes depending on protocol/pseudonode
ND_BGP_ROUTER_ID = 516       # 4 bytes (draft EPE)
ND_MEMBER_AS_NUMBER = 517    # 4 bytes (draft EPE)

ND_TYPE_NAMES = {
    ND_AS_NUMBER: "AS Number",
    ND_BGP_LS_ID: "BGP-LS Identifier",
    ND_OSPF_AREA_ID: "OSPF Area-ID",
    ND_IGP_ROUTER_ID: "IGP Router-ID",
    ND_BGP_ROUTER_ID: "BGP Router-ID",
    ND_MEMBER_AS_NUMBER: "Member AS Number",
}

# ---------------------------------------------------------------------------
# Link Descriptor Sub-TLV Types (RFC 7752 §3.2.2)
# ---------------------------------------------------------------------------
LD_LINK_LOCAL_REMOTE_IDS = 258   # 8 bytes (local 4 + remote 4)
LD_IPV4_IFACE_ADDR = 259         # 4 bytes
LD_IPV4_NEIGHBOR_ADDR = 260      # 4 bytes
LD_IPV6_IFACE_ADDR = 261         # 16 bytes
LD_IPV6_NEIGHBOR_ADDR = 262      # 16 bytes
LD_MT_ID = 263                   # variable (multiples of 2)

LD_TYPE_NAMES = {
    LD_LINK_LOCAL_REMOTE_IDS: "Link Local/Remote Identifiers",
    LD_IPV4_IFACE_ADDR: "IPv4 Interface Address",
    LD_IPV4_NEIGHBOR_ADDR: "IPv4 Neighbor Address",
    LD_IPV6_IFACE_ADDR: "IPv6 Interface Address",
    LD_IPV6_NEIGHBOR_ADDR: "IPv6 Neighbor Address",
    LD_MT_ID: "Multi-Topology ID",
}

# ---------------------------------------------------------------------------
# Prefix Descriptor Sub-TLV Types (RFC 7752 §3.2.3)
# ---------------------------------------------------------------------------
PD_MT_ID = 264               # variable
PD_OSPF_ROUTE_TYPE = 265     # 1 byte
PD_IP_REACHABILITY = 266     # variable (prefix-length + prefix)

PD_TYPE_NAMES = {
    PD_MT_ID: "Multi-Topology ID",
    PD_OSPF_ROUTE_TYPE: "OSPF Route Type",
    PD_IP_REACHABILITY: "IP Reachability Information",
}

# OSPF Route Type values (used in PD_OSPF_ROUTE_TYPE)
OSPF_ROUTE_INTRA_AREA = 1
OSPF_ROUTE_INTER_AREA = 2
OSPF_ROUTE_EXTERNAL_1 = 3
OSPF_ROUTE_EXTERNAL_2 = 4
OSPF_ROUTE_NSSA_1 = 5
OSPF_ROUTE_NSSA_2 = 6

OSPF_ROUTE_TYPE_NAMES = {
    OSPF_ROUTE_INTRA_AREA: "Intra-Area",
    OSPF_ROUTE_INTER_AREA: "Inter-Area",
    OSPF_ROUTE_EXTERNAL_1: "External-1",
    OSPF_ROUTE_EXTERNAL_2: "External-2",
    OSPF_ROUTE_NSSA_1: "NSSA-1",
    OSPF_ROUTE_NSSA_2: "NSSA-2",
}

# ---------------------------------------------------------------------------
# BGP-LS Attribute TLV Types — Node (RFC 7752 §3.3.1)
# ---------------------------------------------------------------------------
NA_MT_IDS = 1024             # Multi-Topology Identifiers
NA_OSPF_NODE_PROPS = 1025    # OSPF Node Properties (1 byte)
NA_ISIS_AREA_ID = 1026       # IS-IS Area Identifier (1–13 bytes)
NA_IPV4_ROUTER_ID_LOCAL = 1027   # 4 bytes
NA_IPV6_ROUTER_ID_LOCAL = 1028   # 16 bytes
NA_NODE_NAME = 1029          # Variable (hostname string)
NA_ISIS_FLAGS = 1030         # 1 byte
NA_OPAQUE_NODE = 1031        # Variable (opaque data)
NA_NODE_MSD = 1066           # RFC 8814 (MSD TLV)

# Node SR TLVs (RFC 8571)
NA_SR_CAPABILITIES = 1034    # SR capabilities
NA_SR_ALGORITHM = 1035       # SR algorithm(s)
NA_SR_LOCAL_BLOCK = 1036     # SR local block (SRLB)
NA_SRMS_PREFERENCE = 1038    # SRMS preference

# Flex-Algorithm Node TLVs (RFC 9088)
NA_FLEX_ALGO_DEF = 1039      # Flex-Algorithm Definition
NA_FLEX_ALGO_EXCL_ANY = 1040 # Flex-Algo Exclude-Any Affinity

NA_TYPE_NAMES = {
    NA_MT_IDS: "Multi-Topology IDs",
    NA_OSPF_NODE_PROPS: "OSPF Node Properties",
    NA_ISIS_AREA_ID: "IS-IS Area Identifier",
    NA_IPV4_ROUTER_ID_LOCAL: "IPv4 Router-ID (Local)",
    NA_IPV6_ROUTER_ID_LOCAL: "IPv6 Router-ID (Local)",
    NA_NODE_NAME: "Node Name",
    NA_ISIS_FLAGS: "IS-IS Flags",
    NA_OPAQUE_NODE: "Opaque Node Attribute",
    NA_NODE_MSD: "Node MSD",
    NA_SR_CAPABILITIES: "SR Capabilities",
    NA_SR_ALGORITHM: "SR Algorithm",
    NA_SR_LOCAL_BLOCK: "SR Local Block",
    NA_SRMS_PREFERENCE: "SRMS Preference",
    NA_FLEX_ALGO_DEF: "Flex-Algorithm Definition",
    NA_FLEX_ALGO_EXCL_ANY: "Flex-Algo Excl-Any Affinity",
}

# ---------------------------------------------------------------------------
# BGP-LS Attribute TLV Types — Link (RFC 7752 §3.3.2)
# ---------------------------------------------------------------------------
LA_IPV4_ROUTER_ID_LOCAL = 1088
LA_IPV6_ROUTER_ID_LOCAL = 1089
LA_IPV4_ROUTER_ID_REMOTE = 1090
LA_IPV6_ROUTER_ID_REMOTE = 1091
LA_ADMIN_GROUP = 1092        # 4 bytes (bitmask)
LA_MAX_LINK_BW = 1093        # 4 bytes IEEE float (bps)
LA_MAX_RESERV_BW = 1094      # 4 bytes IEEE float (bps)
LA_UNRESERVED_BW = 1095      # 32 bytes (8 x 4-byte IEEE float, per CoS)
LA_TE_DEFAULT_METRIC = 1096  # 4 bytes
LA_LINK_PROT_TYPE = 1097     # 2 bytes
LA_MPLS_PROTO_MASK = 1098    # 1 byte
LA_IGP_METRIC = 1099         # 1–3 bytes (IS-IS=3, OSPF=4 actually variable)
LA_SRLG = 1100               # variable (n * 4 bytes)
LA_OPAQUE_LINK = 1101        # variable
LA_LINK_NAME = 1102          # variable (string)
LA_ADJ_SID = 1114            # RFC 8571
LA_LAN_ADJ_SID = 1115        # RFC 8571
LA_UNIDIR_LINK_DELAY = 1116  # RFC 8570
LA_UNIDIR_DELAY_MIN_MAX = 1117
LA_UNIDIR_DELAY_VAR = 1118
LA_UNIDIR_LINK_LOSS = 1119
LA_UNIDIR_RESIDUAL_BW = 1120
LA_UNIDIR_AVAIL_BW = 1121
LA_UNIDIR_UTIL_BW = 1122
LA_EXT_ADMIN_GROUP = 1173    # RFC 7308 extended admin group
LA_ADJ_SID_EPE_PEER_NODE = 1286  # draft EPE peer node SID

LA_TYPE_NAMES = {
    LA_IPV4_ROUTER_ID_LOCAL: "IPv4 Router-ID (Local)",
    LA_IPV6_ROUTER_ID_LOCAL: "IPv6 Router-ID (Local)",
    LA_IPV4_ROUTER_ID_REMOTE: "IPv4 Router-ID (Remote)",
    LA_IPV6_ROUTER_ID_REMOTE: "IPv6 Router-ID (Remote)",
    LA_ADMIN_GROUP: "Admin Group",
    LA_MAX_LINK_BW: "Max Link Bandwidth",
    LA_MAX_RESERV_BW: "Max Reservable Bandwidth",
    LA_UNRESERVED_BW: "Unreserved Bandwidth",
    LA_TE_DEFAULT_METRIC: "TE Default Metric",
    LA_LINK_PROT_TYPE: "Link Protection Type",
    LA_MPLS_PROTO_MASK: "MPLS Protocol Mask",
    LA_IGP_METRIC: "IGP Metric",
    LA_SRLG: "SRLG",
    LA_OPAQUE_LINK: "Opaque Link Attribute",
    LA_LINK_NAME: "Link Name",
    LA_ADJ_SID: "Adjacency SID",
    LA_LAN_ADJ_SID: "LAN Adjacency SID",
    LA_UNIDIR_LINK_DELAY: "Unidirectional Link Delay",
    LA_UNIDIR_DELAY_MIN_MAX: "Unidirectional Delay Min/Max",
    LA_UNIDIR_DELAY_VAR: "Unidirectional Delay Variation",
    LA_UNIDIR_LINK_LOSS: "Unidirectional Link Loss",
    LA_UNIDIR_RESIDUAL_BW: "Unidirectional Residual BW",
    LA_UNIDIR_AVAIL_BW: "Unidirectional Available BW",
    LA_UNIDIR_UTIL_BW: "Unidirectional Utilized BW",
    LA_EXT_ADMIN_GROUP: "Extended Admin Group",
    LA_ADJ_SID_EPE_PEER_NODE: "EPE Peer Node SID",
}

# ---------------------------------------------------------------------------
# BGP-LS Attribute TLV Types — Prefix (RFC 7752 §3.3.3)
# ---------------------------------------------------------------------------
PRA_IGP_FLAGS = 1152         # 1 byte
PRA_IGP_ROUTE_TAG = 1153     # variable (n * 4 bytes)
PRA_EXT_IGP_ROUTE_TAG = 1154 # variable (n * 8 bytes)
PRA_PREFIX_METRIC = 1155     # 4 bytes
PRA_OSPF_FWD_ADDR = 1156     # 4 or 16 bytes
PRA_OPAQUE_PREFIX = 1157     # variable
PRA_PREFIX_SID = 1158        # RFC 8571
PRA_RANGE = 1159             # RFC 8571
PRA_IPV6_SRC_ROUTER_ID = 1170
PRA_PREFIX_ATTR_FLAGS = 1181

PRA_TYPE_NAMES = {
    PRA_IGP_FLAGS: "IGP Flags",
    PRA_IGP_ROUTE_TAG: "IGP Route Tag",
    PRA_EXT_IGP_ROUTE_TAG: "Extended IGP Route Tag",
    PRA_PREFIX_METRIC: "Prefix Metric",
    PRA_OSPF_FWD_ADDR: "OSPF Forwarding Address",
    PRA_OPAQUE_PREFIX: "Opaque Prefix Attribute",
    PRA_PREFIX_SID: "Prefix SID",
    PRA_RANGE: "SID/Label Range",
    PRA_IPV6_SRC_ROUTER_ID: "IPv6 Source Router-ID",
    PRA_PREFIX_ATTR_FLAGS: "Prefix Attribute Flags",
}

# ---------------------------------------------------------------------------
# BGP Notification Error Codes (RFC 4271 §6.2)
# ---------------------------------------------------------------------------
ERR_HEADER = 1
ERR_OPEN = 2
ERR_UPDATE = 3
ERR_HOLD_TIMER_EXPIRED = 4
ERR_FSM = 5
ERR_CEASE = 6

ERR_HEADER_NAMES = {
    1: "Connection Not Synchronized",
    2: "Bad Message Length",
    3: "Bad Message Type",
}
ERR_OPEN_NAMES = {
    1: "Unsupported Version Number",
    2: "Bad Peer AS",
    3: "Bad BGP Identifier",
    4: "Unsupported Optional Parameter",
    6: "Unacceptable Hold Time",
    7: "Unsupported Capability",
}
ERR_UPDATE_NAMES = {
    1: "Malformed Attribute List",
    2: "Unrecognized Well-known Attribute",
    3: "Missing Well-known Attribute",
    4: "Attribute Flags Error",
    5: "Attribute Length Error",
    6: "Invalid ORIGIN Attribute",
    8: "Invalid NEXT_HOP Attribute",
    9: "Optional Attribute Error",
    10: "Invalid Network Field",
    11: "Malformed AS_PATH",
}
ERR_CEASE_SUBCODES = {
    1: "Maximum Number of Prefixes Reached",
    2: "Administrative Shutdown",
    3: "Peer De-configured",
    4: "Administrative Reset",
    5: "Connection Rejected",
    6: "Other Configuration Change",
    7: "Connection Collision Resolution",
    8: "Out of Resources",
}

# ---------------------------------------------------------------------------
# BGP FSM States
# ---------------------------------------------------------------------------
STATE_IDLE = "IDLE"
STATE_CONNECT = "CONNECT"
STATE_ACTIVE = "ACTIVE"
STATE_OPENSENT = "OPENSENT"
STATE_OPENCONFIRM = "OPENCONFIRM"
STATE_ESTABLISHED = "ESTABLISHED"

# ---------------------------------------------------------------------------
# Link Protection Type bitmask (RFC 4203)
# ---------------------------------------------------------------------------
PROT_EXTRA_TRAFFIC = 0x01
PROT_UNPROTECTED = 0x02
PROT_SHARED = 0x04
PROT_DEDICATED_1_1 = 0x08
PROT_DEDICATED_1_PLUS_1 = 0x10
PROT_ENHANCED = 0x20

# ---------------------------------------------------------------------------
# MPLS Protocol Mask bitmask (RFC 7752)
# ---------------------------------------------------------------------------
MPLS_LDPV4 = 0x80
MPLS_RSVPTE = 0x40
MPLS_SR_TE = 0x20  # draft

# ---------------------------------------------------------------------------
# SR Capability flags (RFC 8571)
# ---------------------------------------------------------------------------
SR_CAP_FLAG_I = 0x80   # IS-IS SR
SR_CAP_FLAG_V = 0x40   # IPv6 SR

# Adjacency SID flags (RFC 8571)
ADJ_SID_FLAG_F = 0x80   # Address-Family: 0=IPv4, 1=IPv6
ADJ_SID_FLAG_B = 0x40   # Backup
ADJ_SID_FLAG_V = 0x20   # Value (SID is value, not label index)
ADJ_SID_FLAG_L = 0x10   # Local
ADJ_SID_FLAG_S = 0x08   # Set (group SID)
ADJ_SID_FLAG_P = 0x04   # Persistent

# Prefix SID flags (RFC 8571)
PFX_SID_FLAG_R = 0x80   # Re-advertisement
PFX_SID_FLAG_N = 0x40   # Node-SID
PFX_SID_FLAG_P = 0x20   # No-PHP (penultimate hop popping disabled)
PFX_SID_FLAG_E = 0x10   # Explicit-Null
PFX_SID_FLAG_V = 0x08   # Value (SID is explicit value)
PFX_SID_FLAG_L = 0x04   # Local

# IGP Flags (Prefix Attribute, RFC 7752)
IGP_FLAG_D = 0x80   # IS-IS Up/Down bit
IGP_FLAG_N = 0x40   # OSPF no-unicast
IGP_FLAG_L = 0x20   # OSPF local address
IGP_FLAG_P = 0x10   # OSPF propagate NSSA

# ---------------------------------------------------------------------------
# Multi-Topology ID well-known values (RFC 4915 / RFC 5120)
# ---------------------------------------------------------------------------
MT_IPV4_UNICAST = 0
MT_IPV6_UNICAST = 2
MT_IPV4_MULTICAST = 3
MT_IPV6_MULTICAST = 4
MT_IPV4_MGMT = 5
MT_IPV6_MGMT = 6

MT_NAMES = {
    MT_IPV4_UNICAST: "IPv4 Unicast",
    MT_IPV6_UNICAST: "IPv6 Unicast",
    MT_IPV4_MULTICAST: "IPv4 Multicast",
    MT_IPV6_MULTICAST: "IPv6 Multicast",
    MT_IPV4_MGMT: "IPv4 Management",
    MT_IPV6_MGMT: "IPv6 Management",
}
