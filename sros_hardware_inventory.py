#!/usr/bin/env python3
"""Nokia SR OS hardware inventory collector using pysros."""

import argparse
import sys
from pysros.management import connect
from pysros.exceptions import ModelProcessingError


def get_connection(host, username, password, port=830, hostkey_verify=True):
    """Establish a pysros NETCONF connection to the SR OS router."""
    return connect(
        host=host,
        username=username,
        password=password,
        port=port,
        hostkey_verify=hostkey_verify,
    )


def get_value(data, *keys, default="N/A"):
    """Safely extract a nested value from pysros data structures."""
    current = data
    for key in keys:
        if current is None:
            return default
        if hasattr(current, "data"):
            current = current.data
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
    if current is None:
        return default
    if hasattr(current, "data"):
        return current.data
    return current


def collect_chassis_info(connection):
    """Collect chassis-level hardware information."""
    try:
        chassis_data = connection.running.get(
            "/nokia-state:state/chassis",
            defaults=True,
        )
    except Exception:
        return []

    chassis_list = []
    if not chassis_data:
        return chassis_list

    items = chassis_data if isinstance(chassis_data, dict) else {}
    for chassis_id, chassis in items.items():
        chassis_list.append(
            {
                "chassis_id": chassis_id,
                "type": get_value(chassis, "type"),
                "part_number": get_value(chassis, "hardware-data", "part-number"),
                "serial_number": get_value(chassis, "hardware-data", "serial-number"),
                "manufacture_date": get_value(
                    chassis, "hardware-data", "manufacture-date"
                ),
                "description": get_value(chassis, "hardware-data", "description"),
                "oper_state": get_value(chassis, "oper-state"),
                "base_mac": get_value(chassis, "base-mac-address"),
            }
        )
    return chassis_list


def collect_card_info(connection):
    """Collect line card / IOM hardware information."""
    try:
        card_data = connection.running.get(
            "/nokia-state:state/card",
            defaults=True,
        )
    except Exception:
        return []

    cards = []
    if not card_data:
        return cards

    items = card_data if isinstance(card_data, dict) else {}
    for slot, card in items.items():
        cards.append(
            {
                "slot": slot,
                "equipped_type": get_value(card, "hardware-data", "part-number"),
                "part_number": get_value(card, "hardware-data", "part-number"),
                "serial_number": get_value(card, "hardware-data", "serial-number"),
                "manufacture_date": get_value(
                    card, "hardware-data", "manufacture-date"
                ),
                "description": get_value(card, "hardware-data", "description"),
                "oper_state": get_value(card, "oper-state"),
                "admin_state": get_value(card, "admin-state"),
            }
        )
    return cards


def collect_mda_info(connection):
    """Collect MDA (Media Dependent Adapter) hardware information."""
    try:
        mda_data = connection.running.get(
            "/nokia-state:state/card/mda",
            defaults=True,
        )
    except Exception:
        return []

    mdas = []
    if not mda_data:
        return mdas

    items = mda_data if isinstance(mda_data, dict) else {}
    for key, mda in items.items():
        slot, mda_slot = (key[0], key[1]) if isinstance(key, tuple) else (key, "")
        mdas.append(
            {
                "card_slot": slot,
                "mda_slot": mda_slot,
                "part_number": get_value(mda, "hardware-data", "part-number"),
                "serial_number": get_value(mda, "hardware-data", "serial-number"),
                "manufacture_date": get_value(
                    mda, "hardware-data", "manufacture-date"
                ),
                "description": get_value(mda, "hardware-data", "description"),
                "oper_state": get_value(mda, "oper-state"),
                "admin_state": get_value(mda, "admin-state"),
            }
        )
    return mdas


def collect_fan_info(connection):
    """Collect fan tray hardware information."""
    try:
        fan_data = connection.running.get(
            "/nokia-state:state/chassis/fan-tray",
            defaults=True,
        )
    except Exception:
        return []

    fans = []
    if not fan_data:
        return fans

    items = fan_data if isinstance(fan_data, dict) else {}
    for fan_id, fan in items.items():
        fans.append(
            {
                "fan_id": fan_id,
                "part_number": get_value(fan, "hardware-data", "part-number"),
                "serial_number": get_value(fan, "hardware-data", "serial-number"),
                "oper_state": get_value(fan, "oper-state"),
                "speed": get_value(fan, "speed"),
            }
        )
    return fans


def collect_power_info(connection):
    """Collect power supply hardware information."""
    try:
        psu_data = connection.running.get(
            "/nokia-state:state/chassis/power-shelf",
            defaults=True,
        )
    except Exception:
        return []

    psus = []
    if not psu_data:
        return psus

    items = psu_data if isinstance(psu_data, dict) else {}
    for psu_id, psu in items.items():
        psus.append(
            {
                "psu_id": psu_id,
                "part_number": get_value(psu, "hardware-data", "part-number"),
                "serial_number": get_value(psu, "hardware-data", "serial-number"),
                "oper_state": get_value(psu, "oper-state"),
                "input_power": get_value(psu, "input-power"),
                "output_power": get_value(psu, "output-power"),
            }
        )
    return psus


def collect_system_info(connection):
    """Collect system-level platform information."""
    try:
        platform_data = connection.running.get(
            "/nokia-state:state/system/platform",
            defaults=True,
        )
    except Exception:
        platform_data = None

    try:
        system_info = connection.running.get(
            "/nokia-conf:configure/system/name",
            defaults=True,
        )
    except Exception:
        system_info = None

    return {
        "hostname": get_value(system_info) if system_info else "N/A",
        "platform": get_value(platform_data, "chassis-type") if platform_data else "N/A",
        "software_version": get_value(platform_data, "software-version") if platform_data else "N/A",
        "uptime": get_value(platform_data, "up-time") if platform_data else "N/A",
    }


def print_separator(width=72):
    print("-" * width)


def print_section(title):
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print("=" * 72)


def print_inventory(host, system_info, chassis_list, cards, mdas, fans, psus):
    """Print hardware inventory in a structured format."""
    print(f"\nNokia SR OS Hardware Inventory Report")
    print(f"Host: {host}")
    print_separator()

    print_section("System Information")
    print(f"  Hostname         : {system_info['hostname']}")
    print(f"  Platform         : {system_info['platform']}")
    print(f"  Software Version : {system_info['software_version']}")
    print(f"  Uptime           : {system_info['uptime']}")

    if chassis_list:
        print_section("Chassis")
        for ch in chassis_list:
            print(f"  Chassis ID       : {ch['chassis_id']}")
            print(f"  Type             : {ch['type']}")
            print(f"  Part Number      : {ch['part_number']}")
            print(f"  Serial Number    : {ch['serial_number']}")
            print(f"  Manufacture Date : {ch['manufacture_date']}")
            print(f"  Description      : {ch['description']}")
            print(f"  Oper State       : {ch['oper_state']}")
            print(f"  Base MAC         : {ch['base_mac']}")
            print_separator()

    if cards:
        print_section("Line Cards / IOMs")
        for card in cards:
            print(f"  Slot             : {card['slot']}")
            print(f"  Part Number      : {card['part_number']}")
            print(f"  Serial Number    : {card['serial_number']}")
            print(f"  Manufacture Date : {card['manufacture_date']}")
            print(f"  Description      : {card['description']}")
            print(f"  Admin State      : {card['admin_state']}")
            print(f"  Oper State       : {card['oper_state']}")
            print_separator()

    if mdas:
        print_section("MDAs (Media Dependent Adapters)")
        for mda in mdas:
            print(f"  Card/MDA Slot    : {mda['card_slot']}/{mda['mda_slot']}")
            print(f"  Part Number      : {mda['part_number']}")
            print(f"  Serial Number    : {mda['serial_number']}")
            print(f"  Manufacture Date : {mda['manufacture_date']}")
            print(f"  Description      : {mda['description']}")
            print(f"  Admin State      : {mda['admin_state']}")
            print(f"  Oper State       : {mda['oper_state']}")
            print_separator()

    if fans:
        print_section("Fan Trays")
        for fan in fans:
            print(f"  Fan ID           : {fan['fan_id']}")
            print(f"  Part Number      : {fan['part_number']}")
            print(f"  Serial Number    : {fan['serial_number']}")
            print(f"  Oper State       : {fan['oper_state']}")
            print(f"  Speed            : {fan['speed']}")
            print_separator()

    if psus:
        print_section("Power Supplies")
        for psu in psus:
            print(f"  PSU ID           : {psu['psu_id']}")
            print(f"  Part Number      : {psu['part_number']}")
            print(f"  Serial Number    : {psu['serial_number']}")
            print(f"  Oper State       : {psu['oper_state']}")
            print(f"  Input Power      : {psu['input_power']}")
            print(f"  Output Power     : {psu['output_power']}")
            print_separator()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect hardware inventory from a Nokia SR OS router via pysros"
    )
    parser.add_argument("host", help="Router hostname or IP address")
    parser.add_argument("--username", "-u", default="admin", help="NETCONF username (default: admin)")
    parser.add_argument("--password", "-p", required=True, help="NETCONF password")
    parser.add_argument("--port", type=int, default=830, help="NETCONF port (default: 830)")
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSH host key verification",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"Connecting to {args.host}:{args.port} ...", file=sys.stderr)

    try:
        connection = get_connection(
            host=args.host,
            username=args.username,
            password=args.password,
            port=args.port,
            hostkey_verify=not args.no_verify,
        )
    except Exception as exc:
        print(f"ERROR: Failed to connect to {args.host}: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Connected. Collecting hardware inventory...", file=sys.stderr)

    try:
        system_info = collect_system_info(connection)
        chassis_list = collect_chassis_info(connection)
        cards = collect_card_info(connection)
        mdas = collect_mda_info(connection)
        fans = collect_fan_info(connection)
        psus = collect_power_info(connection)
    except ModelProcessingError as exc:
        print(f"ERROR: YANG model processing error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to retrieve inventory data: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        connection.disconnect()

    if args.output == "json":
        import json

        inventory = {
            "host": args.host,
            "system": system_info,
            "chassis": chassis_list,
            "cards": cards,
            "mdas": mdas,
            "fans": fans,
            "power_supplies": psus,
        }
        print(json.dumps(inventory, indent=2, default=str))
    else:
        print_inventory(args.host, system_info, chassis_list, cards, mdas, fans, psus)


if __name__ == "__main__":
    main()
