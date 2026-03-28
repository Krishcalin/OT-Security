"""
ICS Engineering Project File Parsers.

Each parser returns a list of OTDevice instances populated with ground-truth
identity and business-context fields extracted from the project file.

Supported formats:
  - Siemens TIA Portal (.zap16 / .ap16) — ZIP archive containing XML
  - Rockwell Studio 5000 (.L5X)         — Plain XML export
  - Schneider EcoStruxure (.XEF)        — Plain XML export
  - Generic CSV (.csv)                  — Header-row asset inventory / CMDB
  - Generic JSON (.json)                — Array or {devices:[...]} inventory

All parsers use only Python stdlib (xml.etree.ElementTree, zipfile, json, csv).
All are best-effort / fault-tolerant — vendor file formats vary across versions.
"""

import csv
import json
import logging
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from ..models import OTDevice

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════ helpers ═══

def _detect_namespace(root: ET.Element) -> str:
    """Detect and return the XML namespace prefix string for findall()."""
    tag = root.tag
    if tag.startswith("{"):
        return tag[1:tag.index("}")] + "}"
    return ""


def _ns_wrap(ns: str) -> str:
    """Wrap a namespace URI for use in findall: '{uri}'."""
    return "{" + ns + "}" if ns else ""


def _text(parent: ET.Element, tag: str) -> Optional[str]:
    """Safely get text content of a child element."""
    child = parent.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return None


def _is_valid_ip(s: str) -> bool:
    """Check if a string looks like a valid IPv4 address."""
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _find_any(elem: ET.Element, tags: List[str]) -> Optional[ET.Element]:
    """Return the first child matching any of the given XPath tags."""
    for tag in tags:
        hit = elem.find(tag)
        if hit is not None:
            return hit
    return None


def _findall_any(elem: ET.Element, tags: List[str]) -> List[ET.Element]:
    """Return all children matching any of the given XPath tags (deduplicated)."""
    seen = set()
    results = []
    for tag in tags:
        for child in elem.findall(tag):
            eid = id(child)
            if eid not in seen:
                seen.add(eid)
                results.append(child)
    return results


def _get_attr(elem: ET.Element, *names: str) -> Optional[str]:
    """Return the first non-empty attribute value from the element."""
    for name in names:
        val = elem.get(name)
        if val:
            return val.strip()
    return None


# ══════════════════════════════════════════════ Siemens TIA Portal ════

def parse_tia_portal(path: str) -> List[OTDevice]:
    """
    Parse a Siemens TIA Portal project archive (.zap16 / .ap16).

    These are ZIP files containing XML hardware configuration.
    Extracts: CPU model, firmware, serial, rack/slot, I/O modules, IP address.
    """
    devices: List[OTDevice] = []

    try:
        with zipfile.ZipFile(path, "r") as zf:
            xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            for xml_name in xml_names:
                try:
                    with zf.open(xml_name) as xf:
                        tree = ET.parse(xf)
                        root = tree.getroot()
                        devices.extend(_extract_tia_devices(root))
                except ET.ParseError:
                    logger.debug("Skipping non-XML or malformed: %s", xml_name)
                except Exception as exc:
                    logger.debug("Error parsing %s in ZIP: %s", xml_name, exc)
    except zipfile.BadZipFile:
        logger.warning("Not a valid ZIP file: %s", path)
    except Exception as exc:
        logger.warning("Failed to open TIA Portal archive %s: %s", path, exc)

    return devices


def _extract_tia_devices(root: ET.Element) -> List[OTDevice]:
    """Extract device records from a TIA Portal XML tree."""
    results: List[OTDevice] = []
    ns = _detect_namespace(root)
    nsp = _ns_wrap(ns)

    # Try multiple XPath strategies for different TIA versions
    device_elements = _findall_any(root, [
        f".//{nsp}Device", f".//{nsp}station", f".//{nsp}HW.Device",
        ".//Device", ".//station", ".//HW.Device",
    ])

    for dev_elem in device_elements:
        try:
            dev = _parse_tia_device_element(dev_elem, nsp)
            if dev and dev.ip:
                results.append(dev)
        except Exception as exc:
            logger.debug("Skipping TIA device element: %s", exc)

    return results


def _parse_tia_device_element(
    elem: ET.Element, ns: str,
) -> Optional[OTDevice]:
    """Parse a single TIA Portal device element into an OTDevice."""
    # Order number / product code
    product_code = (
        _get_attr(elem, "OrderNumber", "orderNumber")
        or _text(elem, f".//{ns}OrderNumber")
        or _text(elem, f".//{ns}TypeIdentifier")
        or _text(elem, ".//OrderNumber")
    )

    # Firmware version
    firmware = (
        _get_attr(elem, "FirmwareVersion", "firmwareVersion")
        or _text(elem, f".//{ns}Firmware")
        or _text(elem, f".//{ns}FirmwareVersion")
        or _text(elem, ".//FirmwareVersion")
    )

    # CPU identification
    cpu_elem = _find_any(elem, [
        f".//{ns}CPU", f".//{ns}ProcessorUnit", f".//{ns}CentralModule",
        ".//CPU", ".//ProcessorUnit", ".//CentralModule",
    ])

    model = None
    serial = None
    cpu_info = None
    rack: Optional[int] = None
    slot: Optional[int] = None

    if cpu_elem is not None:
        model = (
            _get_attr(cpu_elem, "Name", "name")
            or _text(cpu_elem, "Name") or _text(cpu_elem, f"{ns}Name")
        )
        serial = _get_attr(cpu_elem, "SerialNumber", "serialNumber")
        cpu_info = model

        rack_str = _get_attr(cpu_elem, "Rack", "rack")
        slot_str = _get_attr(cpu_elem, "Slot", "slot")
        if rack_str:
            try:
                rack = int(rack_str)
            except ValueError:
                pass
        if slot_str:
            try:
                slot = int(slot_str)
            except ValueError:
                pass

    # IP address from network interface
    ip = None
    for iface in _findall_any(elem, [
        f".//{ns}Interface", f".//{ns}NetworkInterface", f".//{ns}Subnet",
        ".//Interface", ".//NetworkInterface", ".//Subnet",
    ]):
        candidate = (
            _get_attr(iface, "IPAddress", "ipAddress", "Address", "address")
            or _text(iface, f".//{ns}IPAddress")
            or _text(iface, f".//{ns}Address")
            or _text(iface, ".//IPAddress")
            or _text(iface, ".//Address")
        )
        if candidate and _is_valid_ip(candidate):
            ip = candidate
            break

    if not ip:
        return None

    # I/O Modules
    modules: List[Dict] = []
    for mod_elem in _findall_any(elem, [
        f".//{ns}Module", f".//{ns}IOModule", ".//Module", ".//IOModule",
    ]):
        mod_info: Dict = {}
        s = _get_attr(mod_elem, "Slot", "slot")
        if s:
            mod_info["slot"] = s
        on = _get_attr(mod_elem, "OrderNumber", "orderNumber")
        if on:
            mod_info["order_number"] = on
        desc = (
            _get_attr(mod_elem, "Description", "description")
            or _text(mod_elem, "Description")
        )
        if desc:
            mod_info["description"] = desc
        if mod_info:
            modules.append(mod_info)

    dev = OTDevice(ip=ip)
    dev.vendor = "Siemens"
    dev.make = "Siemens"
    dev.model = model
    dev.firmware = firmware
    dev.serial_number = serial
    dev.product_code = product_code
    dev.rack = rack
    dev.slot = slot
    dev.cpu_info = cpu_info
    dev.modules = modules
    dev.device_type = "PLC"
    dev.role = "plc"
    return dev


# ═══════════════════════════════════════════ Rockwell Studio 5000 ═════

def parse_rockwell_l5x(path: str) -> List[OTDevice]:
    """
    Parse a Rockwell Studio 5000 L5X export (.L5X).

    Plain XML with Controller + Modules structure.
    Extracts: ProcessorType, revision, serial, Ethernet IP, module inventory.
    """
    devices: List[OTDevice] = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.warning("Invalid XML in L5X file %s: %s", path, exc)
        return devices
    except Exception as exc:
        logger.warning("Cannot read L5X file %s: %s", path, exc)
        return devices

    for ctrl in root.findall(".//Controller") or root.findall("Controller"):
        try:
            dev = _parse_l5x_controller(ctrl)
            if dev and dev.ip:
                devices.append(dev)
        except Exception as exc:
            logger.debug("Skipping L5X controller: %s", exc)

    return devices


def _parse_l5x_controller(ctrl: ET.Element) -> Optional[OTDevice]:
    """Parse a single Controller element from L5X XML."""
    processor_type = ctrl.get("ProcessorType", "")
    major_rev = ctrl.get("MajorRev", "")
    minor_rev = ctrl.get("MinorRev", "")
    serial = ctrl.get("SerialNumber", "")
    ctrl_name = ctrl.get("Name", "")

    # Clean serial number (strip "16#" hex prefix)
    if serial.startswith("16#"):
        serial = serial[3:].replace("_", "")

    firmware = None
    if major_rev:
        firmware = f"V{major_rev}.{minor_rev}" if minor_rev else f"V{major_rev}"

    # Find Ethernet IP address and build module inventory
    ip = None
    modules_info: List[Dict] = []

    for module in ctrl.findall(".//Module"):
        cat_num = module.get("CatalogNumber", "")
        mod_name = module.get("Name", "")
        mod_major = module.get("Major", "")
        mod_minor = module.get("Minor", "")

        # Check for Ethernet port with IP address
        for port in module.findall(".//Port"):
            port_type = port.get("Type", "")
            address = port.get("Address", "")
            if port_type.lower() == "ethernet" and address and _is_valid_ip(address):
                if ip is None:
                    ip = address

        # Collect non-local modules for inventory
        if cat_num and mod_name.lower() != "local":
            modules_info.append({
                "name": mod_name,
                "catalog_number": cat_num,
                "firmware": f"V{mod_major}.{mod_minor}" if mod_major else "",
            })

    if not ip:
        return None

    dev = OTDevice(ip=ip)
    dev.vendor = "Rockwell Automation"
    dev.make = "Allen-Bradley"
    dev.model = processor_type
    dev.firmware = firmware
    dev.serial_number = serial if serial else None
    dev.product_code = processor_type
    dev.cpu_info = f"{ctrl_name} ({processor_type})" if ctrl_name else processor_type
    dev.modules = modules_info
    dev.device_type = "PLC"
    dev.role = "plc"
    return dev


# ═══════════════════════════════════════ Schneider EcoStruxure ════════

def parse_schneider_xef(path: str) -> List[OTDevice]:
    """
    Parse a Schneider EcoStruxure XEF export (.XEF).

    Plain XML with resource / processor / network structure.
    Extracts: CPU type, firmware, serial, IP, I/O modules.
    """
    devices: List[OTDevice] = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.warning("Invalid XML in XEF file %s: %s", path, exc)
        return devices
    except Exception as exc:
        logger.warning("Cannot read XEF file %s: %s", path, exc)
        return devices

    ns = _detect_namespace(root)
    nsp = _ns_wrap(ns)

    resource_elements = _findall_any(root, [
        f".//{nsp}resource", f".//{nsp}Resource",
        f".//{nsp}device", f".//{nsp}Device",
        ".//resource", ".//Resource", ".//device", ".//Device",
    ])

    for res in resource_elements:
        try:
            dev = _parse_xef_resource(res, nsp)
            if dev and dev.ip:
                devices.append(dev)
        except Exception as exc:
            logger.debug("Skipping XEF resource: %s", exc)

    return devices


def _parse_xef_resource(
    elem: ET.Element, ns: str,
) -> Optional[OTDevice]:
    """Parse a single Schneider XEF resource/device element."""
    # Processor / CPU element
    proc = _find_any(elem, [
        f".//{ns}processor", f".//{ns}Processor", f".//{ns}CPU",
        ".//processor", ".//Processor", ".//CPU",
    ])

    model = None
    firmware = None
    serial = None

    if proc is not None:
        model = _get_attr(proc, "type", "Type", "reference", "Reference")
        firmware = _get_attr(proc, "firmware", "Firmware", "firmwareVersion")
        serial = _get_attr(proc, "serialNumber", "SerialNumber")

    # Network interface for IP
    ip = None
    for iface in _findall_any(elem, [
        f".//{ns}interface", f".//{ns}Interface", f".//{ns}ethernet",
        ".//interface", ".//Interface", ".//ethernet",
    ]):
        candidate = _get_attr(
            iface, "ip", "IP", "IPAddress", "ipAddress", "address", "Address",
        )
        if candidate and _is_valid_ip(candidate):
            ip = candidate
            break

    if not ip:
        return None

    # I/O Modules
    modules: List[Dict] = []
    for mod_elem in _findall_any(elem, [
        f".//{ns}module", f".//{ns}Module", f".//{ns}ioModule",
        ".//module", ".//Module", ".//ioModule",
    ]):
        mod_info: Dict = {}
        s = _get_attr(mod_elem, "slot", "Slot")
        if s:
            mod_info["slot"] = s
        ref = _get_attr(mod_elem, "reference", "Reference")
        if ref:
            mod_info["reference"] = ref
        desc = _get_attr(mod_elem, "description", "Description")
        if desc:
            mod_info["description"] = desc
        if mod_info:
            modules.append(mod_info)

    dev = OTDevice(ip=ip)
    dev.vendor = "Schneider Electric"
    dev.make = "Schneider Electric"
    dev.model = model
    dev.firmware = firmware
    dev.serial_number = serial
    dev.modules = modules
    dev.device_type = "PLC"
    dev.role = "plc"
    return dev


# ══════════════════════════════════════════════════ Generic CSV ═══════

# CSV column name -> OTDevice attribute mapping (case-insensitive)
_CSV_FIELD_MAP = {
    "ip":                "ip",
    "ip_address":        "ip",
    "ipaddress":         "ip",
    "vendor":            "vendor",
    "make":              "make",
    "manufacturer":      "make",
    "model":             "model",
    "product":           "model",
    "firmware":          "firmware",
    "firmware_version":  "firmware",
    "serial":            "serial_number",
    "serial_number":     "serial_number",
    "serialnumber":      "serial_number",
    "hardware_version":  "hardware_version",
    "product_code":      "product_code",
    "catalog_number":    "product_code",
    "device_type":       "device_type",
    "type":              "device_type",
    "role":              "role",
    "asset_owner":       "asset_owner",
    "owner":             "asset_owner",
    "location":          "location",
    "site":              "location",
    "asset_tag":         "asset_tag",
    "tag":               "asset_tag",
    "criticality":       "device_criticality",
    "device_criticality": "device_criticality",
    "hostname":          "hostname",
    "mac":               "mac",
    "mac_address":       "mac",
    "cpu_info":          "cpu_info",
    "notes":             "_notes",     # special: appended to notes list
    "rack":              "_rack",      # special: int conversion
    "slot":              "_slot",      # special: int conversion
}


def parse_csv_inventory(path: str) -> List[OTDevice]:
    """
    Parse a generic CSV asset inventory file.

    Requires at minimum an 'ip' or 'ip_address' column.
    All other columns are mapped to OTDevice fields by name.
    """
    devices: List[OTDevice] = []
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                logger.warning("CSV file has no header row: %s", path)
                return devices

            # Build column mapping (case-insensitive, underscored)
            col_map: Dict[str, str] = {}
            for col in reader.fieldnames:
                normalised = col.strip().lower().replace(" ", "_")
                if normalised in _CSV_FIELD_MAP:
                    col_map[col] = _CSV_FIELD_MAP[normalised]

            if not any(v == "ip" for v in col_map.values()):
                logger.warning("CSV file has no 'ip' column: %s", path)
                return devices

            for row_num, row in enumerate(reader, start=2):
                try:
                    dev = _csv_row_to_device(row, col_map)
                    if dev and dev.ip:
                        devices.append(dev)
                except Exception as exc:
                    logger.debug("Skipping CSV row %d: %s", row_num, exc)

    except Exception as exc:
        logger.warning("Cannot read CSV file %s: %s", path, exc)

    return devices


def _csv_row_to_device(
    row: Dict[str, str], col_map: Dict[str, str],
) -> Optional[OTDevice]:
    """Convert a single CSV row into an OTDevice."""
    ip_val = None
    attrs: Dict[str, str] = {}

    for csv_col, dev_attr in col_map.items():
        val = row.get(csv_col, "").strip()
        if not val:
            continue
        if dev_attr == "ip":
            ip_val = val
        else:
            attrs[dev_attr] = val

    if not ip_val or not _is_valid_ip(ip_val):
        return None

    dev = OTDevice(ip=ip_val)
    for attr, val in attrs.items():
        if attr == "_notes":
            dev.notes.append(val)
        elif attr == "_rack":
            try:
                dev.rack = int(val)
            except ValueError:
                pass
        elif attr == "_slot":
            try:
                dev.slot = int(val)
            except ValueError:
                pass
        elif hasattr(dev, attr):
            setattr(dev, attr, val)

    return dev


# ═════════════════════════════════════════════════ Generic JSON ═══════

# JSON key -> OTDevice attribute mapping
_JSON_FIELD_MAP = {
    "vendor": "vendor", "make": "make", "manufacturer": "make",
    "model": "model", "product": "model",
    "firmware": "firmware", "firmware_version": "firmware",
    "serial_number": "serial_number", "serial": "serial_number",
    "hardware_version": "hardware_version",
    "product_code": "product_code", "catalog_number": "product_code",
    "device_type": "device_type", "type": "device_type",
    "role": "role",
    "asset_owner": "asset_owner", "owner": "asset_owner",
    "location": "location", "site": "location",
    "asset_tag": "asset_tag", "tag": "asset_tag",
    "device_criticality": "device_criticality",
    "criticality": "device_criticality",
    "hostname": "hostname",
    "mac": "mac", "mac_address": "mac",
    "cpu_info": "cpu_info",
}


def parse_json_inventory(path: str) -> List[OTDevice]:
    """
    Parse a generic JSON asset inventory file.

    Expects a JSON array of objects, or an object with a 'devices' /
    'assets' / 'inventory' key containing an array.
    Each object must have an 'ip' or 'ip_address' field.
    """
    devices: List[OTDevice] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in %s: %s", path, exc)
        return devices
    except Exception as exc:
        logger.warning("Cannot read JSON file %s: %s", path, exc)
        return devices

    # Accept either a list or {"devices": [...]}
    if isinstance(data, dict):
        data = (
            data.get("devices")
            or data.get("assets")
            or data.get("inventory")
            or []
        )
    if not isinstance(data, list):
        logger.warning("JSON is not a list of devices: %s", path)
        return devices

    for idx, entry in enumerate(data):
        if not isinstance(entry, dict):
            continue
        try:
            dev = _json_entry_to_device(entry)
            if dev and dev.ip:
                devices.append(dev)
        except Exception as exc:
            logger.debug("Skipping JSON entry %d: %s", idx, exc)

    return devices


def _json_entry_to_device(entry: Dict) -> Optional[OTDevice]:
    """Convert a single JSON object into an OTDevice."""
    ip = (
        entry.get("ip") or entry.get("ip_address")
        or entry.get("ipAddress") or entry.get("IP") or ""
    )
    if isinstance(ip, str):
        ip = ip.strip()
    else:
        ip = str(ip).strip()

    if not ip or not _is_valid_ip(ip):
        return None

    dev = OTDevice(ip=ip)

    # String fields
    for json_key, dev_attr in _JSON_FIELD_MAP.items():
        val = entry.get(json_key)
        if val and isinstance(val, str) and hasattr(dev, dev_attr):
            setattr(dev, dev_attr, val.strip())

    # Integer fields
    for int_key, dev_attr in [("rack", "rack"), ("slot", "slot")]:
        val = entry.get(int_key)
        if val is not None:
            try:
                setattr(dev, dev_attr, int(val))
            except (ValueError, TypeError):
                pass

    # Modules list
    mods = entry.get("modules")
    if isinstance(mods, list):
        dev.modules = [m for m in mods if isinstance(m, dict)]

    # Notes
    notes = entry.get("notes")
    if isinstance(notes, str):
        dev.notes.append(notes)
    elif isinstance(notes, list):
        dev.notes.extend(str(n) for n in notes)

    return dev
