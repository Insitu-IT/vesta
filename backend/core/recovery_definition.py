"""Extract only required destination mapping identities from verified VM metadata."""

import base64
import re
from xml.etree import ElementTree

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.storage_receipt_v2 import decode

MAX_DOMAIN_XML = 1024 * 1024
MAX_VM_DEFINITION = 2 * 1024 * 1024
MAX_ENCODED_DEFINITION = 4 * 1024 * 1024
MAX_MANIFEST_TOTAL = 64 * 1024 * 1024
VNBU_HEADER = b"VNBU\x01"
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
NATIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def decrypt_capture(body, key, maximum):
    """Decode bounded VNBU v1 metadata frames without releasing unauthenticated bytes."""
    if key is None:
        if not 0 < len(body) <= maximum:
            raise ValueError("Invalid captured definition length")
        return body
    if not body.startswith(VNBU_HEADER) or len(key) != 32:
        raise ValueError("Invalid captured definition encryption")
    cipher = AESGCM(key)
    output = bytearray()
    offset = len(VNBU_HEADER)
    while offset < len(body):
        frame_start = offset + 4
        count = int.from_bytes(body[offset:frame_start], "big")
        end = frame_start + count
        if not 28 < count <= maximum - len(output) + 28 or end > len(body):
            raise ValueError("Invalid captured definition frame")
        output.extend(
            cipher.decrypt(
                body[frame_start : frame_start + 12], body[frame_start + 12 : end], None
            )
        )
        offset = end
    if not output:
        raise ValueError("Captured VM definition is empty")
    return bytes(output)


def native_requirements(body, manifest):
    xml = body.decode("utf-8")
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        raise ValueError("Unsupported captured XML declaration")
    domain = ElementTree.fromstring(xml)
    name = domain.findtext("name")
    if (
        domain.tag != "domain"
        or domain.get("type") != "kvm"
        or domain.findtext("uuid") != manifest["domain_uuid"]
        or not isinstance(name, str)
        or not 0 < len(name) <= 255
    ):
        raise ValueError("Captured domain identity differs")
    devices = domain.find("devices")
    if devices is None:
        raise ValueError("Captured domain devices are unavailable")
    interfaces = devices.findall("interface")
    if len(interfaces) > 128:
        raise ValueError("Captured domain exceeds interface limit")
    captured, seen = [], set()
    for interface in interfaces:
        mac = interface.find("mac")
        address = mac.get("address") if mac is not None else None
        if (
            not isinstance(address, str)
            or not MAC.fullmatch(address)
            or address in seen
        ):
            raise ValueError("Invalid captured interface identity")
        seen.add(address)
        source = interface.find("source")
        network = (
            source.get("network")
            if source is not None and interface.get("type") == "network"
            else None
        )
        captured.append(
            {
                "source_mac": address,
                "source_network": (
                    network if network and NATIVE_NAME.fullmatch(network) else None
                ),
            }
        )
    return name, {"interfaces": captured}


def kubevirt_definition(archive, key):
    if not isinstance(archive, str) or not 0 < len(archive) <= MAX_ENCODED_DEFINITION:
        raise ValueError("Invalid captured VM definition size")
    body = decrypt_capture(
        base64.b64decode(archive, validate=True), key, MAX_VM_DEFINITION
    )
    return decode(body)


def kubevirt_requirements(definition, plan):
    source = plan["source"]
    metadata = definition["metadata"]
    if (
        set(definition) != {"apiVersion", "kind", "metadata", "spec"}
        or definition["apiVersion"] != "kubevirt.io/v1"
        or definition["kind"] != "VirtualMachine"
        or metadata["namespace"] != source["namespace"]
        or metadata["name"] != plan["vm_name"]
        or metadata["uid"] != source["vm_uid"]
        or metadata.get("resourceVersion") is None
    ):
        raise ValueError("Captured VM identity differs")
    guest = definition["spec"]["template"]["spec"]
    source_networks = guest.get("networks", [])
    source_interfaces = guest["domain"]["devices"].get("interfaces", [])
    if (
        not isinstance(source_networks, list)
        or not isinstance(source_interfaces, list)
        or len(source_networks) > 32
        or len(source_interfaces) > 32
    ):
        raise ValueError("Invalid captured network inventory")
    interfaces = {}
    for interface in source_interfaces:
        name = interface["name"]
        mac = interface.get("macAddress")
        if not DNS.fullmatch(name) or name in interfaces:
            raise ValueError("Invalid captured interface")
        # KubeVirt replaces captured MACs; the required mapping key is its
        # interface/network name. A MAC is a display hint only.
        interfaces[name] = (
            mac.lower() if isinstance(mac, str) and MAC.fullmatch(mac.lower()) else None
        )
    networks = {}
    for network in source_networks:
        name = network["name"]
        source_types = {"pod", "multus"} & network.keys()
        if not DNS.fullmatch(name) or name in networks or len(source_types) != 1:
            raise ValueError("Invalid captured network")
        networks[name] = {
            "name": name,
            "type": next(iter(source_types)),
            "source_mac": interfaces.get(name),
        }
    if set(interfaces) - networks.keys():
        raise ValueError("Captured interface lacks an explicit network")

    protected = {
        volume["name"] for volume in source.get("native_volumes", source["volumes"])
    }
    dependencies = set()

    def add(kind, name):
        if not isinstance(name, str) or not DNS.fullmatch(name):
            raise ValueError("Invalid captured dependency identity")
        dependencies.add((kind, name))

    volumes = guest["volumes"]
    if not isinstance(volumes, list) or len(volumes) > 512:
        raise ValueError("Invalid captured volume inventory")
    for volume in volumes:
        if volume["name"] in protected:
            continue
        for kind, data in volume.items():
            if kind == "containerDisk" and data.get("imagePullSecret"):
                add("secret", data["imagePullSecret"])
            elif kind in {"cloudInitNoCloud", "cloudInitConfigDrive"}:
                for field in ("secretRef", "networkDataSecretRef"):
                    if field in data:
                        add("secret", data[field]["name"])
            elif kind in {"secret", "configMap"}:
                add(kind, data["secretName" if kind == "secret" else "name"])
    return plan["vm_name"], {
        "networks": list(networks.values()),
        "dependencies": [
            {"kind": kind, "name": name} for kind, name in sorted(dependencies)
        ],
    }
