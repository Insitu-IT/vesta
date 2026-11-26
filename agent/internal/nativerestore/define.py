"""Fresh native domain remapping and inactive definition, never VM start."""

import copy
import hashlib
import json
import os
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET

OWNER_NS = "urn:vnbui:restore:1"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def render(request):
    source = ET.fromstring(request["domain_xml"])
    target, manifest = request["target"], request["manifest"]
    require(
        source.tag == "domain" and source.get("type") == "kvm",
        "only native KVM domains are supported",
    )
    require(
        source.findtext("uuid") == manifest["domain_uuid"],
        "captured domain identity differs",
    )
    require(
        NAME.fullmatch(target["vm_name"])
        and target["vm_name"] != source.findtext("name"),
        "fresh domain name required",
    )
    require(
        str(uuid.UUID(target["vm_uuid"])) == target["vm_uuid"]
        and target["vm_uuid"] != manifest["domain_uuid"],
        "fresh domain UUID required",
    )
    require(
        len(request["token"]) == 64
        and all(c in "0123456789abcdef" for c in request["token"]),
        "private restore owner token required",
    )
    require(
        target["drop_excluded_disks"] == manifest["exclusions"],
        "excluded disks must be explicitly dropped",
    )
    protected = {d["target"]: d for d in manifest["disks"]}
    require(target["disks"] == sorted(protected), "all protected disks must be mapped")
    results = {d["target"]: d for d in request["disks"]}
    require(
        len(results) == len(request["disks"]) and set(results) == set(protected),
        "restored disk membership differs",
    )
    # Copy only hardware/guest state that contains no external host resources.
    allowed = {
        "name",
        "uuid",
        "genid",
        "title",
        "description",
        "metadata",
        "memory",
        "currentMemory",
        "vcpu",
        "os",
        "features",
        "cpu",
        "clock",
        "on_poweroff",
        "on_reboot",
        "on_crash",
        "pm",
        "devices",
        "seclabel",
        "resource",
    }
    require(
        all(child.tag in allowed for child in source),
        "unsupported host-bound domain settings",
    )
    resources = source.findall("resource")
    require(len(resources) <= 1, "duplicate source resource partition")
    for resource in resources:
        partition = resource.find("partition")
        require(
            not resource.attrib
            and len(resource) == 1
            and partition is not None
            and not partition.attrib
            and not list(partition)
            and partition.text == "/machine",
            "custom host resource partition is not portable",
        )
    osnode = source.find("os")
    require(
        osnode is not None and osnode.findtext("type") == "hvm",
        "HVM OS definition required",
    )
    require(
        not osnode.attrib
        and all(
            child.tag in {"type", "boot", "bootmenu", "smbios", "bios"}
            for child in osnode
        ),
        "external firmware/kernel state is not protected",
    )
    require(
        osnode.find("smbios") is None or osnode.find("smbios").get("mode") == "emulate",
        "host SMBIOS state is not portable",
    )
    root = ET.Element("domain", {"type": "kvm"})
    ET.SubElement(root, "name").text = target["vm_name"]
    ET.SubElement(root, "uuid").text = target["vm_uuid"]
    metadata = ET.SubElement(root, "metadata")
    ET.SubElement(
        metadata,
        "{" + OWNER_NS + "}restore",
        {
            "id": request["restore_id"],
            "token": request["token"],
            "plan_sha256": request["plan_sha256"],
        },
    )
    for child in source:
        if child.tag not in {
            "name",
            "uuid",
            "genid",
            "title",
            "description",
            "metadata",
            "devices",
            "seclabel",
            "resource",  # Destination libvirt allocates its own default cgroup.
        }:
            root.append(copy.deepcopy(child))
    devices = ET.SubElement(root, "devices")
    original_disks = {d["target"]: d for d in manifest["source"]}
    seen_disks, seen_networks = set(), set()
    networks = {n["source_mac"]: n["network"] for n in target["networks"]}
    require(
        len(networks) == len(target["networks"])
        and all(MAC.fullmatch(k) and NAME.fullmatch(v) for k, v in networks.items()),
        "invalid explicit network mappings",
    )
    for device in source.findall("./devices/*"):
        if device.tag == "disk":
            require(
                device.get("device") == "disk",
                "removable/unprotected storage must be removed from source before backup",
            )
            node, backing, driver = (
                device.find("target"),
                device.find("source"),
                device.find("driver"),
            )
            require(
                node is not None and backing is not None and driver is not None,
                "captured disk mapping incomplete",
            )
            name = node.get("dev")
            known = original_disks.get(name)
            require(
                known is not None and name not in seen_disks,
                "captured disk membership differs",
            )
            expected_path = (
                backing.get("file")
                if device.get("type") == "file"
                else backing.get("dev")
            )
            require(
                expected_path == known["source"]
                and node.get("bus") == known["bus"]
                and driver.get("type") == known["format"],
                "captured disk source differs",
            )
            seen_disks.add(name)
            if name in manifest["exclusions"]:
                continue
            restored = results[name]
            require(
                restored["size_bytes"] == protected[name]["virtual_size"]
                and restored["path"]
                == os.path.join(request["output_path"], name + ".raw"),
                "fresh raw destination differs",
            )
            disk = ET.SubElement(devices, "disk", {"type": "file", "device": "disk"})
            ET.SubElement(
                disk, "driver", {"name": "qemu", "type": "raw", "cache": "none"}
            )
            ET.SubElement(disk, "source", {"file": restored["path"]})
            for tag in ("target", "address", "boot", "serial"):
                old = device.find(tag)
                if old is not None:
                    disk.append(copy.deepcopy(old))
        elif device.tag == "interface":
            mac = device.find("mac")
            address = mac.get("address") if mac is not None else None
            require(
                address in networks and address not in seen_networks,
                "every interface needs its source MAC mapped explicitly",
            )
            seen_networks.add(address)
            network = ET.SubElement(devices, "interface", {"type": "network"})
            ET.SubElement(network, "source", {"network": networks[address]})
            suffix = hashlib.sha256((target["vm_uuid"] + address).encode()).hexdigest()[
                :6
            ]
            ET.SubElement(
                network,
                "mac",
                {
                    "address": "52:54:00:"
                    + ":".join(suffix[i : i + 2] for i in range(0, 6, 2))
                },
            )
            for tag in ("model", "address", "boot"):
                old = device.find(tag)
                if old is not None:
                    network.append(copy.deepcopy(old))
        elif device.tag in {"controller", "video", "memballoon"}:
            devices.append(copy.deepcopy(device))
        elif device.tag == "input":
            require(
                device.get("type") in {"mouse", "tablet", "keyboard"}
                and device.find("source") is None,
                "host input passthrough is not supported",
            )
            devices.append(copy.deepcopy(device))
        elif device.tag == "graphics":
            require(
                device.get("type") in {"vnc", "spice"}, "unsupported graphics device"
            )
            # Console exposure is newly local, not copied source listen/password state.
            graphic = ET.SubElement(
                devices, "graphics", {"type": device.get("type"), "autoport": "yes"}
            )
            ET.SubElement(
                graphic, "listen", {"type": "address", "address": "127.0.0.1"}
            )
        elif device.tag in {"serial", "console"}:
            require(
                device.get("type") == "pty",
                "host character-device paths are not protected",
            )
            new = ET.SubElement(devices, device.tag, {"type": "pty"})
            node = device.find("target")
            if node is not None:
                new.append(copy.deepcopy(node))
        elif device.tag == "channel":
            node = device.find("target")
            require(
                device.get("type") == "unix"
                and node is not None
                and node.get("type") == "virtio",
                "unsupported host channel",
            )
            new = ET.SubElement(devices, "channel", {"type": "unix"})
            copied = copy.deepcopy(node)
            copied.attrib.pop("state", None)  # Runtime-only channel status.
            new.append(copied)  # libvirt allocates a fresh socket.
        elif device.tag == "rng":
            node = device.find("backend")
            require(
                node is not None
                and node.get("model") == "random"
                and node.text in {"/dev/urandom", "/dev/random"},
                "external entropy backend is unsupported",
            )
            devices.append(copy.deepcopy(device))
        elif device.tag == "audio":
            require(
                set(device.attrib) == {"id", "type"}
                and device.get("type") == "none"
                and device.get("id", "").isascii()
                and device.get("id", "").isdigit()
                and int(device.get("id")) > 0
                and not list(device),
                "host audio backend is not portable",
            )
            devices.append(copy.deepcopy(device))
        elif device.tag == "watchdog":
            require(
                device.attrib == {"model": "itco", "action": "reset"}
                and len(device) <= 1
                and all(
                    child.tag == "alias"
                    and set(child.attrib) == {"name"}
                    and NAME.fullmatch(child.get("name", ""))
                    and not list(child)
                    for child in device
                ),
                "only the default virtual itco/reset watchdog is supported",
            )
            # Alias belongs to the old runtime; libvirt mints the fresh one.
            ET.SubElement(devices, "watchdog", dict(device.attrib))
        elif device.tag == "emulator":
            continue  # Installation libvirt selects its configured emulator.
        else:
            raise ValueError("unsupported external or persistent device state")
    require(
        seen_disks == set(original_disks) and seen_networks == set(networks),
        "unused/incomplete destination mapping",
    )
    return ET.tostring(root, encoding="unicode")


def verify_disk_files(request):
    directory = request["output_path"]
    require(
        os.path.realpath(directory) == directory, "destination parent contains symlinks"
    )
    for disk in request["disks"]:
        fd = os.open(disk["path"], os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size == disk["size_bytes"],
                "fresh image identity differs",
            )
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            require(
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                == (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ),
                "fresh image changed",
            )
            require(digest.hexdigest() == disk["sha256"], "fresh image digest differs")


def matching(domain, request):
    require(
        domain.UUIDString() == request["target"]["vm_uuid"]
        and domain.name() == request["target"]["vm_name"],
        "destination domain identity differs",
    )
    require(
        domain.isActive() == 0
        and domain.isPersistent() == 1
        and domain.autostart() == 0,
        "destination is not persistently inactive",
    )
    xml = ET.fromstring(domain.XMLDesc(0))
    owner = xml.find("./metadata/{" + OWNER_NS + "}restore")
    require(
        owner is not None
        and owner.attrib
        == {
            "id": request["restore_id"],
            "token": request["token"],
            "plan_sha256": request["plan_sha256"],
        },
        "destination ownership differs",
    )
    paths = {
        d.find("target").get("dev"): d.find("source").get("file")
        for d in xml.findall("./devices/disk")
    }
    require(
        paths == {d["target"]: d["path"] for d in request["disks"]},
        "destination disk mapping changed",
    )
    actual_networks = sorted(
        d.find("source").get("network") for d in xml.findall("./devices/interface")
    )
    require(
        actual_networks == sorted(n["network"] for n in request["target"]["networks"]),
        "destination network mapping changed",
    )


def define(request, connection=None, library=None):
    xml = render(request)
    verify_disk_files(request)
    if library is None:
        import libvirt as library
    close = connection is None
    connection = connection or library.open(request["uri"])
    require(
        connection is not None
        and any(
            low <= connection.getLibVersion() < high
            for low, high in ((11010000, 11011000), (12007000, 12008000))
        ),
        "validated libvirt 11.10.x or 12.7.x is required",
    )
    try:

        def lookup(method, identity):
            try:
                return method(identity)
            except library.libvirtError as exc:
                if exc.get_error_code() != library.VIR_ERR_NO_DOMAIN:
                    raise
                return None

        by_uuid = lookup(connection.lookupByUUIDString, request["target"]["vm_uuid"])
        by_name = lookup(connection.lookupByName, request["target"]["vm_name"])
        if by_uuid is not None or by_name is not None:
            require(
                by_uuid is not None and by_name is not None,
                "fresh name or UUID collides",
            )
            require(
                not request["allow_create"],
                "target already exists before first definition",
            )
            matching(by_uuid, request)
            matching(by_name, request)
        else:
            require(
                request["allow_create"],
                "uncertain definition disappeared; retain custody",
            )
            for network in request["target"]["networks"]:
                require(
                    connection.networkLookupByName(network["network"]).isActive() == 1,
                    "mapped destination network must be active",
                )
            # UUID is randomly minted for this private operation, never supplied
            # by an arbitrary destination selector. Existing definitions above
            # are never passed to defineXML again, including restart recovery.
            by_uuid = connection.defineXMLFlags(xml, library.VIR_DOMAIN_DEFINE_VALIDATE)
            require(by_uuid is not None, "domain definition acknowledgement missing")
            matching(by_uuid, request)
        return {
            "vm_name": request["target"]["vm_name"],
            "vm_uuid": request["target"]["vm_uuid"],
            "state": "shutoff",
            "disks": request["disks"],
            "plan_sha256": request["plan_sha256"],
        }
    finally:
        if close:
            connection.close()


def main():
    data = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    require(len(data) <= 4 * 1024 * 1024, "restore control input too large")
    request = json.loads(data)
    result = {"xml": render(request)} if sys.argv[1] == "render" else define(request)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Definitions can contain cloud-init-like metadata; never echo inputs.
        print(
            "native restore definition held; inspect private journal and destination prerequisites",
            file=sys.stderr,
        )
        sys.exit(2)
