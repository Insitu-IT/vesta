"""Offline XML remapping and fake libvirt create/replay boundaries."""

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import types
import uuid
import xml.etree.ElementTree as ET

import pytest

spec = importlib.util.spec_from_file_location(
    "native_fresh_define", Path(__file__).with_name("define.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(tmp_path):
    identity = str(uuid.uuid4())
    output = tmp_path / "disks"
    output.mkdir()
    disks = []
    for name in ("vda", "vdb"):
        path = output / (name + ".raw")
        path.write_bytes(name.encode())
        disks.append(
            dict(
                target=name,
                path=str(path),
                size_bytes=3,
                sha256=hashlib.sha256(name.encode()).hexdigest(),
            )
        )
    xml = f"""<domain type="kvm"><name>source</name><uuid>{identity}</uuid><memory unit="MiB">1024</memory><vcpu>2</vcpu><os><type arch="x86_64" machine="pc-q35-10.1">hvm</type></os><devices>
      <disk type="file" device="disk"><driver type="qcow2"/><source file="/live/a"/><target dev="vda" bus="virtio"/></disk>
      <disk type="file" device="disk"><driver type="qcow2"/><source file="/live/b"/><target dev="vdb" bus="virtio"/></disk>
      <interface type="bridge"><mac address="52:54:00:01:02:03"/><source bridge="source-bridge"/><model type="virtio"/></interface>
      <graphics type="vnc" port="5905" passwd="source-private"><listen type="address" address="0.0.0.0"/></graphics>
      <channel type="unix"><source path="/live/guest.sock"/><target type="virtio" name="org.qemu.guest_agent.0"/></channel>
    </devices></domain>"""
    return dict(
        uri="qemu:///system",
        domain_xml=xml,
        manifest=dict(
            domain_uuid=identity,
            source=[
                dict(target="vda", source="/live/a", bus="virtio", format="qcow2"),
                dict(target="vdb", source="/live/b", bus="virtio", format="qcow2"),
            ],
            exclusions=[],
            disks=[
                dict(target=d["target"], virtual_size=d["size_bytes"]) for d in disks
            ],
        ),
        target=dict(
            vm_name="fresh",
            vm_uuid=str(uuid.uuid4()),
            disks=["vda", "vdb"],
            drop_excluded_disks=[],
            networks=[dict(source_mac="52:54:00:01:02:03", network="isolated")],
        ),
        disks=disks,
        restore_id=str(uuid.uuid4()),
        token="a" * 64,
        plan_sha256="b" * 64,
        output_path=str(output),
        allow_create=True,
    )


def test_remaps_both_disks_networks_identity_and_never_mutates_source(tmp_path):
    request = fixture(tmp_path)
    before = deepcopy(request)
    xml = module.render(request)
    root = ET.fromstring(xml)
    assert (
        request == before
        and root.findtext("uuid") != request["manifest"]["domain_uuid"]
    )
    assert [d.find("source").get("file") for d in root.findall("./devices/disk")] == [
        d["path"] for d in request["disks"]
    ]
    assert (
        "/live/" not in xml
        and "source-private" not in xml
        and "source-bridge" not in xml
    )
    assert root.find("./devices/interface/source").get("network") == "isolated"
    assert root.find("./devices/interface/mac").get("address") != "52:54:00:01:02:03"
    assert root.find("./devices/graphics/listen").get("address") == "127.0.0.1"


@pytest.mark.parametrize(
    "fault",
    [
        "same_uuid",
        "same_name",
        "network",
        "disk",
        "excluded",
        "hostdev",
        "firmware",
        "external_memory",
        "removable",
    ],
)
def test_refuses_source_targets_missing_mappings_and_unprotected_state(tmp_path, fault):
    request = fixture(tmp_path)
    if fault == "same_uuid":
        request["target"]["vm_uuid"] = request["manifest"]["domain_uuid"]
    elif fault == "same_name":
        request["target"]["vm_name"] = "source"
    elif fault == "network":
        request["target"]["networks"] = []
    elif fault == "disk":
        request["disks"][0]["path"] = "/live/a"
    elif fault == "excluded":
        request["manifest"]["exclusions"] = ["vdb"]
    elif fault == "hostdev":
        request["domain_xml"] = request["domain_xml"].replace(
            "</devices>", "<hostdev mode='subsystem'/></devices>"
        )
    elif fault == "firmware":
        request["domain_xml"] = request["domain_xml"].replace(
            "</os>", "<nvram>/source/vars.fd</nvram></os>"
        )
    elif fault == "external_memory":
        request["domain_xml"] = request["domain_xml"].replace(
            "</domain>", "<memoryBacking><source type='file'/></memoryBacking></domain>"
        )
    else:
        request["domain_xml"] = request["domain_xml"].replace(
            'device="disk"', 'device="cdrom"', 1
        )
    with pytest.raises(ValueError):
        module.render(request)


def test_excluded_disks_only_removed_when_explicitly_acknowledged(tmp_path):
    request = fixture(tmp_path)
    request["manifest"]["exclusions"] = ["vdb"]
    request["manifest"]["disks"] = request["manifest"]["disks"][:1]
    request["target"]["drop_excluded_disks"] = ["vdb"]
    request["target"]["disks"] = ["vda"]
    request["disks"] = request["disks"][:1]
    assert len(ET.fromstring(module.render(request)).findall("./devices/disk")) == 1


@pytest.mark.parametrize("default", ["resource", "audio", "watchdog"])
def test_standard_libvirt_defaults_do_not_bind_fresh_vm_to_source_host(
    tmp_path, default
):
    request = fixture(tmp_path)
    root = ET.fromstring(request["domain_xml"])
    if default == "resource":
        node = ET.SubElement(root, "resource")
        ET.SubElement(node, "partition").text = "/machine"
    elif default == "audio":
        ET.SubElement(root.find("devices"), "audio", id="1", type="none")
    else:
        node = ET.SubElement(
            root.find("devices"), "watchdog", model="itco", action="reset"
        )
        ET.SubElement(node, "alias", name="watchdog0")
    request["domain_xml"] = ET.tostring(root, encoding="unicode")
    before = deepcopy(request)
    rendered = ET.fromstring(module.render(request))
    assert request == before
    assert rendered.find("resource") is None
    if default == "audio":
        assert rendered.find("./devices/audio").attrib == {"id": "1", "type": "none"}
    if default == "watchdog":
        node = rendered.find("./devices/watchdog")
        assert node.attrib == {"model": "itco", "action": "reset"} and not list(node)


@pytest.mark.parametrize(
    "fragment,at_root",
    [
        ("<resource><partition>/customer.slice</partition></resource>", True),
        ("<resource><partition>/machine</partition><extra/></resource>", True),
        ("<resource><partition host='source'>/machine</partition></resource>", True),
        ("<audio id='1' type='alsa'/>", False),
        ("<audio id='1' type='none'><output file='/host/audio'/></audio>", False),
        ("<audio id='1' type='none' source='/host/audio'/>", False),
        ("<watchdog model='itco' action='dump'/>", False),
        (
            "<watchdog model='itco' action='reset'><source file='/host/state'/></watchdog>",
            False,
        ),
        (
            "<watchdog model='itco' action='reset'><alias name='w'><extra/></alias></watchdog>",
            False,
        ),
    ],
)
def test_default_handling_does_not_allow_custom_host_bindings(
    tmp_path, fragment, at_root
):
    request = fixture(tmp_path)
    root = ET.fromstring(request["domain_xml"])
    (root if at_root else root.find("devices")).append(ET.fromstring(fragment))
    request["domain_xml"] = ET.tostring(root, encoding="unicode")
    with pytest.raises(ValueError):
        module.render(request)


class Missing(Exception):
    def get_error_code(self):
        return 42


class FakeDomain:
    def __init__(self, xml):
        self.xml = xml

    def UUIDString(self):
        return ET.fromstring(self.xml).findtext("uuid")

    def name(self):
        return ET.fromstring(self.xml).findtext("name")

    def isActive(self):
        return 0

    def isPersistent(self):
        return 1

    def autostart(self):
        return 0

    def XMLDesc(self, flags):
        return self.xml


class FakeConnection:
    def __init__(self):
        self.domain = None
        self.writes = 0

    def getLibVersion(self):
        return 12007000

    def lookupByUUIDString(self, value):
        if self.domain is None:
            raise Missing()
        return self.domain

    lookupByName = lookupByUUIDString

    def networkLookupByName(self, name):
        return types.SimpleNamespace(isActive=lambda: 1)

    def defineXMLFlags(self, xml, flags):
        self.writes += 1
        self.domain = FakeDomain(xml)
        return self.domain


LIBRARY = types.SimpleNamespace(
    libvirtError=Missing, VIR_ERR_NO_DOMAIN=42, VIR_DOMAIN_DEFINE_VALIDATE=1
)


@pytest.mark.parametrize("version", [11010000, 11010999, 12007000, 12007999])
def test_define_once_and_read_only_exact_restart_recovery(tmp_path, version):
    request = fixture(tmp_path)
    conn = FakeConnection()
    conn.getLibVersion = lambda: version
    result = module.define(request, conn, LIBRARY)
    assert result["state"] == "shutoff" and conn.writes == 1
    with pytest.raises(ValueError):
        module.define(request, conn, LIBRARY)
    request["allow_create"] = False
    assert module.define(request, conn, LIBRARY) == result and conn.writes == 1
    conn.domain.xml = conn.domain.xml.replace(
        'token="' + request["token"] + '"', 'token="foreign"'
    )
    with pytest.raises(ValueError):
        module.define(request, conn, LIBRARY)
    assert conn.writes == 1


@pytest.mark.parametrize("version", [11009000, 11011000, 12000000, 12006000, 12008000])
def test_no_definition_for_unqualified_runtime(tmp_path, version):
    request = fixture(tmp_path)
    conn = FakeConnection()
    conn.getLibVersion = lambda: version
    with pytest.raises(ValueError, match="libvirt"):
        module.define(request, conn, LIBRARY)
    assert conn.writes == 0


def test_no_definition_for_corrupt_disk_or_missing_uncertain_domain(tmp_path):
    request = fixture(tmp_path)
    conn = FakeConnection()
    request["allow_create"] = False
    with pytest.raises(ValueError):
        module.define(request, conn, LIBRARY)
    request["allow_create"] = True
    Path(request["disks"][0]["path"]).write_bytes(b"bad")
    with pytest.raises(ValueError):
        module.define(request, conn, LIBRARY)
    assert conn.writes == 0
