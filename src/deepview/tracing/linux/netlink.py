"""Optional ``pyroute2``-backed netlink enumerator.

Used by the inspector and monitor CLI to answer ad-hoc questions like
"what interfaces exist in this namespace" or "what's the default
route" without shelling out to ``ip``. Everything here is best-effort:
if ``pyroute2`` is not installed or netlink is unavailable, the
functions return empty lists instead of raising.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deepview.core.logging import get_logger

log = get_logger("tracing.linux.netlink")


@dataclass(slots=True)
class InterfaceRecord:
    ifindex: int
    name: str
    mac: str
    state: str
    mtu: int
    flags: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RouteRecord:
    family: str
    dst: str
    gateway: str
    oif: int
    proto: str
    metric: int


def _pyroute2() -> Any | None:
    try:
        import pyroute2  # noqa: F401
        return pyroute2
    except Exception:  # noqa: BLE001 - import may fail for many reasons
        return None


def available() -> bool:
    return _pyroute2() is not None


def list_interfaces() -> list[InterfaceRecord]:
    pr = _pyroute2()
    if pr is None:
        return []
    out: list[InterfaceRecord] = []
    try:
        with pr.IPRoute() as ipr:
            addr_by_index: dict[int, list[str]] = {}
            for addr in ipr.get_addr():
                idx = addr.get_attr("IFA_INDEX") or addr["index"]
                ip = addr.get_attr("IFA_ADDRESS") or ""
                if ip:
                    addr_by_index.setdefault(idx, []).append(f"{ip}/{addr['prefixlen']}")
            for link in ipr.get_links():
                idx = link["index"]
                name = link.get_attr("IFLA_IFNAME") or ""
                mac = link.get_attr("IFLA_ADDRESS") or ""
                mtu = link.get_attr("IFLA_MTU") or 0
                state = link.get_attr("IFLA_OPERSTATE") or ""
                flags_int = link.get("flags", 0)
                flags = _decode_iff_flags(flags_int)
                out.append(
                    InterfaceRecord(
                        ifindex=idx,
                        name=name,
                        mac=mac,
                        state=state,
                        mtu=int(mtu) if mtu else 0,
                        flags=flags,
                        addresses=addr_by_index.get(idx, []),
                    )
                )
    except Exception as e:  # noqa: BLE001
        log.debug("netlink_list_interfaces_failed", error=str(e))
    return out


def list_routes() -> list[RouteRecord]:
    pr = _pyroute2()
    if pr is None:
        return []
    out: list[RouteRecord] = []
    try:
        with pr.IPRoute() as ipr:
            for rt in ipr.get_routes():
                family = "inet" if rt.get("family", 2) == 2 else "inet6"
                dst = rt.get_attr("RTA_DST") or "default"
                prefix = rt.get("dst_len", 0)
                if dst != "default":
                    dst = f"{dst}/{prefix}"
                gateway = rt.get_attr("RTA_GATEWAY") or ""
                oif = rt.get_attr("RTA_OIF") or 0
                proto = str(rt.get("proto", 0))
                metric = rt.get_attr("RTA_PRIORITY") or 0
                out.append(
                    RouteRecord(
                        family=family,
                        dst=str(dst),
                        gateway=str(gateway),
                        oif=int(oif),
                        proto=proto,
                        metric=int(metric),
                    )
                )
    except Exception as e:  # noqa: BLE001
        log.debug("netlink_list_routes_failed", error=str(e))
    return out


_IFF_FLAGS = [
    (0x1, "UP"),
    (0x2, "BROADCAST"),
    (0x4, "DEBUG"),
    (0x8, "LOOPBACK"),
    (0x10, "POINTOPOINT"),
    (0x40, "RUNNING"),
    (0x100, "PROMISC"),
    (0x1000, "MULTICAST"),
]


def _decode_iff_flags(value: int) -> list[str]:
    return [name for bit, name in _IFF_FLAGS if value & bit]
