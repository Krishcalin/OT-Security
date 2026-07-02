"""
Niagara Fox Protocol Analyzer  (Tridium Niagara Framework)
Ports: TCP 1911 (fox), 4911 (foxs / TLS), 3011, 5011

Fox is the native protocol between Tridium Niagara stations, JACE controllers,
Workbench, and Supervisors — pervasive in building automation (BAS/BMS) and often
internet-exposed. The plaintext "fox hello" frame is a rich passive banner:

    fox a 0 -1 fox hello
    {
      fox.version=s:1.0.1
      hostName=s:jace-01
      station.name=s:MainStation
      ...
    }

We parse those key=value fields (values carry a ``s:`` / ``i:`` type prefix) to
enrich the device with Tridium station/host/version details. The secure variant
(foxs, 4911) is TLS-wrapped, so it is detected by port only.
"""
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult

FOX_PORTS = (1911, 4911, 3011, 5011)
_FOXS_PORTS = (4911, 5011)

# Fox hello field -> normalized detail key.
_FOX_KEYS = {
    "fox.version": "fox_version", "hostName": "host_name",
    "hostAddress": "host_address", "app.name": "app_name",
    "app.version": "app_version", "vm.name": "vm_name",
    "vm.version": "vm_version", "os.name": "os_name",
    "station.name": "station_name", "hostId": "host_id",
    "vmUuid": "vm_uuid", "brandId": "brand_id", "lang": "lang",
    "timeZone": "time_zone",
}


class NiagaraFoxAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP" or len(payload) < 5:
            return False
        if sport in FOX_PORTS or dport in FOX_PORTS:
            return True
        return payload[:6] in (b"fox a ", b"fox s ")

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        # The Niagara station sits on the Fox port.
        if dport in FOX_PORTS:
            device_ip, port = dst_ip, dport
        elif sport in FOX_PORTS:
            device_ip, port = src_ip, sport
        else:
            device_ip, port = dst_ip, 1911

        is_banner = payload[:6] in (b"fox a ", b"fox s ")
        secure = sport in _FOXS_PORTS or dport in _FOXS_PORTS
        proto_name = "Niagara Foxs" if secure else "Niagara Fox"

        details = {"vendor": "Tridium", "device_class": "Niagara station / JACE controller"}
        confidence = "medium"
        if is_banner:
            confidence = "high"
            details.update(self._parse_hello(payload.decode("latin-1", "replace")))
        elif secure:
            details["note"] = "TLS-encrypted (foxs); detected by port"

        detection = self._make_detection(
            protocol=proto_name, port=port, confidence=confidence,
            timestamp=timestamp, transport="TCP", **details,
        )
        return [(device_ip, detection)]

    @staticmethod
    def _parse_hello(text: str) -> dict:
        """Extract the key=value fields from the Fox hello ``{ ... }`` block."""
        start = text.find("{")
        end = text.find("}", start + 1) if start != -1 else -1
        block = text[start + 1:end] if (start != -1 and end != -1) else text
        out: dict = {}
        for line in block.splitlines():
            line = line.strip()
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if len(val) >= 2 and val[1] == ":":     # strip the s:/i:/b: type prefix
                val = val[2:]
            norm = _FOX_KEYS.get(key)
            if norm and val:
                out[norm] = val[:128]
        return out
