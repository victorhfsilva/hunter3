"""Nmap XML parser."""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET

from .base import ParseLimits, ParseResult, candidate, type_from_text

NAME = "Nmap"
PRIORITY = 90


def sniff(path: str, head: str) -> bool:
    return "<nmaprun" in head[:6000] or "<hosthint>" in head[:6000]


def parse(path: str, limits: ParseLimits) -> ParseResult:
    out = []
    started = time.monotonic()
    timed_out = False
    try:
        # limite: iterparse incremental; para ao atingir limite.max_candidates.
        for _event, element in ET.iterparse(path, events=("end",)):
            # limite: tempo por arquivo e limite.max_candidates.
            if time.monotonic() - started > limits.max_seconds:
                timed_out = True
                break
            if element.tag.split("}")[-1] != "host":
                continue
            address = ""
            for child in list(element):
                if child.tag.split("}")[-1] == "address":
                    address = child.attrib.get("addr", "")
            for port in element.iter():
                if port.tag.split("}")[-1] != "port":
                    continue
                port_id = port.attrib.get("portid", "")
                protocol = port.attrib.get("protocol", "tcp")
                service = ""
                scripts = []
                for child in list(port):
                    tag = child.tag.split("}")[-1]
                    if tag == "service":
                        service = child.attrib.get("name", "")
                    if tag == "script":
                        scripts.append(f"{child.attrib.get('id', '')}: {child.attrib.get('output', '')}")
                for script in scripts or [""]:
                    endpoint = f"{protocol}://{address}:{port_id}" if address else f"{protocol}://:{port_id}"
                    out.append(
                        candidate(
                            raw_type=type_from_text(script) if script else "endpoint_internal",
                            endpoint=endpoint,
                            evidence=f"Nmap {address}:{port_id}/{protocol} {service} {script}"[:300],
                            tool=NAME,
                            severity="info",
                            confidence="medium",
                            title=(script[:160] or f"open port {port_id}/{protocol}"),
                        )
                    )
                    if len(out) >= limits.max_candidates:
                        return ParseResult(out, limits.start_offset, 0, True, "limite de candidatas")
            element.clear()
    except (OSError, ET.ParseError):
        return ParseResult(out, limits.start_offset, 0, True, "formato: XML inválido/parcial")
    return ParseResult(out, limits.start_offset, 0, timed_out, "timeout de arquivo" if timed_out else "")
