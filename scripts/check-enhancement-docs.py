from pathlib import Path
import re
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


root = Path(__file__).resolve().parents[1]
enhancement = root / "docs/enhancements/managed-gateway-endpoints"
required = [enhancement / name for name in ("README.md", "acceptance-tests.md", "source-review.md")]
for document in required:
    if not document.is_file() or not document.read_text().strip():
        raise ValueError(f"Missing design document: {document}")

documents = [root / "README.md", *sorted((root / "docs").rglob("*.md"))]
for document in documents:
    text = document.read_text()
    for target in re.findall(r"\]\(([^\s)]+)\)", text):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        resolved = (document.parent / unquote(parsed.path)).resolve()
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError(f"Broken or out-of-repository link in {document}: {target}")

diagrams = sorted((enhancement / "diagrams").glob("*.svg"))
if len(diagrams) < 2:
    raise ValueError("Expected ownership and provisioning diagrams")
for diagram in diagrams:
    element = ET.parse(diagram).getroot()
    if element.tag != "{http://www.w3.org/2000/svg}svg":
        raise ValueError(f"Not an SVG: {diagram}")
    identifiers = [node.attrib["id"] for node in element.iter() if "id" in node.attrib]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"Duplicate SVG identifiers: {diagram}")
    for reference in re.findall(r"url\(#([^\)]+)\)", diagram.read_text()):
        if reference not in identifiers:
            raise ValueError(f"Missing SVG reference in {diagram}: {reference}")

print(f"Validated {len(documents)} Markdown documents and {len(diagrams)} SVG diagrams")
