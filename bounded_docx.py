"""Bounded DOCX extraction; no archive extraction, entity expansion or external fetch."""
import io
import re
import zipfile
from xml.etree import ElementTree as ET

NS='{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
class DOCXFailure(ValueError):
    def __init__(self,code,detail,category='PARSER_ERROR'):
        super().__init__(code);self.code=code;self.detail=detail;self.category=category

def extract_docx(body,text_limit):
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            entries=archive.infolist()
            if len(entries)>512 or sum(x.file_size for x in entries)>16*1024*1024:
                raise DOCXFailure('DOCX_EXPANSION_LIMIT','DOCX archive exceeds its entry or expanded-size limit.','LIMIT')
            names=[x.filename for x in entries]
            if len(set(names))!=len(names):raise DOCXFailure('DOCX_DUPLICATE_PART','DOCX contains duplicate package parts.')
            for entry in entries:
                if entry.flag_bits&1:raise DOCXFailure('DOCX_ENCRYPTED','Encrypted DOCX requires manual review.')
                if entry.filename.startswith(('/','\\')) or '..' in entry.filename.replace('\\','/').split('/'):
                    raise DOCXFailure('DOCX_UNSAFE_PART','DOCX contains an unsafe package path.','SECURITY')
            if '[Content_Types].xml' not in names or 'word/document.xml' not in names:
                raise DOCXFailure('DOCX_INVALID_PACKAGE','Response is not a supported DOCX package.')
            def xml(name):
                entry=archive.getinfo(name)
                if entry.file_size>4*1024*1024:raise DOCXFailure('DOCX_XML_LIMIT','DOCX XML part exceeds its size limit.','LIMIT')
                data=archive.read(name)
                if b'\x00' in data or re.search(br'<!\s*(?:DOCTYPE|ENTITY)',data,re.I):raise DOCXFailure('DOCX_XML_ENTITIES','DOCX XML entity declarations are prohibited.','SECURITY')
                return ET.fromstring(data)
            types=xml('[Content_Types].xml')
            if any('macroenabled' in str(x.attrib.get('ContentType','')).lower() or 'vbaproject' in str(x.attrib.get('ContentType','')).lower() for x in types) or any('vbaproject' in n.lower() for n in names):
                raise DOCXFailure('DOCX_MACROS','Macro-enabled documents require manual review.','SECURITY')
            parts=['word/document.xml']+sorted(n for n in names if re.fullmatch(r'word/(?:footnotes|endnotes|header\d*|footer\d*)\.xml',n))
            texts=[];size=0
            for name in parts:
                tree=xml(name)
                if any(x.tag in (NS+'altChunk',NS+'del',NS+'ins') for x in tree.iter()):
                    raise DOCXFailure('DOCX_UNSUPPORTED_REVISION','Embedded text chunks or tracked revisions require manual review.')
                for paragraph in tree.iter(NS+'p'):
                    fragments=[]
                    for node in paragraph.iter():
                        if node.tag==NS+'t':fragments.append(node.text or '')
                        elif node.tag in (NS+'tab',NS+'br',NS+'cr'):fragments.append(' ')
                    line=''.join(fragments)
                    size+=len(line.encode('utf-8'))
                    if size>text_limit:raise DOCXFailure('TEXT_LIMIT','DOCX text exceeds the text size limit.','LIMIT')
                    if line.strip():texts.append(line)
            if not texts:raise DOCXFailure('DOCX_EMPTY_TEXT','DOCX contains no supported text; embedded images require manual review.')
            return '\n'.join(texts)
    except (zipfile.BadZipFile,ET.ParseError,RuntimeError,NotImplementedError) as exc:
        raise DOCXFailure('DOCX_PARSE_ERROR','DOCX package parsing failed ('+type(exc).__name__+').') from exc
