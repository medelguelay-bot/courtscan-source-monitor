"""Optional bounded OCR for public image-only PDFs. Never a legal verification."""
import csv
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

MAX_PAGES=20
class OCRFailure(ValueError):
    def __init__(self,code,detail,category='PARSER_ERROR'):
        super().__init__(code);self.code=code;self.detail=detail;self.category=category

def extract_pdf(body,pages,deadline,text_limit,blank_pages=()):
    if pages>MAX_PAGES:raise OCRFailure('OCR_PAGE_LIMIT','Image-only PDF exceeds the 20-page OCR limit.','LIMIT')
    renderer=shutil.which('pdftoppm');engine=shutil.which('tesseract')
    if not renderer or not engine:raise OCRFailure('OCR_UNAVAILABLE','Image-only PDF requires optional Poppler and Tesseract; manual review is required.')
    env=os.environ.copy();env['OMP_THREAD_LIMIT']='1'
    def run(args):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise OCRFailure('OCR_TIMEOUT','OCR exhausted the source time budget.','TIMEOUT')
        try:
            result=subprocess.run(args,capture_output=True,timeout=remaining,env=env)
        except subprocess.TimeoutExpired:raise OCRFailure('OCR_TIMEOUT','OCR exhausted the source time budget.','TIMEOUT')
        except OSError:raise OCRFailure('OCR_PROCESS_ERROR','An installed OCR tool could not be started.')
        if result.returncode:raise OCRFailure('OCR_PROCESS_ERROR','An OCR subprocess rejected the document; partial text was discarded.')
        if len(result.stdout)>8*1024*1024:raise OCRFailure('OCR_OUTPUT_LIMIT','OCR subprocess output exceeds its size limit.','LIMIT')
        return result.stdout
    texts=[];confidences=[];empty=[];size=0
    # Files are transient, including uncleared third-party content; only final policy permits persistence.
    with tempfile.TemporaryDirectory(prefix='courtscan-ocr-') as folder:
        root=Path(folder);pdf=root/'source.pdf';pdf.write_bytes(body)
        for page in range(1,pages+1):
            base=root/'page'
            run([renderer,'-f',str(page),'-l',str(page),'-singlefile','-scale-to','2200','-gray','-png',str(pdf),str(base)])
            image=base.with_suffix('.png')
            if not image.exists():raise OCRFailure('OCR_RENDER_ERROR','PDF renderer did not produce a page image.')
            if image.stat().st_size>8*1024*1024:raise OCRFailure('OCR_IMAGE_LIMIT','Rendered page exceeds the OCR image size limit.','LIMIT')
            raw=run([engine,str(image),'stdout','-l','eng','--psm','3','tsv'])
            try:
                rows=list(csv.DictReader(io.StringIO(raw.decode('utf-8',errors='strict')),delimiter='\t'))
                lines={};page_conf=[]
                for row in rows:
                    word=(row.get('text') or '').strip()
                    if row.get('level')!='5' or not word:continue
                    confidence=float(row['conf'])
                    if confidence<0:continue
                    key=(row['block_num'],row['par_num'],row['line_num'])
                    lines.setdefault(key,[]).append(word);page_conf.append(confidence)
            except (ValueError,KeyError,UnicodeError,csv.Error):raise OCRFailure('OCR_OUTPUT_INVALID','OCR returned invalid structured output.')
            page_text='\n'.join(' '.join(words) for words in lines.values())
            if not page_text:
                if page not in blank_pages:raise OCRFailure('OCR_INCOMPLETE','A nonblank PDF page yielded no OCR text; partial text was discarded.')
                empty.append(page)
            elif sum(page_conf)/len(page_conf)<55:raise OCRFailure('OCR_LOW_CONFIDENCE','OCR confidence is insufficient; partial text was discarded.')
            confidences.extend(page_conf);size+=len(page_text.encode('utf-8'))
            if size>text_limit:raise OCRFailure('TEXT_LIMIT','OCR text exceeds the text size limit.','LIMIT')
            texts.append(page_text);image.unlink()
    if len(confidences)<10:raise OCRFailure('OCR_EMPTY_TEXT','OCR did not yield sufficient readable text for monitoring.')
    return '\n'.join(texts),{'extractionMethod':'OCR','reviewRequired':True,'ocrPages':pages,'ocrMeanConfidence':round(sum(confidences)/len(confidences),2),'ocrEmptyPages':empty}
