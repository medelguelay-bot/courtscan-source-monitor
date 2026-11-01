"""Optional bounded OCR for scanned pages in public PDFs. Never a legal verification."""
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

def extract_pdf(body,pages,deadline,text_limit,blank_pages=(),native_texts=None):
    if not isinstance(pages,int) or not 1<=pages<=500:
        raise OCRFailure('PDF_PAGE_LIMIT','PDF exceeds the bounded 500-page processing scope.','LIMIT')
    if native_texts is None:native_texts=['']*pages
    if len(native_texts)!=pages or any(not isinstance(part,str) for part in native_texts):
        raise OCRFailure('OCR_PAGE_ACCOUNTING','Native text must account for every PDF page.')
    blanks=set(blank_pages)
    if any(not isinstance(page,int) or page<1 or page>pages for page in blanks):
        raise OCRFailure('OCR_PAGE_ACCOUNTING','Blank-page metadata is outside the PDF page scope.')
    if any(native_texts[page-1].strip() for page in blanks):
        raise OCRFailure('OCR_PAGE_ACCOUNTING','A page cannot be both verified blank and native text.')
    native_pages=[index for index,part in enumerate(native_texts,1) if part.strip()]
    selected=[page for page in range(1,pages+1) if page not in blanks and page not in native_pages]
    if len(selected)>MAX_PAGES:
        raise OCRFailure('OCR_PAGE_LIMIT','PDF exceeds the 20-page limit for pages requiring OCR.','LIMIT')
    if not selected:raise OCRFailure('OCR_PAGE_ACCOUNTING','No page requires OCR; retain native text directly.')
    if len(native_pages)+len(blanks)+len(selected)!=pages:
        raise OCRFailure('OCR_PAGE_ACCOUNTING','Not every document page has an extraction method.')
    size=sum(len(part.encode('utf-8')) for part in native_texts)+max(0,pages-1)
    if size>text_limit:raise OCRFailure('TEXT_LIMIT','Combined PDF text exceeds the text size limit.','LIMIT')
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
    texts=list(native_texts);confidences=[]
    # Files are transient, including uncleared third-party content; only final policy permits persistence.
    with tempfile.TemporaryDirectory(prefix='courtscan-ocr-') as folder:
        root=Path(folder);pdf=root/'source.pdf';pdf.write_bytes(body)
        for page in selected:
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
                raise OCRFailure('OCR_INCOMPLETE','A nonblank PDF page yielded no OCR text; partial text was discarded.')
            elif sum(page_conf)/len(page_conf)<55:raise OCRFailure('OCR_LOW_CONFIDENCE','OCR confidence is insufficient; partial text was discarded.')
            confidences.extend(page_conf);size+=len(page_text.encode('utf-8'))
            if size>text_limit:raise OCRFailure('TEXT_LIMIT','OCR text exceeds the text size limit.','LIMIT')
            texts[page-1]=page_text;image.unlink()
    if len(confidences)<10:raise OCRFailure('OCR_EMPTY_TEXT','OCR did not yield sufficient readable text for monitoring.')
    return '\n'.join(texts),{'extractionMethod':'OCR','reviewRequired':True,'ocrPages':len(selected),'ocrMeanConfidence':round(sum(confidences)/len(confidences),2),'ocrEmptyPages':[],'pdfPages':pages,'ocrPageNumbers':selected,'nativeTextPageNumbers':native_pages,'blankPdfPageNumbers':sorted(blanks)}
