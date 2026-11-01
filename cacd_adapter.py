"""Exact reviewed CACD judge-procedure JSON adapter; no generic JSON flattening."""
import json
import re

ORIGIN='https://apps.cacd.uscourts.gov'
REVIEWED={
    '33cb8842-9482-45f4-3518-08de636ff965':('AYP','Anna Y. Park',"Judge's Procedures"),
    '1d7ad7ef-589f-4c4a-3eda-08ddece20de6':('ADS','Autumn D. Spaeth','Important Notice'),
    '33e68914-24b3-40a5-3ed9-08ddece20de6':('KES','Karen E. Scott',"Judge's Procedures"),
    '3e4e42a0-7045-4e32-432f-08de214ff94e':('DSR','Daniel S. Roberts','Important Notice'),
    'a9e85fb5-8f88-408d-3ec1-08ddece20de6':('JFW','John F. Walter','Important Notice'),
    '99da3dfe-00c8-4e85-3ec3-08ddece20de6':('ODW','Otis D. Wright II',"Judge's Procedures"),
    'ad05fcf4-7d99-4dad-3739-08de58702db8':('ACCV','Angela C. C. Viramontes','Important Notice'),
    'e048d7c4-f266-4bec-3ed2-08ddece20de6':('RAO','Rozella A. Oliver',"Judge's Procedures"),
    'c2f8424c-aa26-4c30-3ed8-08ddece20de6':('AS','Alka Sagar','Important Notice'),
}
class AdapterError(ValueError):
    def __init__(self,code,detail,category='PARSER_ERROR'):
        super().__init__(code);self.code=code;self.detail=detail;self.category=category

def validate(adapter,url,source_url=None):
    if not isinstance(adapter,dict) or adapter.get('type')!='CACD_JUDGE_PROCEDURES':
        raise AdapterError('ADAPTER_CONFIG','Unrecognized source adapter.','SECURITY')
    identity=adapter.get('judgeId')
    if not isinstance(identity,str) or identity not in REVIEWED:
        raise AdapterError('ADAPTER_SCOPE','Judge identity is outside the reviewed adapter scope.','SECURITY')
    initials,name,title=REVIEWED[identity]
    if adapter.get('initials')!=initials or adapter.get('blockTitle')!=title:
        raise AdapterError('ADAPTER_CONFIG','Adapter identity or selected title differs from its reviewed contract.','SECURITY')
    if url!=ORIGIN+'/JpsApi/judge/'+identity:
        raise AdapterError('ADAPTER_SCOPE','Adapter request is not its exact reviewed HTTPS endpoint.','SECURITY')
    if source_url is not None and source_url!=ORIGIN+'/Jps/#/judge/'+identity+'/'+initials.lower():
        raise AdapterError('ADAPTER_SOURCE_IDENTITY','Original profile identity differs from its reviewed adapter.','SECURITY')
    return identity,initials,name,title

def read_html(body,content_type,adapter,url):
    identity,initials,name,title=validate(adapter,url)
    if len(body)>1024*1024:raise AdapterError('ADAPTER_BODY_LIMIT','Judge-procedure JSON exceeds the 1 MiB adapter bound.','LIMIT')
    if content_type.split(';',1)[0].strip().lower()!='application/json':
        raise AdapterError('ADAPTER_CONTENT_TYPE','Judge-procedure endpoint did not return JSON.')
    def unique_pairs(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise AdapterError('ADAPTER_DUPLICATE_KEY','Judge-procedure JSON contains duplicate object keys.')
            value[key]=item
        return value
    try:data=json.loads(body.decode('utf-8',errors='strict'),object_pairs_hook=unique_pairs)
    except (ValueError,UnicodeError,RecursionError) as exc:
        if isinstance(exc,AdapterError):raise
        raise AdapterError('ADAPTER_JSON','Judge-procedure JSON is invalid.') from exc
    if not isinstance(data,dict) or (data.get('id'),data.get('initials'),data.get('name'))!=(identity,initials,name):
        raise AdapterError('ADAPTER_IDENTITY','JSON identity does not match the reviewed judge.')
    page=data.get('webPage')
    blocks=page.get('webBlocks') if isinstance(page,dict) else None
    if not isinstance(blocks,list) or len(blocks)>64 or any(not isinstance(block,dict) for block in blocks):
        raise AdapterError('ADAPTER_SCHEMA','Judge-procedure block schema is missing or unsupported.')
    selected=[block for block in blocks if block.get('title')==title]
    if len(selected)!=1:raise AdapterError('ADAPTER_BLOCK','Exactly one reviewed procedure block is required.')
    content=selected[0].get('content')
    if not isinstance(content,str) or not content.strip():
        raise AdapterError('ADAPTER_EMPTY_BLOCK','Reviewed procedure block has no HTML text.')
    return content,'Judge: '+name+' ('+initials+')\n'+title

def verify_text(text):
    # A TOC/heading alone is insufficient; require a substantive nearby observed duty/reminder.
    clauses=re.finditer(r'artificial\s+intelligence.{0,1200}?(?:(?:rule|procedure)\s+11\b|certif\w*)',text,re.I|re.S)
    if len(text)<150 or len(text.split())<20 or not any(len(match.group())>=80 for match in clauses):
        raise AdapterError('ADAPTER_AI_BODY_MISSING','The reviewed AI paragraph/body is missing or no longer matches the bounded extraction contract.')
