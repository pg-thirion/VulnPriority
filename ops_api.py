"""Local operations API, with explicit request bounds and same-origin checks."""
import json
import sqlite3
from pathlib import Path
from operations import Store
from scoring import parse_csv

PAGE = Path(__file__).with_name('operations.html')


def handle(handler, store, method):
    path = handler.path
    if path not in ('/operations','/api/ops/inventory','/api/ops/report','/api/ops/audit','/api/ops/import','/api/ops/change','/api/ops/intelligence'):
        return False
    host = handler.headers.get('Host')
    if host not in ('localhost:8000','127.0.0.1:8000') or handler.headers.get('Origin') not in (None,'http://localhost:8000','http://127.0.0.1:8000'):
        handler.json_reply(403, {'error':'Local origin only'})
        return True
    try:
        if method == 'GET':
            if path == '/operations':
                handler.reply(200,PAGE.read_bytes(),'text/html; charset=utf-8')
            elif path in ('/api/ops/inventory','/api/ops/report','/api/ops/audit'):
                data = {'/api/ops/inventory':store.inventory,'/api/ops/report':store.report,'/api/ops/audit':store.audit}[path]()
                handler.json_reply(200,data)
            else:
                handler.json_reply(405,{'error':'Method not allowed'})
        elif method == 'POST':
            if path not in ('/api/ops/import','/api/ops/change','/api/ops/intelligence'):
                handler.json_reply(405,{'error':'Method not allowed'})
            elif handler.headers.get_content_type() != 'application/json':
                handler.json_reply(415,{'error':'Expected JSON'})
            else:
                size = int(handler.headers.get('Content-Length','0'))
                if not 0 < size <= 16_000_000:
                    handler.json_reply(413,{'error':'Request too large or empty'})
                    return True
                data = json.loads(handler.rfile.read(size))
                if not isinstance(data,dict):
                    raise ValueError('Expected JSON object')
                if path == '/api/ops/import' and set(data) in ({'csv'},{'findings'}):
                    result = store.ingest(parse_csv(data['csv']) if 'csv' in data else data['findings'])
                elif path == '/api/ops/change' and set(data) == {'id','revision','patch'} and isinstance(data['id'],str):
                    result = store.change(data['id'],data['revision'],data['patch'])
                elif path == '/api/ops/intelligence' and set(data) == {'kind','payload','as_of'} and isinstance(data['kind'],str):
                    result = store.enrich(**data)
                else:
                    raise ValueError('Invalid request fields')
                handler.json_reply(200,result)
        else:
            handler.json_reply(405,{'error':'Method not allowed'})
    except LookupError:
        handler.json_reply(404,{'error':'Finding not found'})
    except RuntimeError as exc:
        handler.json_reply(409,{'error':str(exc)})
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        handler.json_reply(400,{'error':str(exc)})
    except sqlite3.Error:
        handler.json_reply(503,{'error':'Database unavailable'})
    return True
