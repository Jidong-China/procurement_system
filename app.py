import os, smtplib, secrets, atexit
from datetime import datetime, timedelta
from functools import wraps
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sqlite3

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DATABASE = os.environ.get('DATABASE_PATH', 'data/procurement.db')

def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
        db = g._db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
    return db

@app.teardown_appcontext
def close_db(e): 
    db = getattr(g, '_db', None)
    if db: db.close()

def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS payables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sheet TEXT NOT NULL DEFAULT '',
            sign_date TEXT,
            contract_no TEXT DEFAULT '',
            our_company TEXT DEFAULT '',
            supplier TEXT NOT NULL,
            total_amount REAL,
            payment_terms TEXT DEFAULT '',
            prepayment REAL,
            tail_payment REAL,
            due_date TEXT,
            due_date_raw TEXT DEFAULT '',
            payment_days INTEGER DEFAULT NULL,
            prepayment_paid INTEGER DEFAULT 0,
            tail_paid INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            is_paid INTEGER DEFAULT 0,
            paid_at TEXT,
            updated_at TEXT DEFAULT (datetime('now')),
            upload_batch TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS project_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_no TEXT NOT NULL,
            contract_name TEXT DEFAULT '',
            responsible TEXT DEFAULT '',
            supplier TEXT NOT NULL DEFAULT '',
            goods_ready TEXT DEFAULT '',
            inspection_photo TEXT DEFAULT '',
            ship_date TEXT DEFAULT '',
            location TEXT DEFAULT '',
            packing_list TEXT DEFAULT '',
            label_ok TEXT DEFAULT '',
            invoice_ok TEXT DEFAULT '',
            qty REAL,
            net_weight REAL,
            gross_weight REAL,
            volume REAL,
            remark TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS report_schedule (
            id INTEGER PRIMARY KEY,
            emails TEXT DEFAULT 'jidong@seatrustpower.com',
            send_time TEXT DEFAULT '08:00',
            send_time2 TEXT DEFAULT '16:30',
            report_title TEXT DEFAULT '采购应付款每日预警日报',
            enabled INTEGER DEFAULT 1,
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS report_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sent_at TEXT,
            recipients TEXT,
            urgent_count INTEGER DEFAULT 0,
            warning_count INTEGER DEFAULT 0,
            status TEXT,
            error TEXT
        );
    """)
    db.commit()
    if not db.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        pw = os.environ.get('ADMIN_PASSWORD', 'admin123456')
        db.execute("INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,'admin')",
                   ('admin', generate_password_hash(pw), '管理员'))
        db.commit()
        print(f"[INIT] Admin created. Password: {pw}")
    if not db.execute("SELECT id FROM report_schedule WHERE id=1").fetchone():
        db.execute("INSERT INTO report_schedule(id) VALUES(1)")
        db.commit()
    # 兼容旧数据库：加新列
    for col, default in [
        ('payment_days', 'INTEGER DEFAULT NULL'),
        ('prepayment_paid', 'INTEGER DEFAULT 0'),
        ('tail_paid', 'INTEGER DEFAULT 0'),
    ]:
        try:
            db.execute(f"ALTER TABLE payables ADD COLUMN {col} {default}")
            db.commit()
        except: pass
    # 兼容旧数据库：加 send_time2 列
    try:
        db.execute("ALTER TABLE report_schedule ADD COLUMN send_time2 TEXT DEFAULT '16:30'")
        db.commit()
    except: pass
    # 设置默认邮箱（如果还未设置）
    try:
        row = db.execute("SELECT emails FROM report_schedule WHERE id=1").fetchone()
        if row and not row[0]:
            db.execute("UPDATE report_schedule SET emails='jidong@seatrustpower.com' WHERE id=1")
            db.commit()
    except: pass

def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if 'uid' not in session:
            return jsonify({'error':'未登录'}),401 if request.is_json else redirect(url_for('login_page'))
        return f(*a, **kw)
    return dec

def admin_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if 'uid' not in session: return jsonify({'error':'未登录'}),401
        u = query("SELECT role FROM users WHERE id=? AND active=1",(session['uid'],),one=True)
        if not u or u['role']!='admin': return jsonify({'error':'权限不足'}),403
        return f(*a, **kw)
    return dec

def me():
    if 'uid' not in session: return None
    return query("SELECT * FROM users WHERE id=? AND active=1",(session['uid'],),one=True)

# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'uid' in session else url_for('login_page'))

@app.route('/login')
def login_page():
    if 'uid' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=dict(me()))

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.json
    u = query("SELECT * FROM users WHERE username=? AND active=1",(d.get('username',''),),one=True)
    if not u or not check_password_hash(u['password_hash'], d.get('password','')):
        return jsonify({'error':'用户名或密码错误'}),401
    session['uid'] = u['id']
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=7)
    return jsonify({'ok':True,'user':{'id':u['id'],'username':u['username'],'display_name':u['display_name'],'role':u['role']}})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear(); return jsonify({'ok':True})

@app.route('/api/me')
@login_required
def api_me():
    u = me()
    return jsonify({'id':u['id'],'username':u['username'],'display_name':u['display_name'],'role':u['role']})

@app.route('/api/change_password', methods=['POST'])
@login_required
def api_change_pw():
    d = request.json; u = me()
    if not check_password_hash(u['password_hash'], d.get('old_password','')): return jsonify({'error':'原密码错误'}),400
    pw = d.get('new_password','')
    if len(pw)<6: return jsonify({'error':'新密码至少6位'}),400
    execute("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(pw),u['id']))
    return jsonify({'ok':True})

# ── Users ─────────────────────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
@admin_required
def api_users_get():
    return jsonify([dict(r) for r in query("SELECT id,username,display_name,role,active,created_at FROM users ORDER BY id")])

@app.route('/api/users', methods=['POST'])
@admin_required
def api_users_post():
    d = request.json
    un,pw,dn,role = d.get('username','').strip(),d.get('password','').strip(),d.get('display_name','').strip(),d.get('role','viewer')
    if not un or not pw or not dn: return jsonify({'error':'字段不能为空'}),400
    if len(pw)<6: return jsonify({'error':'密码至少6位'}),400
    if query("SELECT id FROM users WHERE username=?",(un,),one=True): return jsonify({'error':'用户名已存在'}),400
    execute("INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)",
            (un,generate_password_hash(pw),dn,role))
    return jsonify({'ok':True})

@app.route('/api/users/<int:uid>', methods=['PUT'])
@admin_required
def api_users_put(uid):
    d = request.json; fields,vals = [],[]
    for k in ['display_name','role','active']:
        if k in d: fields.append(f"{k}=?"); vals.append(d[k])
    if 'password' in d and d['password']:
        if len(d['password'])<6: return jsonify({'error':'密码至少6位'}),400
        fields.append("password_hash=?"); vals.append(generate_password_hash(d['password']))
    if not fields: return jsonify({'error':'无内容'}),400
    vals.append(uid)
    execute(f"UPDATE users SET {', '.join(fields)} WHERE id=?",vals)
    return jsonify({'ok':True})

@app.route('/api/users/<int:uid>', methods=['DELETE'])
@admin_required
def api_users_del(uid):
    if uid==me()['id']: return jsonify({'error':'不能删除自己'}),400
    execute("UPDATE users SET active=0 WHERE id=?",(uid,))
    return jsonify({'ok':True})

# ── Payables ──────────────────────────────────────────────────────────────────

@app.route('/api/payables')
@login_required
def api_payables():
    sql = "SELECT * FROM payables WHERE 1=1"; args=[]
    for k,col in [('sheet','sheet'),('supplier','supplier'),('contract_no','contract_no')]:
        v=request.args.get(k)
        if v: sql+=f" AND {col}=?"; args.append(v)
    s=request.args.get('status')
    if s=='paid': sql+=" AND is_paid=1"
    elif s=='unpaid': sql+=" AND is_paid=0"
    sql+=" ORDER BY due_date ASC, id ASC"
    return jsonify([dict(r) for r in query(sql,args)])

@app.route('/api/payables/meta')
@login_required
def api_payables_meta():
    db=get_db()
    suppliers=[r[0] for r in db.execute("SELECT DISTINCT supplier FROM payables WHERE supplier!='' ORDER BY supplier")]
    contracts=[r[0] for r in db.execute("SELECT DISTINCT contract_no FROM payables WHERE contract_no!='' ORDER BY contract_no")]
    return jsonify({'suppliers':suppliers,'contracts':contracts})

@app.route('/api/payables/upload', methods=['POST'])
@admin_required
def api_payables_upload():
    records=request.json.get('records',[])
    if not records: return jsonify({'error':'数据为空'}),400
    batch=datetime.now().strftime('%Y%m%d_%H%M%S')
    execute("DELETE FROM payables")
    for r in records:
        execute("""INSERT INTO payables(sheet,sign_date,contract_no,our_company,supplier,
                   total_amount,payment_terms,prepayment,tail_payment,due_date,due_date_raw,notes,upload_batch)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (r.get('sheet',''),r.get('sign_date') or None,r.get('contract_no',''),
                 r.get('our_company',''),r.get('supplier',''),r.get('total_amount'),
                 r.get('payment_terms',''),r.get('prepayment'),r.get('tail_payment'),
                 r.get('due_date') or None,r.get('due_date_raw',''),r.get('notes',''),batch))
    return jsonify({'ok':True,'count':len(records),'batch':batch})

@app.route('/api/payables/upload_excel', methods=['POST'])
@admin_required
def api_upload_excel():
    """服务端解析Excel — 用pandas，100%可靠，不依赖浏览器SheetJS"""
    try:
        import pandas as pd, re as _re
        from pandas import NaT
    except ImportError:
        return jsonify({'error':'服务端缺少pandas'}), 500
    if 'file' not in request.files:
        return jsonify({'error':'未收到文件'}), 400
    f = request.files['file']
    if not f.filename.endswith(('.xlsx','.xls')):
        return jsonify({'error':'请上传 .xlsx 或 .xls 文件'}), 400
    def _date(v):
        if v is None or v is NaT: return None
        try:
            if pd.isna(v): return None
        except: pass
        if hasattr(v,'strftime'): return v.strftime('%Y-%m-%d')
        s=str(v).strip()
        m=_re.match(r'^(\d{4})[-/](\d{1,2})[-/](\d{1,2})',s)
        return f"{m[1]}-{m[2].zfill(2)}-{m[3].zfill(2)}" if m else (s if s else None)
    def _float(v):
        if v is None or v is NaT: return None
        try:
            if pd.isna(v): return None
        except: pass
        try: return float(str(v).replace(',','').strip())
        except: return None
    def _str(v):
        if v is None or v is NaT: return ''
        try:
            if pd.isna(v): return ''
        except: pass
        return str(v).strip()
    # Sheet名映射：支持旧格式（人名）和新格式（合同号前缀）
    # 合法合同编号前缀：TSD→田少东, ZFC→张翡翠, ZHX/ME→赵虹，其他一律报错
    PREFIX_MAP = {
        'TSD': '田少东',
        'ZFC': '张翡翠',
        'ZHX': '赵虹',
        'ME':  '赵虹',
    }
    NAME_MAP = {'田少东':'田少东','张翡翠':'张翡翠','赵虹':'赵虹','胡激东':'胡激东','谭荣毅':'谭荣毅','田工':'田少东'}
    def guess_person(sheet_name, contract_no):
        cn = str(contract_no).strip().upper()
        if cn:
            for prefix, person in sorted(PREFIX_MAP.items(), key=lambda x:-len(x[0])):
                if cn.startswith(prefix): return person
            return '__INVALID__'  # 有合同号但前缀非法
        # 合同号为空：按sheet名判断
        return NAME_MAP.get(sheet_name, '__INVALID__')
    records = []
    invalid_rows = []
    try:
        xf = pd.ExcelFile(f)
        for sheet in xf.sheet_names:
            df = pd.read_excel(xf, sheet_name=sheet)
            cols = df.columns.tolist()
            due_col = '实际交货期' if '实际交货期' in cols else '交货期'
            notes_col = '中期跟进' if '中期跟进' in cols else ('临期跟进' if '临期跟进' in cols else None)
            for _, row in df.iterrows():
                supplier = _str(row.get('供应商',''))
                if not supplier or supplier=='nan' or supplier.startswith('总计') or supplier.startswith('合计'): continue
                contract_no = _str(row.get('合同编号',''))
                if not contract_no:
                    invalid_rows.append(f"(合同编号为空)·{supplier}")
                    continue
                person = guess_person(sheet, contract_no)
                if person == '__INVALID__':
                    invalid_rows.append(f"{contract_no}·{supplier}")
                    continue
                due_raw = _str(row.get(due_col,''))
                notes_val = _str(row.get(notes_col,''))[:200] if notes_col else ''
                records.append({
                    'sheet':person, 'sign_date':_date(row.get('签订日期')),
                    'contract_no':contract_no, 'our_company':_str(row.get('我方公司','')),
                    'supplier':supplier, 'total_amount':_float(row.get('合同总金额')),
                    'payment_terms':_str(row.get('付款方式','')), 'prepayment':_float(row.get('预付款')),
                    'tail_payment':_float(row.get('尾款')), 'due_date':_date(row.get(due_col)),
                    'due_date_raw':due_raw, 'notes':notes_val,
                })
    except Exception as e:
        return jsonify({'error':f'解析失败: {str(e)}'}), 400
    if invalid_rows:
        return jsonify({'error':f'上传失败，请检查以下记录（合同编号不能为空，且必须以 TSD/ZFC/ZHX/ME 开头）：' + '；'.join(invalid_rows[:10])}), 400
    if not records:
        return jsonify({'error':'未找到有效数据（供应商列为空）'}), 400
    batch = datetime.now().strftime('%Y%m%d_%H%M%S')
    # 去重：取出系统中已有的合同编号，以系统数据为准，跳过已存在的
    existing_contracts = set(
        row[0] for row in get_db().execute(
            "SELECT contract_no FROM payables WHERE contract_no != ''"
        ).fetchall()
    )
    inserted, skipped = 0, 0
    for r in records:
        cn = r['contract_no']
        if cn and cn in existing_contracts:
            skipped += 1
            continue
        execute("""INSERT INTO payables(sheet,sign_date,contract_no,our_company,supplier,
                   total_amount,payment_terms,prepayment,tail_payment,due_date,due_date_raw,notes,upload_batch)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (r['sheet'],r['sign_date'],r['contract_no'],r['our_company'],r['supplier'],
                 r['total_amount'],r['payment_terms'],r['prepayment'],r['tail_payment'],
                 r['due_date'],r['due_date_raw'],r['notes'],batch))
        inserted += 1
    return jsonify({'ok':True,'count':inserted,'skipped':skipped,'batch':batch})


@app.route('/api/payables/<int:pid>/subpaid', methods=['PUT'])
@admin_required
def api_mark_subpaid(pid):
    d = request.json
    ptype = d.get('type')  # 'prepayment' or 'tail'
    paid = 1 if d.get('paid') else 0
    if ptype == 'prepayment':
        execute("UPDATE payables SET prepayment_paid=?,updated_at=datetime('now') WHERE id=?", (paid, pid))
    elif ptype == 'tail':
        execute("UPDATE payables SET tail_paid=?,updated_at=datetime('now') WHERE id=?", (paid, pid))
    else:
        return jsonify({'error': '无效类型'}), 400
    return jsonify({'ok': True})

@app.route('/api/payables/<int:pid>/fields', methods=['PUT'])
@admin_required
def api_update_fields(pid):
    d = request.json
    allowed = ['sign_date','due_date','contract_no','our_company']
    sets, vals = [], []
    for k in allowed:
        if k in d:
            sets.append(f"{k}=?")
            vals.append(d[k] or None)
    if not sets:
        return jsonify({'error':'无有效字段'}), 400
    vals.append(pid)
    execute(f"UPDATE payables SET {','.join(sets)},updated_at=datetime('now') WHERE id=?", tuple(vals))
    return jsonify({'ok': True})

@app.route('/api/payables/<int:pid>/notes', methods=['PUT'])
@admin_required
def api_update_notes(pid):
    notes = request.json.get('notes','')
    execute("UPDATE payables SET notes=?,updated_at=datetime('now') WHERE id=?",(notes[:500],pid))
    return jsonify({'ok':True})

@app.route('/api/payables/<int:pid>/payment', methods=['PUT'])
@admin_required
def api_update_payment(pid):
    d = request.json
    pre = d.get('prepayment')
    tail = d.get('tail_payment')
    pdays = d.get('payment_days')
    execute("UPDATE payables SET prepayment=?,tail_payment=?,payment_days=?,updated_at=datetime('now') WHERE id=?",
            (float(pre) if pre is not None else None,
             float(tail) if tail is not None else None,
             int(pdays) if pdays is not None else None, pid))
    return jsonify({'ok':True})

@app.route('/api/payables/<int:pid>/paid', methods=['PUT'])
@admin_required
def api_mark_paid(pid):
    is_paid=1 if request.json.get('is_paid') else 0
    paid_at=datetime.now().isoformat() if is_paid else None
    execute("UPDATE payables SET is_paid=?,paid_at=?,updated_at=datetime('now') WHERE id=?",(is_paid,paid_at,pid))
    return jsonify({'ok':True})

# ── Projects ──────────────────────────────────────────────────────────────────

@app.route('/api/projects')
@login_required
def api_projects():
    rows=query("""SELECT contract_no,contract_name,responsible,
                  COUNT(*) as supplier_count,
                  SUM(CASE WHEN goods_ready='√' THEN 1 ELSE 0 END) as ready_count,
                  MAX(updated_at) as last_updated
                  FROM project_tracking GROUP BY contract_no ORDER BY contract_no DESC""")
    return jsonify([dict(r) for r in rows])

@app.route('/api/projects/<path:cn>')
@login_required
def api_project_get(cn):
    return jsonify([dict(r) for r in query("SELECT * FROM project_tracking WHERE contract_no=? ORDER BY sort_order,id",(cn,))])

@app.route('/api/projects/<path:cn>/rows', methods=['POST'])
@admin_required
def api_project_add_row(cn):
    d=request.json
    cur=execute("""INSERT INTO project_tracking(contract_no,contract_name,responsible,supplier,
                   goods_ready,inspection_photo,ship_date,location,packing_list,label_ok,invoice_ok,
                   qty,net_weight,gross_weight,volume,remark,sort_order)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cn,d.get('contract_name',''),d.get('responsible',''),d.get('supplier','新供应商'),
                 '','','','','','','',None,None,None,None,'',d.get('sort_order',0)))
    return jsonify({'ok':True,'id':cur.lastrowid})

@app.route('/api/projects/rows/<int:rid>', methods=['PUT'])
@admin_required
def api_project_row_put(rid):
    d=request.json
    allowed=['supplier','goods_ready','inspection_photo','ship_date','location','packing_list',
             'label_ok','invoice_ok','qty','net_weight','gross_weight','volume','remark',
             'sort_order','contract_name','responsible']
    fields,vals=[],[]
    for k in allowed:
        if k in d: fields.append(f"{k}=?"); vals.append(d[k])
    if not fields: return jsonify({'error':'无内容'}),400
    fields.append("updated_at=datetime('now')"); vals.append(rid)
    execute(f"UPDATE project_tracking SET {', '.join(fields)} WHERE id=?",vals)
    return jsonify({'ok':True})

@app.route('/api/projects/rows/<int:rid>', methods=['DELETE'])
@admin_required
def api_project_row_del(rid):
    execute("DELETE FROM project_tracking WHERE id=?",(rid,))
    return jsonify({'ok':True})

@app.route('/api/projects/<path:cn>', methods=['DELETE'])
@admin_required
def api_project_del(cn):
    execute("DELETE FROM project_tracking WHERE contract_no=?",(cn,))
    return jsonify({'ok':True})

@app.route('/api/projects/<path:cn>/import', methods=['POST'])
@admin_required
def api_project_import(cn):
    d=request.json; rows=d.get('rows',[])
    execute("DELETE FROM project_tracking WHERE contract_no=?",(cn,))
    for i,r in enumerate(rows):
        execute("""INSERT INTO project_tracking(contract_no,contract_name,responsible,supplier,
                   goods_ready,inspection_photo,ship_date,location,packing_list,label_ok,invoice_ok,
                   qty,net_weight,gross_weight,volume,remark,sort_order)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cn,d.get('contract_name',''),d.get('responsible',''),
                 r.get('supplier',''),r.get('goods_ready',''),r.get('inspection_photo',''),
                 r.get('ship_date',''),r.get('location',''),r.get('packing_list',''),
                 r.get('label_ok',''),r.get('invoice_ok',''),
                 r.get('qty'),r.get('net_weight'),r.get('gross_weight'),r.get('volume'),
                 r.get('remark',''),i))
    return jsonify({'ok':True,'count':len(rows)})

# ── Report schedule ───────────────────────────────────────────────────────────

@app.route('/api/report_schedule')
@login_required
def api_sched_get():
    r=query("SELECT * FROM report_schedule WHERE id=1",one=True)
    return jsonify(dict(r) if r else {})

@app.route('/api/report_schedule', methods=['PUT'])
@admin_required
def api_sched_put():
    d=request.json
    execute("UPDATE report_schedule SET emails=?,send_time=?,send_time2=?,report_title=?,enabled=?,updated_at=datetime('now') WHERE id=1",
            (d.get('emails',''),d.get('send_time','08:00'),d.get('send_time2','16:30'),
             d.get('report_title','采购应付款每日预警日报'),1 if d.get('enabled',True) else 0))
    restart_scheduler()
    return jsonify({'ok':True})

@app.route('/api/report_schedule/send_now', methods=['POST'])
@admin_required
def api_send_now():
    ok,msg=send_daily_report()
    return jsonify({'ok':ok,'msg':msg}) if ok else (jsonify({'error':msg}),500)

@app.route('/api/report_log')
@login_required
def api_report_log():
    return jsonify([dict(r) for r in query("SELECT * FROM report_log ORDER BY sent_at DESC LIMIT 30")])

# ── Report logic ──────────────────────────────────────────────────────────────

def days_until(s):
    if not s: return None
    try:
        d=datetime.strptime(str(s)[:10],'%Y-%m-%d')
        t=datetime.now().replace(hour=0,minute=0,second=0,microsecond=0)
        return (d-t).days
    except: return None

def send_daily_report():
    with app.app_context():
        try:
            sched=query("SELECT * FROM report_schedule WHERE id=1",one=True)
            if not sched or not sched['emails'] or not sched['enabled']:
                return False,'日报未启用或无收件人'
            emails=[e.strip() for e in sched['emails'].split(',') if e.strip()]
            rows=query("SELECT * FROM payables WHERE is_paid=0 AND due_date IS NOT NULL")
            urgent,warning=[],[]
            for r in rows:
                n=days_until(r['due_date'])
                if n is None: continue
                if 0<=n<=3: urgent.append(dict(r))
                elif 4<=n<=7: warning.append(dict(r))
            smtp_host=os.environ.get('SMTP_HOST','smtp.gmail.com')
            smtp_port=int(os.environ.get('SMTP_PORT','587'))
            smtp_user=os.environ.get('SMTP_USER','')
            smtp_pass=os.environ.get('SMTP_PASS','')
            if not smtp_user or not smtp_pass: return False,'SMTP未配置'
            def fmt(v): return f'¥{v:,.2f}' if v else '—'
            def trs(items,color):
                if not items: return '<tr><td colspan="5" style="text-align:center;color:#999;padding:10px">暂无</td></tr>'
                return ''.join(f'<tr><td style="padding:7px 12px;border-bottom:1px solid #f0f0f0">{r["supplier"]}</td><td style="padding:7px 12px;border-bottom:1px solid #f0f0f0;color:#666">{r["sheet"]}</td><td style="padding:7px 12px;border-bottom:1px solid #f0f0f0;font-family:monospace">{fmt(r["tail_payment"] or r["total_amount"])}</td><td style="padding:7px 12px;border-bottom:1px solid #f0f0f0;color:{color};font-weight:600">{days_until(r["due_date"])}天后</td><td style="padding:7px 12px;border-bottom:1px solid #f0f0f0;color:#999">{r["due_date"] or "—"}</td></tr>' for r in items)
            ut=sum((r['tail_payment'] or r['total_amount'] or 0) for r in urgent)
            wt=sum((r['tail_payment'] or r['total_amount'] or 0) for r in warning)
            today=datetime.now().strftime('%Y年%m月%d日')
            th='<th style="padding:7px 12px;text-align:left;color:#999;font-weight:500">'
            html=f'''<div style="font-family:'PingFang SC',Arial,sans-serif;max-width:750px;margin:0 auto;background:#f8f7f4;padding:20px">
<div style="background:#1a1714;border-radius:10px;padding:18px 22px;margin-bottom:16px"><h1 style="color:#fff;margin:0;font-size:17px">{sched["report_title"]}</h1><p style="color:rgba(255,255,255,.4);margin:3px 0 0;font-size:11px">{today} 自动发送</p></div>
<div style="display:flex;gap:12px;margin-bottom:16px">
<div style="flex:1;background:#fff;border-radius:8px;padding:14px;border-left:3px solid #c54b1e"><div style="font-size:10px;color:#999;text-transform:uppercase">紧急预警 3天内</div><div style="font-size:26px;font-weight:700;color:#c54b1e;margin:3px 0">{len(urgent)}</div><div style="font-size:11px;color:#666">应付合计 ¥{ut:,.2f}</div></div>
<div style="flex:1;background:#fff;border-radius:8px;padding:14px;border-left:3px solid #b36b00"><div style="font-size:10px;color:#999;text-transform:uppercase">预警提醒 7天内</div><div style="font-size:26px;font-weight:700;color:#b36b00;margin:3px 0">{len(warning)}</div><div style="font-size:11px;color:#666">应付合计 ¥{wt:,.2f}</div></div>
</div>
<div style="background:#fff;border-radius:8px;margin-bottom:12px;overflow:hidden"><div style="background:#fdf0eb;padding:10px 14px;font-weight:600;color:#c54b1e;font-size:13px">🔴 紧急预警（{len(urgent)}条）</div><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:#fafafa">{th}供应商</th>{th}负责人</th>{th}应付金额</th>{th}剩余天数</th>{th}到期日</th></tr></thead><tbody>{trs(urgent,"#c54b1e")}</tbody></table></div>
<div style="background:#fff;border-radius:8px;overflow:hidden"><div style="background:#fef7ea;padding:10px 14px;font-weight:600;color:#b36b00;font-size:13px">🟠 预警提醒（{len(warning)}条）</div><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="background:#fafafa">{th}供应商</th>{th}负责人</th>{th}应付金额</th>{th}剩余天数</th>{th}到期日</th></tr></thead><tbody>{trs(warning,"#b36b00")}</tbody></table></div>
<p style="color:#aaa;font-size:10px;text-align:center;margin-top:14px">此邮件由系统自动发送，请勿回复</p></div>'''
            msg=MIMEMultipart('alternative')
            msg['Subject']=f"{sched['report_title']} — {today}"
            msg['From']=smtp_user; msg['To']=', '.join(emails)
            msg.attach(MIMEText(html,'html','utf-8'))
            with smtplib.SMTP(smtp_host,smtp_port) as srv:
                srv.ehlo(); srv.starttls(); srv.login(smtp_user,smtp_pass)
                srv.sendmail(smtp_user,emails,msg.as_string())
            execute("INSERT INTO report_log(sent_at,recipients,urgent_count,warning_count,status) VALUES(datetime('now'),?,?,?,'success')",
                    (', '.join(emails),len(urgent),len(warning)))
            return True,f'已发送至 {", ".join(emails)}'
        except Exception as e:
            try: execute("INSERT INTO report_log(sent_at,status,error) VALUES(datetime('now'),'error',?)",(str(e),))
            except: pass
            return False,str(e)

# ── Scheduler ─────────────────────────────────────────────────────────────────

if HAS_SCHEDULER:
    scheduler=BackgroundScheduler(timezone='Asia/Shanghai')

def restart_scheduler():
    if not HAS_SCHEDULER: return
    for jid in ['dr1','dr2']:
        if scheduler.get_job(jid): scheduler.remove_job(jid)
    with app.app_context():
        s=query("SELECT * FROM report_schedule WHERE id=1",one=True)
        if s and s['enabled'] and s['emails']:
            t1 = s['send_time'] if s['send_time'] else '08:00'
            t2 = s['send_time2'] if s['send_time2'] else '16:30'
            for i, t in enumerate([t1, t2], 1):
                try:
                    if not t: continue
                    h,m=t.strip().split(':')
                    scheduler.add_job(send_daily_report,'cron',hour=int(h),minute=int(m),
                                      id=f'dr{i}',replace_existing=True)
                    print(f"[Scheduler] 日报{i}: 每天 {t}")
                except Exception as e: print(f"[Scheduler] 定时{i}失败: {e}")


@app.route('/download_template')
@login_required
def download_template():
    import base64 as _b, io
    data = _b.b64decode('UEsDBBQAAAAIAFK7nFxGx01IlQAAAM0AAAAQAAAAZG9jUHJvcHMvYXBwLnhtbE3PTQvCMAwG4L9SdreZih6kDkQ9ip68zy51hbYpbYT67+0EP255ecgboi6JIia2mEXxLuRtMzLHDUDWI/o+y8qhiqHke64x3YGMsRoPpB8eA8OibdeAhTEMOMzit7Dp1C5GZ3XPlkJ3sjpRJsPiWDQ6sScfq9wcChDneiU+ixNLOZcrBf+LU8sVU57mym/8ZAW/B7oXUEsDBBQAAAAIAFK7nFwi95pK7gAAACsCAAARAAAAZG9jUHJvcHMvY29yZS54bWzNks9KxDAQh19Fcm+nTaVK6OaieFIQXFC8hWR2N9j8IRlp9+1t624X0QfwmJlfvvkGptNR6JDwOYWIiSzmq9H1PgsdN+xAFAVA1gd0KpdTwk/NXUhO0fRMe4hKf6g9Aq+qFhySMooUzMAirkQmO6OFTqgopBPe6BUfP1O/wIwG7NGhpwx1WQOT88R4HPsOLoAZRphc/i6gWYlL9U/s0gF2So7ZrqlhGMqhWXLTDjW8PT2+LOsW1mdSXuP0K1tBx4gbdp782tzdbx+Y5BVvi+q64Ldb3gjeiubmfXb94XcRdsHYnf3HxmdB2cGvu5BfUEsDBBQAAAAIAFK7nFyZXJwjEAYAAJwnAAATAAAAeGwvdGhlbWUvdGhlbWUxLnhtbO1aW3PaOBR+76/QeGf2bQvGNoG2tBNzaXbbtJmE7U4fhRFYjWx5ZJGEf79HNhDLlg3tkk26mzwELOn7zkVH5+g4efPuLmLohoiU8nhg2S/b1ru3L97gVzIkEUEwGaev8MAKpUxetVppAMM4fckTEsPcgosIS3gUy9Zc4FsaLyPW6rTb3VaEaWyhGEdkYH1eLGhA0FRRWm9fILTlHzP4FctUjWWjARNXQSa5iLTy+WzF/NrePmXP6TodMoFuMBtYIH/Ob6fkTlqI4VTCxMBqZz9Wa8fR0kiAgsl9lAW6Sfaj0xUIMg07Op1YznZ89sTtn4zK2nQ0bRrg4/F4OLbL0otwHATgUbuewp30bL+kQQm0o2nQZNj22q6RpqqNU0/T933f65tonAqNW0/Ta3fd046Jxq3QeA2+8U+Hw66JxqvQdOtpJif9rmuk6RZoQkbj63oSFbXlQNMgAFhwdtbM0gOWXin6dZQa2R273UFc8FjuOYkR/sbFBNZp0hmWNEZynZAFDgA3xNFMUHyvQbaK4MKS0lyQ1s8ptVAaCJrIgfVHgiHF3K/99Ze7yaQzep19Os5rlH9pqwGn7bubz5P8c+jkn6eT101CznC8LAnx+yNbYYcnbjsTcjocZ0J8z/b2kaUlMs/v+QrrTjxnH1aWsF3Pz+SejHIju932WH32T0duI9epwLMi15RGJEWfyC265BE4tUkNMhM/CJ2GmGpQHAKkCTGWoYb4tMasEeATfbe+CMjfjYj3q2+aPVehWEnahPgQRhrinHPmc9Fs+welRtH2Vbzco5dYFQGXGN80qjUsxdZ4lcDxrZw8HRMSzZQLBkGGlyQmEqk5fk1IE/4rpdr+nNNA8JQvJPpKkY9psyOndCbN6DMawUavG3WHaNI8ev4F+Zw1ChyRGx0CZxuzRiGEabvwHq8kjpqtwhErQj5iGTYacrUWgbZxqYRgWhLG0XhO0rQR/FmsNZM+YMjszZF1ztaRDhGSXjdCPmLOi5ARvx6GOEqa7aJxWAT9nl7DScHogstm/bh+htUzbCyO90fUF0rkDyanP+kyNAejmlkJvYRWap+qhzQ+qB4yCgXxuR4+5Xp4CjeWxrxQroJ7Af/R2jfCq/iCwDl/Ln3Ppe+59D2h0rc3I31nwdOLW95GblvE+64x2tc0LihjV3LNyMdUr5Mp2DmfwOz9aD6e8e362SSEr5pZLSMWkEuBs0EkuPyLyvAqxAnoZFslCctU02U3ihKeQhtu6VP1SpXX5a+5KLg8W+Tpr6F0PizP+Txf57TNCzNDt3JL6raUvrUmOEr0scxwTh7LDDtnPJIdtnegHTX79l125COlMFOXQ7gaQr4Dbbqd3Do4npiRuQrTUpBvw/npxXga4jnZBLl9mFdt59jR0fvnwVGwo+88lh3HiPKiIe6hhpjPw0OHeXtfmGeVxlA0FG1srCQsRrdguNfxLBTgZGAtoAeDr1EC8lJVYDFbxgMrkKJ8TIxF6HDnl1xf49GS49umZbVuryl3GW0iUjnCaZgTZ6vK3mWxwVUdz1Vb8rC+aj20FU7P/lmtyJ8MEU4WCxJIY5QXpkqi8xlTvucrScRVOL9FM7YSlxi84+bHcU5TuBJ2tg8CMrm7Oal6ZTFnpvLfLQwJLFuIWRLiTV3t1eebnK56Inb6l3fBYPL9cMlHD+U751/0XUOufvbd4/pukztITJx5xREBdEUCI5UcBhYXMuRQ7pKQBhMBzZTJRPACgmSmHICY+gu98gy5KRXOrT45f0Usg4ZOXtIlEhSKsAwFIRdy4+/vk2p3jNf6LIFthFQyZNUXykOJwT0zckPYVCXzrtomC4Xb4lTNuxq+JmBLw3punS0n/9te1D20Fz1G86OZ4B6zh3OberjCRaz/WNYe+TLfOXDbOt4DXuYTLEOkfsF9ioqAEativrqvT/klnDu0e/GBIJv81tuk9t3gDHzUq1qlZCsRP0sHfB+SBmOMW/Q0X48UYq2msa3G2jEMeYBY8wyhZjjfh0WaGjPVi6w5jQpvQdVA5T/b1A1o9g00HJEFXjGZtjaj5E4KPNz+7w2wwsSO4e2LvwFQSwMEFAAAAAgAUrucXOQ+muJKBgAAwyUAABgAAAB4bC93b3Jrc2hlZXRzL3NoZWV0MS54bWylmtlu20YUhl+FUNBcFEg0CzkcxgvQ0FzRAEbcxegdI9O2EElUKbpO+vSdhZJNef6QaS4smfzmLPPPHErHntPHpv28u6/rzvuyXm12Z7P7rtu+m893i/t6Xe3eNtt6o8ht066rTl22d/Pdtq2rG2O0Xs0ZIWK+rpab2fmpuXfZnp82D91quakvW2/3sF5X7df39ap5PJvR2f7Gx+XdfadvzM9Pt9VdfVV3v28vW3U1P3i5Wa7rzW7ZbLy2vj2b/ULflYxrAzPij2X9uHv2u6en8qlpPuuL4uZsRmba9ab2vl5tV0sVjM+8rtn+Wt92cb1aKYf+zKsW3fKf+lINO5t9arquWWuu0uyqTt26bZt/642JWa9qNVYls30x2Drpneo5/t0nPDvMRyf1/Pd95qkRVgn1qdrVcbP6c3nT3Z/N5My7qW+rh1X3sXnM616sQPtbNKudefUe7VhGZt7iYaey6Y1VBuvlxr5XX3qRnxtIYMB6A3ZkQH1gwHsDfhyBAQO/N/CPIwhgEPQGwZEBR5MWvYGYOoewNwinGsjeQE41iHqD6FglZEDJfuWI2UF2yc1+uai66vy0bR691ozX++JJi8NOUVt/oUeY3WgGqrvLjS7Kq65VdKkcduevX1HGiX/y+hUPOY30u6A+Ve+MUKnvs9APDI+Ib94DIYW+T30p7XhuxvHAl8ZO8tDYUaH9sYgFeryOExi7gLL+Xd/nLLD21I8M9wNq7Jng+ppGkYmj4zHrn1CTRyjkiffb1YU39/5KY/2aX6vXD4mnvXBGjBfJdRQRcBKeXGkBbWgdglNmU5CBz01o6YdmsEra8MikxJkfGmlUrjYVKozzgAd8ypQoYcZOENZLzMJeul5qJfHpvFMrrZdlvlA/aoUPy8zsMj8V1ctlZmaZGVzmb+f48zC4cfl+1CXhRhbms9615MTpKh5zxanadXZRfWGVkkY5waPoxOHxYjS5gNrtJki/naW/n69weUy+V0Hm2w2qCseuakSEM9d0XMhhqR1y9rmK4PCYjerZF+uLIh7LNR/NlduVmuyxGPfYe5K+fWAQyllfHd/cA+WoZxZGRsdQSvKt+uK2vqjE9cVNLI5jHT229s8QxiKll35MqVWlhNDra0Jd1fa/Azir0G54cnjIuYpyNKJNnREm3hD6hgauOhx1clSHh0pX+bIXdbl/NrvqczxSJMxTlnPJX66A+lRT8rvKc5oO9jNEnDDyE66vwydHFAj/+R7ePzuEsOPVtTyR2tWwoFzF/oMTZ5Ix17zzHxWUMlVWror/ro3F33BXPZTjTp4Xt14K37d1IOTxBhoUuz9e7L6J7ZvYuq15qlJIYkuCl+QCkgSSFJIMkhySApLSRQZqBeNqBVAtSOIAqgVJAkkKSQZJDkkBSekiA7XEuFoCqgVJLKBakCSQpJBkkOSQFJCULjJQKxxXK4RqQRKHUC1IEkhSSDJIckgKSEoXGaglx9WSUC1IYgnVgiSBJIUkgySHpICkdJGBWtG4WhFUC5I4gmpBkkCSQpJBkkNSQFK6yEAt/feGMbn0GKAXRnGPXIphlGCUYpRhlGNUYFQ60VA4OkE4ioWDKO6RUziIEoxSjDKMcowKjEonGgrHJgjHsHAQxT1yCgdRglGKUYZRjlGBUelEQ+EmNKuUY+EginvkFA6iBKMUowyjHKMCo9KJhsJN+OJP8Td/jGKKv/tjlGCUYpRhlGNUYFQ60VC4CT0AxU0ARjHFbQBGCUYpRhlGOUYFRqUTDYWb0A5Q3A9gFFPcEWCUYJRilGGUY1RgVDrRULgJnQHFrQFGMcXNAUYJRilGGUY5RgVGpRMNhZvQJFDcJWAUU9wnYJRglGKUYZRjVGBUOtFQuAn9AsUNA0YxxS0DRglGKUYZRjlGBUalEw3/NTWhc2C4c8AoZrhzwCjBKMUowyjHqMCodKKhcBM6B4Y7B4xihjsHjBKMUowyjHKMCoxKJxoKN6FzYLhzwChmuHPAKMEoxSjDKMeowKh0oqFwEzoHhjsHjGKGOweMEoxSjDKMcowKjEonssLNn524WNftnTnhs/MWzcOmV+1w9+mEkj3z8zTcHm/6ULV3y83OW9W3ypS8DVW81qpvL7pma45p2GNF9mhHXd3UrR6g+G3TdPsLHeBwbuv8P1BLAwQUAAAACABSu5xc4n5FAEkDAACwEAAADQAAAHhsL3N0eWxlcy54bWzdWG1v2jAQ/iuRf8BCSMnIBEgtGtKkbaq0fthXQxyw5MSZYzror5/Pzhvg2+ja7sMSVbF99zz3+Hx2Qme1Pgr2bceYDg6FKOs52WldfQjDerNjBa3fyYqVxpJLVVBtumob1pViNKsBVIhwPBolYUF5SRazcl+sCl0HG7kv9ZyMSLiY5bLsRybEDRhXWrDgkYo5WVLB14pbX1pwcXTDYxjYSCFVoI0UNicRjNRPzhy5HqhseApeSgWDoYtwHudWcSp6UrVdG4Wj6d3NJIpPmEfXkKwb5wvClb2eT8gxwqm9hoTpNXze6PZRGxQXoluU98QNLGYV1ZqpcmU6FmMHL0xB0344VmZVtooeo/GEXA2opeAZhNwuz/J29zGxNAPoC0nHS7hfmXR1C/drk65W8Wr02qQTuFFS+zDVsJYqY6qrhzFphxYzwXJt4Ipvd/DUsoLal1rLwjQyTreypLZYWsQQGdjjZU70zh4PJ2W9tJfVBq5NjCsR1tfKuRJgPFvdVyKc82BiTcPka8OE+AYk3/MuaZGhOuSBOwE/ZXD4BbDZ2qbJdNN0NK4DgYZsjntAm/wVbVDxR6nv9mYGpe3/2EvN7hXL+cH2D3kXH2OPevbxGTutKnG8FXxbFszN/eqAixltccFOKv5kosEpBSVAgkemNN9Af2McmCLBT0WrB3bQzcEYHnJc8bhXHA8VR2+iuFV4oflPMuNe5s3by0QS+yeRN73IyduIfImk5B9LCptdOdj6Jxu/Gw3gRTwnX+FrSfRBgvWeC83LprfjWcbKi/1v6DVdm8+xE37jn7Gc7oV+6Ixz0re/sIzvi7TzuoeJN159+zMcmFHSfVyYWLzM2IFly6ZrTsCTd4e7AHBu6b9wLi0Yxtn8FrBhcTAFGMahsDj/03ym6HycDdM29VqmKGaKYhzKZ1naG4vjx6Tm8s80TeM4SbCMutf1hYIllrckgT8/G6YNEFgciPS8XOOrjVfI7+sAW9PfVQg2U7wSsZniuQaLP2+ASFP/amNxAIGtAlY7EN8fB2rKj4nj9iPQpw3bwbglTTEL1KK/RpMEyU4Ct399sF0Sx2nqt4DNryCOMQvsRtyCKQANmCW2P7/Ds/dR2L6nwv5/FItfUEsDBBQAAAAIAFK7nFyXirscwAAAABMCAAALAAAAX3JlbHMvLnJlbHOdkrluwzAMQH/F0J4wB9AhiDNl8RYE+QFWog/YEgWKRZ2/r9qlcZALGXk9PBLcHmlA7TiktoupGP0QUmla1bgBSLYlj2nOkUKu1CweNYfSQETbY0OwWiw+QC4ZZre9ZBanc6RXiFzXnaU92y9PQW+ArzpMcUJpSEszDvDN0n8y9/MMNUXlSiOVWxp40+X+duBJ0aEiWBaaRcnToh2lfx3H9pDT6a9jIrR6W+j5cWhUCo7cYyWMcWK0/jWCyQ/sfgBQSwMEFAAAAAgAUrucXIhYDZMyAQAAIAIAAA8AAAB4bC93b3JrYm9vay54bWyNUdFqwkAQ/JVwH9BEaYWK8aXSViitVPH9TDZm8e427G209eu7SQgV+tKnvZ1Zhpm5xYX4dCA6JV/ehZibWqSZp2ksavA23lEDQZmK2FvRlY9pbBhsGWsA8S6dZtks9RaDWS5GrQ2ntwsJFIIUFOyAPcIl/vLdmpwx4gEdyndu+rcDk3gM6PEKZW4yk8SaLq/EeKUg1m0LJudyMxmIPbBg8QfediZ39hB7ROzh06qR3MwyFayQo/QXvb5Vj2fQ42FrhZ7RCfDKCrwwtQ2GYyejKdKbGH0P4xxKnPN/aqSqwgJWVLQeggw9MrjOYIg1NtEkwXrIzW676tKo/LockolauumJ56gEr8vB3OiohAoDlO8qEhXXdooNJ93odab3D5NHbaF17kmxj/BGthwDjp+z/AFQSwMEFAAAAAgAUrucXCQem6KtAAAA+AEAABoAAAB4bC9fcmVscy93b3JrYm9vay54bWwucmVsc7WRPQ6DMAyFrxLlADVQqUMFTF1YKy4QBfMjEhLFrgq3L4UBkDp0YbKeLX/vyU6faBR3bqC28yRGawbKZMvs7wCkW7SKLs7jME9qF6ziWYYGvNK9ahCSKLpB2DNknu6Zopw8/kN0dd1pfDj9sjjwDzC8XeipRWQpShUa5EzCaLY2wVLiy0yWoqgyGYoqlnBaIOLJIG1pVn2wT06053kXN/dFrs3jCa7fDHB4dP4BUEsDBBQAAAAIAFK7nFxlkHmSGQEAAM8DAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbK2TTU7DMBCFrxJlWyUuLFigphtgC11wAWNPGqv+k2da0tszTtpKoBIVhU2seN68z56XrN6PEbDonfXYlB1RfBQCVQdOYh0ieK60ITlJ/Jq2Ikq1k1sQ98vlg1DBE3iqKHuU69UztHJvqXjpeRtN8E2ZwGJZPI3CzGpKGaM1ShLXxcHrH5TqRKi5c9BgZyIuWFCKq4Rc+R1w6ns7QEpGQ7GRiV6lY5XorUA6WsB62uLKGUPbGgU6qL3jlhpjAqmxAyBn69F0MU0mnjCMz7vZ/MFmCsjKTQoRObEEf8edI8ndVWQjSGSmr3ghsvXs+0FOW4O+kc3j/QxpN+SBYljmz/h7xhf/G87xEcLuvz+xvNZOGn/mi+E/Xn8BUEsBAhQDFAAAAAgAUrucXEbHTUiVAAAAzQAAABAAAAAAAAAAAAAAAIABAAAAAGRvY1Byb3BzL2FwcC54bWxQSwECFAMUAAAACABSu5xcIveaSu4AAAArAgAAEQAAAAAAAAAAAAAAgAHDAAAAZG9jUHJvcHMvY29yZS54bWxQSwECFAMUAAAACABSu5xcmVycIxAGAACcJwAAEwAAAAAAAAAAAAAAgAHgAQAAeGwvdGhlbWUvdGhlbWUxLnhtbFBLAQIUAxQAAAAIAFK7nFzkPpriSgYAAMMlAAAYAAAAAAAAAAAAAACAgSEIAAB4bC93b3Jrc2hlZXRzL3NoZWV0MS54bWxQSwECFAMUAAAACABSu5xc4n5FAEkDAACwEAAADQAAAAAAAAAAAAAAgAGhDgAAeGwvc3R5bGVzLnhtbFBLAQIUAxQAAAAIAFK7nFyXirscwAAAABMCAAALAAAAAAAAAAAAAACAARUSAABfcmVscy8ucmVsc1BLAQIUAxQAAAAIAFK7nFyIWA2TMgEAACACAAAPAAAAAAAAAAAAAACAAf4SAAB4bC93b3JrYm9vay54bWxQSwECFAMUAAAACABSu5xcJB6boq0AAAD4AQAAGgAAAAAAAAAAAAAAgAFdFAAAeGwvX3JlbHMvd29ya2Jvb2sueG1sLnJlbHNQSwECFAMUAAAACABSu5xcZZB5khkBAADPAwAAEwAAAAAAAAAAAAAAgAFCFQAAW0NvbnRlbnRfVHlwZXNdLnhtbFBLBQYAAAAACQAJAD4CAACMFgAAAAA=')
    return app.response_class(
        response=data,
        status=200,
        headers={
            'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'Content-Disposition': 'attachment; filename="采购付款台账导入模版.xlsx"'
        }
    )

@app.route('/health')
def health(): return jsonify({'status':'ok','time':datetime.now().isoformat()})

with app.app_context():
    init_db()
    restart_scheduler()

if HAS_SCHEDULER:
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())



# ── 一次性数据导入路由（数据已从Excel预处理） ──────────────────────────────


@app.route('/import_data_now')
def import_data_now():
    secret = request.args.get('key','')
    if secret != os.environ.get('ADMIN_PASSWORD','admin123456'):
        return 'forbidden', 403
    db = get_db()
    db.execute('DELETE FROM payables')
    for r in _PAYABLES_DATA:
        db.execute(
            'INSERT INTO payables(sheet,sign_date,contract_no,our_company,supplier,total_amount,payment_terms,prepayment,tail_payment,due_date,due_date_raw,notes,upload_batch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (r['sheet'],r.get('sign_date'),r.get('contract_no',''),r.get('our_company',''),
             r['supplier'],r.get('total_amount'),r.get('payment_terms',''),r.get('prepayment'),
             r.get('tail_payment'),r.get('due_date'),r.get('due_date_raw',''),r.get('notes',''),'import_route')
        )
    db.commit()
    c = db.execute('SELECT COUNT(*) FROM payables').fetchone()[0]
    t = db.execute('SELECT SUM(total_amount) FROM payables WHERE total_amount IS NOT NULL').fetchone()[0]
    return f'OK: {c} records imported, total CNY {t:,.0f}'




@app.route('/seed_payables')
def seed_payables():
    if request.args.get('k') != os.environ.get('ADMIN_PASSWORD','admin123456'):
        return 'forbidden', 403
    import json as _j, base64 as _b, gzip as _g
    raw = _b.b64decode('H4sIAM445mkC/9WYW4vrNhCA/0oI7NtZMyNpRqPzWFraUuhL+1DalOCL3C5knZC1KYfS/16NE+/mbJx0E3JMNwTFWGNpMt/c5N/+nj/9GWM7/zibLzpPFhYdlYiLzkUs5x9m86eHP5pllbdRRQwYvgd7D0anynXTbvOyXTZrnfz5p68NgwGGH74BVIF1t12W68dN3nzabcAVhTSWVC86CT6NZLBI13WVRsI6T6ONNsl4SJKBSRVCLvV+Lb1C3WazeojbvcoxN0maKq/SJSc5jnonmvQ8VVXUJyvRUXQPZjm3ertu89Uyf1x3jRolEABkkCY2+afH2LTLNm4fn3a2uEtLiDi1lW7AhY2LJv3aSpe1RKpYTKNU3ge9F3qlUGg2m3m6U+mQS6lyVlV3oOuILdH1Skp/LyZpulPtNtu41yNpgGHQrc0fVsuXCc/DRNXFI3aG5wczy23+1+ezM4CP/VfFmnUb+387/+fD7Av4CslX3+8EjnyFCkH1FaWZruuBctpYDTuY6E1esvc4U6YxkPpd8rhyWMvXwBf4hPHOGUsXesWOs1TGH3Le8RV9iMok2IsfkSaXFvRjqA2G5NdyEjbKOdgoN4dNI7BH8I4gOkgNro6oiIr4VtyvELFBDicI2WsI+f8ghJKUkoyOCTmb4p37mTFAFs8BsnhrQGhuAcjXkiwhWNsrARm27Ki3ykQhZLwJGcLzh8eCCQJy5p5lzP8E2vkUGiZKoYXtq5ofzM4edS3jw7WJ1ARDMGEedSQ0WjFRrDtXMuFsyYSb83ZXB+mekpJJSPIhixK6F0qhUq8wApdkVCdTkkITeAxUyqXuJKaJwrLpVqsb4AmiLWGITvNpLLQnqWL90qH2SIy2hSFF+QWo0DmYkpURGQ8qJAPvGdZBwWPAaih7KZaKIZbIBD2+FH2MBfAXYCJrmTOZLqSAvc3sSN1zhoPNnHu/pCLxUJsCFk7t76mveWqoqMfKfe5z9XP9u/AoyKeCKjUVavki5Lp7hUeW5/Fj2v4Pv/9MRpj3B173ql2/Kiyc3Wf+iRp3i9IH4Ss4FrzPvnD/J5U6qbAPJzoBd49+pBP49btfUufnkPHHb8Fe9KLlMGu9ufM7WCsA5n3j765s/AOKlykbCbGeMobPevrX70ssgTlo+3EUu7s3/jR2nT2F/fd/AV65fj5mEwAA')
    records = _j.loads(_g.decompress(raw))
    db = get_db()
    db.execute("DELETE FROM payables")
    for r in records:
        execute("""INSERT INTO payables(sheet,sign_date,contract_no,our_company,supplier,total_amount,
            payment_terms,prepayment,tail_payment,due_date,due_date_raw,notes,upload_batch)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (r.get('sheet',''),r.get('sign_date'),r.get('contract_no',''),r.get('our_company',''),
             r.get('supplier',''),r.get('total_amount'),r.get('payment_terms',''),
             r.get('prepayment'),r.get('tail_payment'),r.get('due_date'),
             r.get('due_date_raw',''),r.get('notes',''),'seed_v4'))
    c = db.execute("SELECT COUNT(*) FROM payables").fetchone()[0]
    t = db.execute("SELECT SUM(total_amount) FROM payables WHERE total_amount IS NOT NULL").fetchone()[0] or 0
    return f'OK: {c} records, CNY {t:,.0f}'

if __name__=='__main__':
    port=int(os.environ.get('PORT',5001))
    app.run(host='0.0.0.0',port=port,debug=False)
