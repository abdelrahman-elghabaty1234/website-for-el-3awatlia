import os, re, io, csv, json, random, sqlite3, hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, session, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get('QUIZ_DB', os.path.join(BASE, 'quiz.db'))
app = Flask(__name__, static_folder=os.path.join(BASE, 'static'))
SK = os.path.join(BASE, '.secret')
if not os.path.exists(SK):
    open(SK, 'w').write(os.urandom(24).hex())
app.secret_key = open(SK).read()
app.config.update(SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
                  MAX_CONTENT_LENGTH=30 * 1024 * 1024)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student');
CREATE TABLE IF NOT EXISTS subjects(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chapters(id INTEGER PRIMARY KEY, subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY, chapter_id INTEGER NOT NULL REFERENCES chapters(id) ON DELETE CASCADE,
  text TEXT NOT NULL, a TEXT NOT NULL, b TEXT NOT NULL, c TEXT NOT NULL, d TEXT NOT NULL, correct TEXT NOT NULL,
  expl TEXT DEFAULT '', difficulty TEXT, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS qh ON questions(hash);
CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE, finished TEXT, duration INTEGER, total INTEGER, correct INTEGER, unanswered INTEGER);
CREATE TABLE IF NOT EXISTS qstats(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE, rt INTEGER DEFAULT 0, wr INTEGER DEFAULT 0,
  last TEXT, streak INTEGER DEFAULT 0, PRIMARY KEY(user_id, question_id));
"""


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def close(e):
    d = g.pop('db', None)
    if d:
        d.close()


def q(sql, *a):
    return [dict(r) for r in db().execute(sql, a).fetchall()]


def x(sql, *a):
    c = db().execute(sql, a)
    db().commit()
    return c.lastrowid


def err(m, c=400):
    return jsonify(error=m), c


def init():
    with app.app_context():
        db().executescript(SCHEMA)
        if not q("SELECT 1 FROM users WHERE role='admin'"):
            x("INSERT INTO users(username,pw,role) VALUES('admin',?,'admin')", generate_password_hash('admin123'))
        if not q("SELECT 1 FROM subjects"):
            for n in ('Operating Systems (OS)', 'LO'):
                x("INSERT INTO subjects(name) VALUES(?)", n)


def need(role=None):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if 'uid' not in session:
                return err('Please log in.', 401)
            if role and session.get('role') != role:
                return err('Admins only.', 403)
            return f(*a, **k)
        return w
    return deco


# ---------- auth ----------
@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')


def login_as(u):
    session.clear()
    session.permanent = True
    session['uid'], session['role'] = u['id'], u['role']
    return jsonify(id=u['id'], username=u['username'], role=u['role'])


@app.post('/api/register')
def register():
    d = request.get_json() or {}
    n, p = (d.get('username') or '').strip(), d.get('password') or ''
    if not 3 <= len(n) <= 30 or len(p) < 6:
        return err('Username 3-30 chars and password at least 6 chars.')
    if q("SELECT 1 FROM users WHERE lower(username)=lower(?)", n):
        return err('Username already taken.')
    i = x("INSERT INTO users(username,pw) VALUES(?,?)", n, generate_password_hash(p))
    return login_as(dict(id=i, username=n, role='student'))


@app.post('/api/login')
def login():
    d = request.get_json() or {}
    u = q("SELECT * FROM users WHERE lower(username)=lower(?)", (d.get('username') or '').strip())
    if not u or not check_password_hash(u[0]['pw'], d.get('password') or ''):
        return err('Wrong username or password.', 401)
    return login_as(u[0])


@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify(ok=1)


@app.get('/api/me')
@need()
def me():
    u = q("SELECT id,username,role FROM users WHERE id=?", session['uid'])
    return jsonify(u[0]) if u else err('Please log in.', 401)


# ---------- subjects / chapters ----------
@app.get('/api/subjects')
@need()
def subjects():
    return jsonify(q("""SELECT s.id,s.name,
      (SELECT COUNT(*) FROM chapters c WHERE c.subject_id=s.id) chapters,
      (SELECT COUNT(*) FROM questions qu JOIN chapters c ON c.id=qu.chapter_id WHERE c.subject_id=s.id) questions
      FROM subjects s ORDER BY s.id"""))


@app.get('/api/subjects/<int:i>')
@need()
def subject(i):
    s = q("SELECT * FROM subjects WHERE id=?", i)
    if not s:
        return err('Subject not found.', 404)
    u = session['uid']
    ch = q("""SELECT c.id,c.name,(SELECT COUNT(*) FROM questions WHERE chapter_id=c.id) total,
      COALESCE(SUM(qs.rt),0) rt, COALESCE(SUM(qs.wr),0) wr, COUNT(qs.question_id) seen
      FROM chapters c LEFT JOIN questions qu ON qu.chapter_id=c.id
      LEFT JOIN qstats qs ON qs.question_id=qu.id AND qs.user_id=?
      WHERE c.subject_id=? GROUP BY c.id ORDER BY c.id""", u, i)
    rec = q("SELECT finished,total,correct,unanswered,duration FROM attempts WHERE user_id=? AND subject_id=? ORDER BY id DESC LIMIT 5", u, i)
    return jsonify(subject=s[0], chapters=ch, recent=rec)


def nm(d):
    n = ((d or {}).get('name') or '').strip()
    return n[:120] if n else None


@app.post('/api/subjects')
@need('admin')
def add_subject():
    n = nm(request.get_json())
    return jsonify(id=x("INSERT INTO subjects(name) VALUES(?)", n)) if n else err('Name required.')


@app.put('/api/subjects/<int:i>')
@need('admin')
def ren_subject(i):
    n = nm(request.get_json())
    if not n:
        return err('Name required.')
    x("UPDATE subjects SET name=? WHERE id=?", n, i)
    return jsonify(ok=1)


@app.delete('/api/subjects/<int:i>')
@need('admin')
def del_subject(i):
    x("DELETE FROM subjects WHERE id=?", i)
    return jsonify(ok=1)


@app.post('/api/chapters')
@need('admin')
def add_chapter():
    d = request.get_json() or {}
    n = nm(d)
    if not n or not q("SELECT 1 FROM subjects WHERE id=?", d.get('subject_id')):
        return err('Valid subject and name required.')
    return jsonify(id=x("INSERT INTO chapters(subject_id,name) VALUES(?,?)", d['subject_id'], n))


@app.put('/api/chapters/<int:i>')
@need('admin')
def ren_chapter(i):
    n = nm(request.get_json())
    if not n:
        return err('Name required.')
    x("UPDATE chapters SET name=? WHERE id=?", n, i)
    return jsonify(ok=1)


@app.delete('/api/chapters/<int:i>')
@need('admin')
def del_chapter(i):
    x("DELETE FROM chapters WHERE id=?", i)
    return jsonify(ok=1)


# ---------- question helpers ----------
def norm(s):
    return re.sub(r'\s+', ' ', str(s if s is not None else '')).strip()


def qhash(text):
    return hashlib.sha1(norm(text).lower().encode()).hexdigest()


def nq(r):
    ch = [norm(c) for c in (r.get('choices') or [])][:4]
    c = norm(r.get('correct'))
    if len(c) > 1:
        m = [i for i, t in enumerate(ch) if t.lower() == c.lower()]
        c = 'ABCD'[m[0]] if m else ''
    d = norm(r.get('difficulty')).capitalize()
    return dict(text=norm(r.get('text')), choices=ch, correct=c.upper(), explanation=norm(r.get('explanation')),
                difficulty=d if d in ('Easy', 'Medium', 'Hard') else '', chapter=norm(r.get('chapter')))


def check(r):
    e, w, ch = [], [], r['choices']
    if not r['text']:
        e.append('Missing question text')
    if len(ch) != 4 or not all(ch):
        e.append('Needs 4 non-empty choices')
    if r['correct'] not in list('ABCD'):
        e.append('Missing/invalid correct answer')
    if not e:
        k = 'ABCD'.index(r['correct'])
        o = [len(c) for j, c in enumerate(ch) if j != k]
        if len(ch[k]) > 25 and len(ch[k]) > 1.8 * sum(o) / 3:
            w.append('Correct answer is much longer than the others')
    return e, w


def insert_q(cid, r):
    c = r['choices']
    return x("INSERT INTO questions(chapter_id,text,a,b,c,d,correct,expl,difficulty,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
             cid, r['text'], c[0], c[1], c[2], c[3], r['correct'], r['explanation'], r['difficulty'] or None, qhash(r['text']))


def subject_hashes(sid):
    return {r['hash'] for r in q("SELECT qu.hash FROM questions qu JOIN chapters c ON c.id=qu.chapter_id WHERE c.subject_id=?", sid)}


# ---------- file parsing ----------
def from_dict(r):
    r = {norm(k).lower(): v for k, v in r.items() if k}
    g_ = lambda *k: next((r[i] for i in k if r.get(i) not in (None, '')), '')
    ch = r.get('choices')
    if not isinstance(ch, list):
        ch = [g_('a', 'option a', 'choice a'), g_('b', 'option b', 'choice b'),
              g_('c', 'option c', 'choice c'), g_('d', 'option d', 'choice d')]
    return dict(text=g_('question', 'text'), choices=ch, correct=g_('correct', 'answer', 'correct answer'),
                explanation=g_('explanation', 'expl'), difficulty=g_('difficulty'), chapter=g_('chapter'))


def parse_csv(b):
    t = b.decode('utf-8-sig')
    return [from_dict(r) for r in csv.DictReader(io.StringIO(t))], []


def parse_json(b):
    d = json.loads(b.decode('utf-8-sig'))
    if isinstance(d, dict):
        d = d.get('questions', [])
    return [from_dict(r) for r in d], []


def parse_xlsx(b):
    from openpyxl import load_workbook
    rows = list(load_workbook(io.BytesIO(b), read_only=True, data_only=True).active.iter_rows(values_only=True))
    if not rows:
        return [], []
    h = [norm(c) for c in rows[0]]
    return [from_dict(dict(zip(h, r))) for r in rows[1:] if any(r)], []


def parse_pdf(b):
    from pypdf import PdfReader
    text = '\n'.join((p.extract_text() or '') for p in PdfReader(io.BytesIO(b)).pages)
    if len(text.strip()) < 50:
        return [], ['No text found: the PDF is probably scanned images. It needs OCR first.']
    parts = re.split(r'\n\s*(?:Q(?:uestion)?\.?\s*)?(\d{1,4})\s*[\.\)\-:]\s+', '\n' + text)
    out, notes = [], []
    for num, body in zip(parts[1::2], parts[2::2]):
        ans = re.search(r'(?:correct\s+)?answer\s*(?:is)?\s*[:\-]?\s*\(?([A-Da-d])\b', body, re.I)
        ex = re.search(r'explanation\s*[:\-]\s*(.+)', body, re.I | re.S)
        cut = min([m.start() for m in (ans, ex) if m] or [len(body)])
        o = re.split(r'\n\s*\(?([A-Da-d])[\.\)]\s+', '\n' + body[:cut])
        letters = [l.upper() for l in o[1::2]]
        if letters != list('ABCD'):
            notes.append('Question %s skipped: could not find exactly 4 choices A-D.' % num)
            continue
        out.append(dict(text=o[0], choices=o[2::2], correct=ans.group(1) if ans else '',
                        explanation=ex.group(1) if ex else '', difficulty='', chapter=''))
    if not out:
        notes.append('No questions detected. Expected: "1. question", choices "A) ..", then "Answer: B".')
    return out, notes


PARSERS = {'csv': parse_csv, 'json': parse_json, 'xlsx': parse_xlsx, 'pdf': parse_pdf}


@app.post('/api/admin/preview')
@need('admin')
def preview():
    f = request.files.get('file')
    if not f:
        return err('Choose a file.')
    ext = f.filename.lower().rsplit('.', 1)[-1]
    if ext not in PARSERS:
        return err('Unsupported file. Use .xlsx, .csv, .json or .pdf')
    try:
        rows, notes = PARSERS[ext](f.read())
    except Exception as e:
        return err('Could not read file: %s' % e)
    items = []
    for r in rows:
        r = nq(r)
        r['errors'], r['warnings'] = check(r)
        items.append(r)
    return jsonify(questions=items, notes=notes)


@app.post('/api/admin/commit')
@need('admin')
def commit():
    d = request.get_json() or {}
    sid, default = d.get('subject_id'), d.get('chapter_id')
    seen = subject_hashes(sid)
    res = dict(added=0, duplicates=0, skipped=0)
    for r in d.get('questions', []):
        r = nq(r)
        cid = default
        if r['chapter']:
            f = q("SELECT id FROM chapters WHERE subject_id=? AND lower(name)=lower(?)", sid, r['chapter'])
            cid = f[0]['id'] if f else x("INSERT INTO chapters(subject_id,name) VALUES(?,?)", sid, r['chapter'])
        ok = cid and q("SELECT 1 FROM chapters WHERE id=? AND subject_id=?", cid, sid)
        if check(r)[0] or not ok:
            res['skipped'] += 1
        elif qhash(r['text']) in seen:
            res['duplicates'] += 1
        else:
            seen.add(qhash(r['text']))
            insert_q(cid, r)
            res['added'] += 1
    return jsonify(res)


# ---------- admin question CRUD ----------
@app.get('/api/admin/questions')
@need('admin')
def admin_qs():
    return jsonify(q("SELECT * FROM questions WHERE chapter_id=? ORDER BY id", request.args.get('chapter')))


def body_q():
    d = request.get_json() or {}
    r = nq(dict(d, choices=d.get('choices')))
    return d, r, check(r)[0]


@app.post('/api/admin/questions')
@need('admin')
def add_q():
    d, r, e = body_q()
    c = q("SELECT subject_id FROM chapters WHERE id=?", d.get('chapter_id'))
    if e or not c:
        return err('; '.join(e) or 'Choose a chapter.')
    if qhash(r['text']) in subject_hashes(c[0]['subject_id']):
        return err('Duplicate: this question already exists in the subject.', 409)
    return jsonify(id=insert_q(d['chapter_id'], r))


@app.put('/api/admin/questions/<int:i>')
@need('admin')
def edit_q(i):
    d, r, e = body_q()
    if e:
        return err('; '.join(e))
    c = r['choices']
    x("UPDATE questions SET chapter_id=?,text=?,a=?,b=?,c=?,d=?,correct=?,expl=?,difficulty=?,hash=? WHERE id=?",
      d.get('chapter_id'), r['text'], c[0], c[1], c[2], c[3], r['correct'], r['explanation'], r['difficulty'] or None, qhash(r['text']), i)
    return jsonify(ok=1)


@app.delete('/api/admin/questions/<int:i>')
@need('admin')
def del_q(i):
    x("DELETE FROM questions WHERE id=?", i)
    return jsonify(ok=1)


# ---------- quiz ----------
def weight(r):
    if not r['rt'] + r['wr']:
        return 3.0                                   # unseen: high priority
    if r['wr']:                                      # past mistakes: revise, fade with streak
        return max(.4, (2 + min(r['wr'], 5)) * .6 ** r['streak'])
    return .3                                        # only ever correct: low priority


@app.post('/api/quiz')
@need()
def gen_quiz():
    d = request.get_json() or {}
    sid, mist = d.get('subject'), bool(d.get('mistakes'))
    try:
        chs = [int(c) for c in d.get('chapters') or []]
        n = int(d.get('n') or 10)
    except ValueError:
        return err('Invalid input.')
    if not chs and not mist:
        return err('Select at least one chapter.')
    if not 1 <= n <= 200:
        return err('Number of questions must be between 1 and 200.')
    sql = ("SELECT qu.id,qu.text,qu.a,qu.b,qu.c,qu.d,c.name chapter,COALESCE(s.rt,0) rt,COALESCE(s.wr,0) wr,COALESCE(s.streak,0) streak "
           "FROM questions qu JOIN chapters c ON c.id=qu.chapter_id LEFT JOIN qstats s ON s.question_id=qu.id AND s.user_id=? "
           "WHERE c.subject_id=?")
    args = [session['uid'], sid]
    if chs:
        sql += ' AND qu.chapter_id IN (%s)' % ','.join('?' * len(chs))
        args += chs
    if d.get('difficulty') in ('Easy', 'Medium', 'Hard'):
        sql += ' AND qu.difficulty=?'
        args.append(d['difficulty'])
    if mist:
        sql += ' AND COALESCE(s.wr,0)>0 AND COALESCE(s.streak,0)<3'
    rows = q(sql, *args)
    if not rows:
        return err('No active mistakes to practice here.' if mist else 'No questions match your selection.')
    if mist:
        n = min(n, len(rows))
    if len(rows) < n:
        return err('Only %d questions match your selection but you asked for %d. Lower the number or select more chapters.' % (len(rows), n))
    picked = sorted(rows, key=lambda r: -(random.random() ** (1 / weight(r))))[:n]   # weighted sampling, no repeats
    random.shuffle(picked)
    out = []
    for r in picked:
        o = [dict(k=k, t=r[k.lower()]) for k in 'ABCD']
        if d.get('shuffle', True):
            random.shuffle(o)
        out.append(dict(id=r['id'], text=r['text'], chapter=r['chapter'], options=o))
    return jsonify(questions=out)


@app.post('/api/quiz/submit')
@need()
def submit():
    d = request.get_json() or {}
    ids = [int(i) for i in d.get('ids') or []]
    if not ids:
        return err('Empty quiz.')
    rows = {r['id']: r for r in q("""SELECT qu.*,c.name chapter,c.subject_id sid,s.name subject FROM questions qu
        JOIN chapters c ON c.id=qu.chapter_id JOIN subjects s ON s.id=c.subject_id WHERE qu.id IN (%s)""" % ','.join('?' * len(ids)), *ids)}
    ans, now, u = d.get('answers') or {}, datetime.now().isoformat(timespec='seconds'), session['uid']
    review, cor, un = [], 0, 0
    for i in ids:
        r = rows.get(i)
        if not r:
            continue
        ch = ans.get(str(i))
        ch = ch if ch in list('ABCD') else None
        ok = ch == r['correct']
        if ch:
            cor += ok
            x("""INSERT INTO qstats(user_id,question_id,rt,wr,last,streak) VALUES(?,?,?,?,?,?)
                 ON CONFLICT(user_id,question_id) DO UPDATE SET rt=rt+?,wr=wr+?,last=?,streak=CASE WHEN ?=1 THEN streak+1 ELSE 0 END""",
              u, i, int(ok), int(not ok), now, int(ok), int(ok), int(not ok), now, int(ok))
        else:
            un += 1
        review.append(dict(text=r['text'], a=r['a'], b=r['b'], c=r['c'], d=r['d'], correct=r['correct'], chosen=ch,
                           ok=ok, expl=r['expl'], chapter=r['chapter'], subject=r['subject']))
    if not review:
        return err('Questions no longer exist.')
    sid = rows[next(iter(rows))]['sid']
    tot = len(review)
    x("INSERT INTO attempts(user_id,subject_id,finished,duration,total,correct,unanswered) VALUES(?,?,?,?,?,?,?)",
      u, sid, now, int(d.get('duration') or 0), tot, cor, un)
    return jsonify(total=tot, correct=cor, wrong=tot - cor - un, unanswered=un, duration=int(d.get('duration') or 0),
                   subject_id=sid, review=review)


# ---------- mistakes & stats ----------
@app.get('/api/mistakes')
@need()
def mistakes():
    return jsonify(q("""SELECT qu.id,qu.text,c.name chapter,s.id sid,s.name subject,qs.rt,qs.wr,qs.last,qs.streak,
        CASE WHEN qs.streak>=3 THEN 'Mastered' WHEN qs.streak>0 THEN 'Improving' ELSE 'Needs practice' END status
        FROM qstats qs JOIN questions qu ON qu.id=qs.question_id JOIN chapters c ON c.id=qu.chapter_id
        JOIN subjects s ON s.id=c.subject_id WHERE qs.user_id=? AND qs.wr>0 ORDER BY (qs.streak>=3), qs.wr DESC""", session['uid']))


@app.get('/api/stats')
@need()
def stats():
    u = session['uid']
    t = q("SELECT COUNT(*) quizzes,COALESCE(SUM(correct),0) correct,COALESCE(SUM(total-unanswered),0) answered FROM attempts WHERE user_id=?", u)[0]
    j = "LEFT JOIN questions qu ON qu.chapter_id=c.id LEFT JOIN qstats qs ON qs.question_id=qu.id AND qs.user_id=?"
    subj = q("SELECT s.id,s.name,COALESCE(SUM(qs.rt),0) rt,COALESCE(SUM(qs.wr),0) wr FROM subjects s LEFT JOIN chapters c ON c.subject_id=s.id " + j + " GROUP BY s.id ORDER BY s.id", u)
    chap = q("SELECT c.id,c.name,s.name subject,COALESCE(SUM(qs.rt),0) rt,COALESCE(SUM(qs.wr),0) wr FROM chapters c JOIN subjects s ON s.id=c.subject_id " + j + " GROUP BY c.id ORDER BY c.id", u)
    hist = q("SELECT finished,total-unanswered answered,correct FROM attempts WHERE user_id=? ORDER BY id DESC LIMIT 20", u)[::-1]
    return jsonify(totals=t, subjects=subj, chapters=chap, history=hist)


init()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
