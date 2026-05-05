import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

# Gunakan path absolut agar tidak bergantung pada CWD
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "..", "..", "platform_state.db")

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Jobs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                target TEXT,
                status TEXT,
                start_time TEXT,
                end_time TEXT,
                findings TEXT,
                logs TEXT,
                metrics TEXT
            )
        ''')
        
        # Simple Migration: Add columns if they don't exist
        cursor.execute("PRAGMA table_info(jobs)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'metrics' not in columns:
            cursor.execute("ALTER TABLE jobs ADD COLUMN metrics TEXT DEFAULT '{}'")
        if 'findings' not in columns:
            cursor.execute("ALTER TABLE jobs ADD COLUMN findings TEXT DEFAULT '[]'")
        if 'logs' not in columns:
            cursor.execute("ALTER TABLE jobs ADD COLUMN logs TEXT DEFAULT '[]'")
        
        # AI Activities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_activities (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                activity_type TEXT,
                prompt TEXT,
                response TEXT,
                duration REAL,
                status TEXT,
                model_used TEXT,
                parameters TEXT,
                job_id TEXT,
                FOREIGN KEY (job_id) REFERENCES jobs (id)
            )
        ''')

        # NEW: Structured Vulnerabilities (from METATRON)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT,
                name TEXT,
                severity TEXT,
                port TEXT,
                service TEXT,
                description TEXT,
                timestamp TEXT,
                FOREIGN KEY (job_id) REFERENCES jobs (id)
            )
        ''')

        # NEW: Fixes (from METATRON)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fixes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_id INTEGER,
                job_id TEXT,
                fix_text TEXT,
                source TEXT,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (id),
                FOREIGN KEY (job_id) REFERENCES jobs (id)
            )
        ''')

        # NEW: Exploits (from METATRON)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT,
                exploit_name TEXT,
                tool_used TEXT,
                payload TEXT,
                result TEXT,
                notes TEXT,
                timestamp TEXT,
                FOREIGN KEY (job_id) REFERENCES jobs (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Storage] Error initializing database: {e}")

def save_job(job_dict: Dict[str, Any]):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO jobs (id, target, status, start_time, end_time, findings, logs, metrics)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            job_dict['id'],
            job_dict['target'],
            job_dict['status'],
            job_dict['start_time'],
            job_dict['end_time'],
            json.dumps(job_dict['findings']),
            json.dumps(job_dict['logs']),
            json.dumps(job_dict['metrics'])
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Storage] Error saving job: {e}")
        raise e

def save_ai_activity(activity_dict: Dict[str, Any]):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ai_activities (id, timestamp, activity_type, prompt, response, duration, status, model_used, parameters, job_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            activity_dict['id'],
            activity_dict['timestamp'],
            activity_dict['activity_type'],
            activity_dict['prompt'],
            activity_dict['response'],
            activity_dict['duration'],
            activity_dict['status'],
            activity_dict['model_used'],
            json.dumps(activity_dict['parameters']),
            activity_dict.get('job_id')
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Storage] Error saving AI activity: {e}")

def save_structured_vulnerability(job_id: str, vuln: Dict[str, Any]) -> int:
    """Save a structured vulnerability from METATRON logic."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO vulnerabilities (job_id, name, severity, port, service, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            job_id,
            vuln.get('vuln_name'),
            vuln.get('severity'),
            vuln.get('port'),
            vuln.get('service'),
            vuln.get('description'),
            now
        ))
        vuln_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return vuln_id
    except Exception as e:
        print(f"[Storage] Error saving structured vulnerability: {e}")
        return 0

def save_structured_fix(job_id: str, vuln_id: int, fix_text: str, source: str = "ai"):
    """Save a fix recommendation."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO fixes (vuln_id, job_id, fix_text, source)
            VALUES (?, ?, ?, ?)
        ''', (vuln_id, job_id, fix_text, source))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Storage] Error saving structured fix: {e}")

def save_structured_exploit(job_id: str, exploit: Dict[str, Any]):
    """Save an exploit attempt/detail."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO exploits (job_id, exploit_name, tool_used, payload, result, notes, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            job_id,
            exploit.get('exploit_name'),
            exploit.get('tool_used'),
            exploit.get('payload'),
            exploit.get('result'),
            exploit.get('notes'),
            now
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Storage] Error saving structured exploit: {e}")

def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single job with all its related structured findings."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM jobs WHERE id = ?', (job_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
        
    job = dict(row)
    try:
        job['findings'] = json.loads(job['findings'])
        job['logs'] = json.loads(job['logs'])
        job['metrics'] = json.loads(job['metrics'])
    except:
        job['findings'] = []
        job['logs'] = []
        job['metrics'] = {}
        
    # Enrich with structured vulnerabilities
    cursor.execute('SELECT * FROM vulnerabilities WHERE job_id = ?', (job_id,))
    vulns = [dict(v) for v in cursor.fetchall()]
    
    # Enrich vulnerabilities with fixes
    for v in vulns:
        cursor.execute('SELECT * FROM fixes WHERE vuln_id = ?', (v['id'],))
        v['fixes'] = [dict(f) for f in cursor.fetchall()]
    
    job['structured_vulnerabilities'] = vulns
    
    # Enrich with structured exploits
    cursor.execute('SELECT * FROM exploits WHERE job_id = ?', (job_id,))
    job['structured_exploits'] = [dict(e) for e in cursor.fetchall()]
    
    # Enrich with AI activities
    cursor.execute('SELECT * FROM ai_activities WHERE job_id = ? ORDER BY timestamp DESC', (job_id,))
    job['ai_activities'] = [dict(a) for a in cursor.fetchall()]
    for a in job['ai_activities']:
        a['parameters'] = json.loads(a['parameters'])
    
    conn.close()
    return job

def get_all_jobs(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT j.*, 
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.job_id = j.id) as vuln_count,
               (SELECT COUNT(*) FROM exploits e WHERE e.job_id = j.id) as exploit_count
        FROM jobs j 
        ORDER BY start_time DESC LIMIT ? OFFSET ?
    ''', (limit, offset))
    rows = cursor.fetchall()
    
    jobs = []
    for row in rows:
        job = dict(row)
        try:
            job['findings'] = json.loads(job['findings'])
            job['logs'] = json.loads(job['logs'])
            job['metrics'] = json.loads(job['metrics'])
        except:
            job['findings'] = []
            job['logs'] = []
            job['metrics'] = {}
        
        # NEW: Fetch structured vulnerabilities for the list view to populate Global Vault
        cursor.execute('SELECT * FROM vulnerabilities WHERE job_id = ?', (job['id'],))
        job['structured_vulnerabilities'] = [dict(v) for v in cursor.fetchall()]
        
        jobs.append(job)
        
    conn.close()
    return jobs

def get_ai_activities(job_id: Optional[str] = None, activity_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = 'SELECT * FROM ai_activities'
    params = []
    
    conditions = []
    if job_id:
        conditions.append('job_id = ?')
        params.append(job_id)
    if activity_type:
        conditions.append('activity_type = ?')
        params.append(activity_type)
        
    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
        
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    activities = []
    for row in rows:
        activity = dict(row)
        activity['parameters'] = json.loads(activity['parameters'])
        activities.append(activity)
        
    conn.close()
    return activities

# Initialize on import
init_db()
