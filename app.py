import sqlite3
from pathlib import Path
import secrets
from urllib.parse import urlparse

from flask import Flask, redirect, render_template, request, session, url_for, send_from_directory
import pymysql
from pymysql.cursors import DictCursor
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
from ai_helper import get_ai_response

app = Flask(__name__)
app.secret_key = "smart-virtual-lab-secret-key"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

BASE_DIR = Path(__file__).resolve().parent
LABS_DIR = BASE_DIR / "lab"
ACCESS_DB = Path(__file__).with_name("access_control.db")
DEFAULT_APPROVERS = [
    {
        "full_name": "مالك المنصة",
        "username": "owner",
        "password": "Owner@12345",
        "is_system_manager": 1,
    },
    {
        "full_name": "المشرف العام",
        "username": "supervisor",
        "password": "Supervisor@12345",
        "is_system_manager": 0,
    },
]


def get_db_connection():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="",
        database="smart_labs_db",
        charset="utf8mb4",
        cursorclass=DictCursor,
    )


def get_access_connection():
    conn = sqlite3.connect(ACCESS_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_access_db():
    conn = get_access_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                activation_code TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                is_approver INTEGER NOT NULL DEFAULT 0,
                is_system_manager INTEGER NOT NULL DEFAULT 0,
                approved_by TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "activation_code" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN activation_code TEXT")
        if "is_system_manager" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_system_manager INTEGER NOT NULL DEFAULT 0")

        for approver in DEFAULT_APPROVERS:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (approver["username"],),
            ).fetchone()
            if existing:
                continue

            conn.execute(
                """
                INSERT INTO users (
                    full_name, username, password_hash, role, activation_code, status,
                    is_approver, is_system_manager, approved_by
                ) VALUES (?, ?, ?, 'approver', ?, 'approved', 1, ?, 'system')
                """,
                (
                    approver["full_name"],
                    approver["username"],
                    generate_password_hash(approver["password"]),
                    "SYSTEM",
                    approver["is_system_manager"],
                ),
            )

        conn.commit()
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = get_access_connection()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()


def list_local_experiment_files():
    if not LABS_DIR.exists():
        return []
    return sorted(
        str(path.relative_to(BASE_DIR)).replace("\\", "/")
        for path in LABS_DIR.rglob("*.html")
        if path.is_file()
    )


def normalize_experiment_target(target: str):
    if not target:
        return None

    cleaned = target.strip().replace("\\", "/")
    parsed = urlparse(cleaned)
    if parsed.scheme or parsed.netloc or cleaned.startswith("//"):
        return None

    relative_path = Path(cleaned)
    if relative_path.is_absolute():
        return None

    resolved_path = (BASE_DIR / relative_path).resolve()
    try:
        resolved_path.relative_to(LABS_DIR.resolve())
    except ValueError:
        return None

    if resolved_path.suffix.lower() != ".html" or not resolved_path.is_file():
        return None

    return str(resolved_path.relative_to(BASE_DIR)).replace("\\", "/")


def generate_activation_code() -> str:
    return f"SVL-{secrets.token_hex(3).upper()}"


def create_access_request(full_name: str, username: str, password: str, role: str):
    activation_code = generate_activation_code()
    conn = get_access_connection()
    try:
        conn.execute(
            """
            INSERT INTO users (
                full_name, username, password_hash, role, activation_code, status, is_approver
            ) VALUES (?, ?, ?, ?, ?, 'pending', 0)
            """,
            (full_name, username, generate_password_hash(password), role, activation_code),
        )
        conn.commit()
        return activation_code
    finally:
        conn.close()


def list_pending_requests():
    conn = get_access_connection()
    try:
        return conn.execute(
            """
            SELECT id, full_name, username, role, created_at
            , activation_code
            FROM users
            WHERE status = 'pending' AND is_approver = 0
            ORDER BY created_at ASC
            """
        ).fetchall()
    finally:
        conn.close()


def list_supervisors():
    conn = get_access_connection()
    try:
        return conn.execute(
            """
            SELECT id, full_name, username, status, is_system_manager, created_at
            FROM users
            WHERE is_approver = 1
            ORDER BY is_system_manager DESC, created_at ASC
            """
        ).fetchall()
    finally:
        conn.close()


def create_supervisor(full_name: str, username: str, password: str, is_system_manager: int):
    conn = get_access_connection()
    try:
        conn.execute(
            """
            INSERT INTO users (
                full_name, username, password_hash, role, activation_code, status,
                is_approver, is_system_manager, approved_by
            ) VALUES (?, ?, ?, 'approver', 'SYSTEM', 'active', 1, ?, 'system')
            """,
            (full_name, username, generate_password_hash(password), is_system_manager),
        )
        conn.commit()
    finally:
        conn.close()


def update_supervisor_role(user_id: int, is_system_manager: int):
    conn = get_access_connection()
    try:
        conn.execute(
            "UPDATE users SET is_system_manager = ? WHERE id = ? AND is_approver = 1",
            (is_system_manager, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def update_request_status(user_id: int, status: str, approver_name: str):
    conn = get_access_connection()
    try:
        conn.execute(
            "UPDATE users SET status = ?, approved_by = ? WHERE id = ?",
            (status, approver_name, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def load_experiments():
    all_data = {}
    subjects_list = {"sci": "العلوم"}
    error_message = None

    subject_names = {
        "sci": "العلوم",
        "phy": "الفيزياء",
        "che": "الكيمياء",
        "bio": "الأحياء",
        "env": "علم البيئة",
    }

    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT title, subject, grade, term, url FROM experiments ORDER BY title ASC")
                rows = cursor.fetchall()
        finally:
            conn.close()
    except Exception as exc:
        rows = []
        error_message = f"تعذر قراءة البيانات من قاعدة البيانات: {exc}"

    for row in rows:
        key = f"{row['grade']}-{row['term']}"
        subject = row["subject"]

        if subject not in all_data:
            all_data[subject] = {}
        if key not in all_data[subject]:
            all_data[subject][key] = {}

        all_data[subject][key][row["title"]] = row["url"]

        if subject not in subjects_list:
            subjects_list[subject] = subject_names.get(subject, subject)

    return all_data, subjects_list, error_message


def get_label_maps():
    return {
        "subjects": {
            "sci": "العلوم",
            "phy": "الفيزياء",
            "che": "الكيمياء",
            "bio": "الأحياء",
            "env": "علم البيئة",
        },
        "grades": {
            "p4": "الرابع",
            "p5": "الخامس",
            "p6": "السادس",
            "m1": "الأول متوسط",
            "m2": "الثاني متوسط",
            "m3": "الثالث متوسط",
            "s1": "الأول ثانوي",
            "s2": "الثاني ثانوي",
            "s3": "الثالث ثانوي",
        },
        "terms": {
            "t1": "الفصل الأول",
            "t2": "الفصل الثاني",
        },
    }


def list_experiments_for_admin():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, subject, grade, term, url
                FROM experiments
                ORDER BY id DESC
                """
            )
            return cursor.fetchall()
    finally:
        conn.close()


def get_experiment_by_id(experiment_id: int):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, subject, grade, term, url
                FROM experiments
                WHERE id = %s
                LIMIT 1
                """,
                (experiment_id,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def insert_experiment(title: str, subject: str, grade: str, term: str, url: str):
    safe_url = normalize_experiment_target(url)
    if not safe_url:
        raise ValueError("رابط التجربة يجب أن يشير إلى ملف HTML موجود داخل مجلد lab.")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO experiments (title, subject, grade, term, url)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (title, subject, grade, term, safe_url),
            )
        conn.commit()
    finally:
        conn.close()


def update_experiment(experiment_id: int, title: str, subject: str, grade: str, term: str, url: str):
    safe_url = normalize_experiment_target(url)
    if not safe_url:
        raise ValueError("رابط التجربة يجب أن يشير إلى ملف HTML موجود داخل مجلد lab.")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE experiments
                SET title = %s, subject = %s, grade = %s, term = %s, url = %s
                WHERE id = %s
                """,
                (title, subject, grade, term, safe_url, experiment_id),
            )
        conn.commit()
    finally:
        conn.close()


def delete_experiment(experiment_id: int):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM experiments WHERE id = %s", (experiment_id,))
        conn.commit()
    finally:
        conn.close()


def init_evaluation_tables():
    """إنشاء جداول نظام التقييم إذا لم تكن موجودة"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # جدول معايير التقييم
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evaluation_criteria (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    description TEXT,
                    category ENUM('student', 'supervisor') NOT NULL,
                    max_score INT DEFAULT 5,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # جدول تقييمات الطلاب
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS student_evaluations (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    student_username VARCHAR(100) NOT NULL,
                    evaluator_username VARCHAR(100) NOT NULL,
                    experiment_id INT,
                    criteria_id INT NOT NULL,
                    score INT NOT NULL,
                    comments TEXT,
                    evaluation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (experiment_id) REFERENCES experiments(id),
                    FOREIGN KEY (criteria_id) REFERENCES evaluation_criteria(id)
                )
            """)

            # جدول تقييمات المشرفين
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS supervisor_evaluations (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    supervisor_username VARCHAR(100) NOT NULL,
                    evaluator_username VARCHAR(100) NOT NULL,
                    criteria_id INT NOT NULL,
                    score INT NOT NULL,
                    comments TEXT,
                    evaluation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (criteria_id) REFERENCES evaluation_criteria(id)
                )
            """)

            # جدول الأنشطة
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS student_activities (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    student_username VARCHAR(100) NOT NULL,
                    activity_type ENUM('experiment_access', 'evaluation_received', 'file_downloaded', 'file_uploaded') NOT NULL,
                    description TEXT NOT NULL,
                    related_id INT,
                    activity_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # جداول نظام الاختبارات الذكية
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(200) NOT NULL,
                    description TEXT,
                    created_by VARCHAR(100) NOT NULL,
                    subject VARCHAR(50),  -- فيزياء، كيمياء، بيولوجيا
                    difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
                    total_questions INT DEFAULT 0,
                    time_limit INT,  -- بالدقائق
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS questions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    test_id INT NOT NULL,
                    question_text TEXT NOT NULL,
                    question_type ENUM('multiple_choice', 'true_false', 'short_answer') DEFAULT 'multiple_choice',
                    correct_answer TEXT,
                    points INT DEFAULT 1,
                    FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS answers (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    question_id INT NOT NULL,
                    answer_text TEXT NOT NULL,
                    is_correct BOOLEAN DEFAULT 0,
                    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS student_test_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    student_username VARCHAR(100) NOT NULL,
                    test_id INT NOT NULL,
                    score DECIMAL(5,2) DEFAULT 0,
                    total_score DECIMAL(5,2) DEFAULT 0,
                    percentage DECIMAL(5,2) DEFAULT 0,
                    time_taken INT,  -- بالدقائق
                    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (test_id) REFERENCES tests(id)
                )
            """)

            # إدراج معايير التقييم الافتراضية
            cursor.execute("SELECT COUNT(*) as count FROM evaluation_criteria")
            if cursor.fetchone()['count'] == 0:
                default_criteria = [
                    # معايير تقييم الطلاب
                    ('الفهم العلمي', 'مدى فهم الطالب للمفاهيم العلمية', 'student', 5),
                    ('المهارات العملية', 'قدرة الطالب على إجراء التجارب بدقة', 'student', 5),
                    ('التحليل والاستنتاج', 'قدرة الطالب على تحليل النتائج واستخراج الاستنتاجات', 'student', 5),
                    ('الانضباط والالتزام', 'مدى التزام الطالب بالتعليمات والإجراءات', 'student', 5),
                    ('الابتكار والإبداع', 'قدرة الطالب على التفكير الإبداعي وحل المشكلات', 'student', 5),

                    # معايير تقييم المشرفين
                    ('الكفاءة التعليمية', 'مدى كفاءة المشرف في شرح المفاهيم', 'supervisor', 5),
                    ('التوجيه والإرشاد', 'قدرة المشرف على توجيه الطلاب ومساعدتهم', 'supervisor', 5),
                    ('التقييم العادل', 'عدالة المشرف في تقييم أداء الطلاب', 'supervisor', 5),
                    ('التواصل الفعال', 'فعالية التواصل مع الطلاب والزملاء', 'supervisor', 5),
                    ('الالتزام بالمعايير', 'مدى التزام المشرف بالمعايير التعليمية', 'supervisor', 5),
                ]

                cursor.executemany("""
                    INSERT INTO evaluation_criteria (name, description, category, max_score)
                    VALUES (%s, %s, %s, %s)
                """, default_criteria)

        conn.commit()
    finally:
        conn.close()


def get_evaluation_criteria(category: str):
    """الحصول على معايير التقييم حسب الفئة"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, name, description, max_score
                FROM evaluation_criteria
                WHERE category = %s
                ORDER BY name
            """, (category,))
            return cursor.fetchall()
    finally:
        conn.close()


def submit_student_evaluation(student_username: str, evaluator_username: str, experiment_id: int, evaluations: list):
    """إرسال تقييم طالب"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            for criteria_id, score, comments in evaluations:
                cursor.execute("""
                    INSERT INTO student_evaluations
                    (student_username, evaluator_username, experiment_id, criteria_id, score, comments)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (student_username, evaluator_username, experiment_id, criteria_id, score, comments))
        conn.commit()

        # تسجيل نشاط تلقي التقييم
        log_student_activity(student_username, 'evaluation_received', f'تلقي تقييم من {evaluator_username}')
    finally:
        conn.close()


def submit_supervisor_evaluation(supervisor_username: str, evaluator_username: str, evaluations: list):
    """إرسال تقييم مشرف"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            for criteria_id, score, comments in evaluations:
                cursor.execute("""
                    INSERT INTO supervisor_evaluations
                    (supervisor_username, evaluator_username, criteria_id, score, comments)
                    VALUES (%s, %s, %s, %s, %s)
                """, (supervisor_username, evaluator_username, criteria_id, score, comments))
        conn.commit()
    finally:
        conn.close()


def get_student_evaluations(student_username: str):
    """الحصول على تقييمات طالب معين"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT se.*, ec.name as criteria_name, ec.max_score,
                       se.evaluator_username as evaluator_name, e.title as experiment_title
                FROM student_evaluations se
                JOIN evaluation_criteria ec ON se.criteria_id = ec.id
                LEFT JOIN experiments e ON se.experiment_id = e.id
                WHERE se.student_username = %s
                ORDER BY se.evaluation_date DESC
            """, (student_username,))
            return cursor.fetchall()
    finally:
        conn.close()


def get_supervisor_evaluations(supervisor_username: str):
    """الحصول على تقييمات مشرف معين"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT se.*, ec.name as criteria_name, ec.max_score,
                       se.evaluator_username as evaluator_name
                FROM supervisor_evaluations se
                JOIN evaluation_criteria ec ON se.criteria_id = ec.id
                WHERE se.supervisor_username = %s
                ORDER BY se.evaluation_date DESC
            """, (supervisor_username,))
            return cursor.fetchall()
    finally:
        conn.close()


def log_student_activity(student_username: str, activity_type: str, description: str, related_id: int = None):
    """تسجيل نشاط الطالب"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO student_activities (student_username, activity_type, description, related_id)
                VALUES (%s, %s, %s, %s)
            """, (student_username, activity_type, description, related_id))
        conn.commit()
    finally:
        conn.close()


def get_student_activities(student_username: str):
    """الحصول على أنشطة الطالب"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT * FROM student_activities
                WHERE student_username = %s
                ORDER BY activity_date DESC
                LIMIT 50
            """, (student_username,))
            return cursor.fetchall()
    finally:
        conn.close()


def get_evaluation_stats():
    """الحصول على إحصائيات التقييمات والحسابات"""
    conn = get_db_connection()
    access_conn = get_access_connection()
    try:
        stats = {
            'student_stats': {},
            'supervisor_stats': {},
            'account_stats': {},
            'top_students': [],
            'top_supervisors': []
        }

        with conn.cursor() as cursor:
            # إحصائيات الطلاب
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT se.student_username) as total_students_evaluated,
                    COUNT(se.id) as total_student_evaluations,
                    AVG(se.score) as avg_student_score
                FROM student_evaluations se
            """)
            student_stats = cursor.fetchone()
            stats['student_stats'] = {
                'total_students_evaluated': student_stats['total_students_evaluated'] or 0,
                'total_student_evaluations': student_stats['total_student_evaluations'] or 0,
                'avg_student_score': float(student_stats['avg_student_score'] or 0)
            }

            # إحصائيات المشرفين
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT se.supervisor_username) as total_supervisors_evaluated,
                    COUNT(se.id) as total_supervisor_evaluations,
                    AVG(se.score) as avg_supervisor_score
                FROM supervisor_evaluations se
            """)
            supervisor_stats = cursor.fetchone()
            stats['supervisor_stats'] = {
                'total_supervisors_evaluated': supervisor_stats['total_supervisors_evaluated'] or 0,
                'total_supervisor_evaluations': supervisor_stats['total_supervisor_evaluations'] or 0,
                'avg_supervisor_score': float(supervisor_stats['avg_supervisor_score'] or 0)
            }

            # إحصائيات الاختبارات
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT t.id) as total_tests,
                    COUNT(DISTINCT str.student_username) as total_students_tested,
                    COUNT(str.id) as total_test_results,
                    AVG(str.percentage) as avg_test_score
                FROM tests t
                LEFT JOIN student_test_results str ON t.id = str.test_id
            """)
            test_stats = cursor.fetchone()
            stats['test_stats'] = {
                'total_tests': test_stats['total_tests'] or 0,
                'total_students_tested': test_stats['total_students_tested'] or 0,
                'total_test_results': test_stats['total_test_results'] or 0,
                'avg_test_score': float(test_stats['avg_test_score'] or 0)
            }

            # أفضل الطلاب - الحصول على أسماء المستخدمين من SQLite
            cursor.execute("""
                SELECT 
                    se.student_username,
                    AVG(se.score) as avg_score,
                    COUNT(se.id) as evaluation_count
                FROM student_evaluations se
                GROUP BY se.student_username
                ORDER BY avg_score DESC
                LIMIT 10
            """)
            top_students_data = cursor.fetchall()

            # الحصول على أسماء المستخدمين
            for student in top_students_data:
                user = access_conn.execute(
                    "SELECT full_name FROM users WHERE username = ?",
                    (student['student_username'],)
                ).fetchone()
                if user:
                    stats['top_students'].append({
                        'full_name': user['full_name'],
                        'avg_score': float(student['avg_score']),
                        'evaluation_count': student['evaluation_count']
                    })

            # أفضل المشرفين
            cursor.execute("""
                SELECT 
                    se.supervisor_username,
                    AVG(se.score) as avg_score,
                    COUNT(se.id) as evaluation_count
                FROM supervisor_evaluations se
                GROUP BY se.supervisor_username
                ORDER BY avg_score DESC
                LIMIT 10
            """)
            top_supervisors_data = cursor.fetchall()

            for supervisor in top_supervisors_data:
                user = access_conn.execute(
                    "SELECT full_name FROM users WHERE username = ?",
                    (supervisor['supervisor_username'],)
                ).fetchone()
                if user:
                    stats['top_supervisors'].append({
                        'full_name': user['full_name'],
                        'avg_score': float(supervisor['avg_score']),
                        'evaluation_count': supervisor['evaluation_count']
                    })

        # إحصائيات الحسابات
        account_stats = access_conn.execute("""
            SELECT 
                COUNT(*) as total_accounts,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_accounts,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_accounts,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_accounts,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_accounts,
                SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END) as total_students,
                SUM(CASE WHEN role = 'visitor' THEN 1 ELSE 0 END) as total_visitors,
                SUM(CASE WHEN is_approver = 1 THEN 1 ELSE 0 END) as total_supervisors
            FROM users
        """).fetchone()

        stats['account_stats'] = {
            'total_accounts': account_stats['total_accounts'] or 0,
            'active_accounts': account_stats['active_accounts'] or 0,
            'pending_accounts': account_stats['pending_accounts'] or 0,
            'approved_accounts': account_stats['approved_accounts'] or 0,
            'rejected_accounts': account_stats['rejected_accounts'] or 0,
            'total_students': account_stats['total_students'] or 0,
            'total_visitors': account_stats['total_visitors'] or 0,
            'total_supervisors': account_stats['total_supervisors'] or 0
        }

        return stats
    finally:
        conn.close()
        access_conn.close()


def get_student_files(student_username: str):
    """الحصول على الملفات المرفوعة للطالب"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, filename, original_filename, uploaded_by, upload_date
                FROM student_files
                WHERE student_username = %s
                ORDER BY upload_date DESC
            """, (student_username,))
            return cursor.fetchall()
    finally:
        conn.close()


def upload_student_file(filename: str, original_filename: str, uploaded_by: str, student_username: str, file_path: str):
    """رفع ملف للطالب"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO student_files (filename, original_filename, uploaded_by, student_username, file_path)
                VALUES (%s, %s, %s, %s, %s)
            """, (filename, original_filename, uploaded_by, student_username, file_path))
        conn.commit()

        # تسجيل نشاط رفع الملف للطالب
        log_student_activity(student_username, 'file_uploaded', f'رفع ملف من {uploaded_by}: {original_filename}')
    finally:
        conn.close()


@app.route("/")
def home():
    all_data, subjects_list, error_message = load_experiments()
    return render_template(
        "index.html",
        all_data=all_data,
        subjects_list=subjects_list,
        error_message=error_message,
        current_user=session.get("user_name"),
        user_role=session.get("user_role"),
        is_approver=session.get("is_approver", False),
        is_system_manager=session.get("is_system_manager", False),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error_message = None
    notice_message = "الحسابات الجديدة تحتاج موافقة المالك أو المشرف قبل تسجيل الدخول."

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = (request.form.get("next") or "").strip()

        user = get_user_by_username(username)

        if not user or not check_password_hash(user["password_hash"], password):
            error_message = "بيانات الدخول غير صحيحة."
        elif user["status"] == "pending":
            error_message = "حسابك ما زال بانتظار موافقة المالك أو المشرف."
        elif user["status"] == "approved" and not user["is_approver"]:
            error_message = "تمت الموافقة على الحساب، لكن يجب إدخال رمز التفعيل أولاً لإكمال التفعيل."
        elif user["status"] == "rejected":
            error_message = "تم رفض طلب الحساب. راجع المشرف."
        else:
            session["user_name"] = user["full_name"]
            session["user_role"] = user["role"]
            session["is_approver"] = bool(user["is_approver"])
            session["is_system_manager"] = bool(user["is_system_manager"])
            session["username"] = user["username"]

            if next_url:
                return redirect(next_url)
            return redirect(url_for("home"))

    return render_template(
        "login.html",
        error_message=error_message,
        notice_message=notice_message,
        next_url=request.args.get("next", ""),
    )


@app.route("/request-access", methods=["GET", "POST"])
def request_access():
    error_message = None
    success_message = None
    activation_code = None

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "").strip()

        existing = get_user_by_username(username) if username else None

        if not full_name or not username or not password:
            error_message = "يرجى تعبئة جميع الحقول المطلوبة."
        elif role not in {"student", "visitor"}:
            error_message = "يرجى اختيار نوع الحساب."
        elif len(password) < 6:
            error_message = "كلمة المرور يجب أن تكون 6 أحرف على الأقل."
        elif existing:
            if existing["status"] == "pending":
                error_message = "يوجد طلب سابق بهذا الاسم المستخدم وما زال بانتظار الموافقة."
            elif existing["status"] == "approved":
                error_message = "تمت الموافقة على الحساب سابقًا وهو بانتظار إدخال رمز التفعيل."
            elif existing["status"] == "active":
                error_message = "هذا الحساب مفعل بالفعل."
            else:
                error_message = "اسم المستخدم مستخدم بالفعل."
        else:
            activation_code = create_access_request(full_name, username, password, role)
            success_message = "تم إرسال الطلب بنجاح. احتفظ برمز التفعيل وشاركَه مع المالك أو المشرف لاعتماد الحساب."

    return render_template(
        "request_access.html",
        error_message=error_message,
        success_message=success_message,
        activation_code=activation_code,
    )


@app.route("/approvals", methods=["GET", "POST"])
def approvals():
    if not session.get("is_approver"):
        return redirect(url_for("login", next=url_for("approvals")))

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        user_id = int(request.form.get("user_id") or 0)
        if action in {"approved", "rejected"} and user_id > 0:
            update_request_status(user_id, action, session.get("username", "approver"))
        return redirect(url_for("approvals"))

    return render_template(
        "approvals.html",
        pending_requests=list_pending_requests(),
        current_user=session.get("user_name"),
    )


@app.route("/activate-account", methods=["GET", "POST"])
def activate_account():
    error_message = None
    success_message = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        activation_code = (request.form.get("activation_code") or "").strip().upper()

        user = get_user_by_username(username) if username else None

        if not username or not activation_code:
            error_message = "يرجى إدخال اسم المستخدم ورمز التفعيل."
        elif not user:
            error_message = "لا يوجد حساب بهذا الاسم."
        elif user["is_approver"]:
            error_message = "حسابات المشرفين لا تحتاج صفحة التفعيل."
        elif user["status"] == "pending":
            error_message = "هذا الحساب ما زال بانتظار موافقة المالك أو المشرف."
        elif user["status"] == "rejected":
            error_message = "تم رفض هذا الحساب ولا يمكن تفعيله."
        elif user["status"] == "active":
            success_message = "هذا الحساب مفعل بالفعل. يمكنك تسجيل الدخول مباشرة."
        elif user["activation_code"] != activation_code:
            error_message = "رمز التفعيل غير صحيح."
        else:
            update_request_status(user["id"], "active", user["approved_by"] or "activation")
            success_message = "تم تفعيل الحساب بنجاح. يمكنك الآن تسجيل الدخول."

    return render_template(
        "activate_account.html",
        error_message=error_message,
        success_message=success_message,
    )


@app.route("/admin/experiments", methods=["GET", "POST"])
def admin_experiments():
    if not session.get("is_approver"):
        return redirect(url_for("login", next=url_for("admin_experiments")))

    error_message = None
    success_message = None
    edit_experiment = None

    edit_id = int(request.args.get("edit") or 0)
    if edit_id > 0:
        try:
            edit_experiment = get_experiment_by_id(edit_id)
            if not edit_experiment:
                error_message = "التجربة المطلوبة للتعديل غير موجودة."
        except Exception as exc:
            error_message = f"تعذر تحميل بيانات التجربة: {exc}"

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()

        try:
            if action == "add":
                title = (request.form.get("title") or "").strip()
                subject = (request.form.get("subject") or "").strip()
                grade = (request.form.get("grade") or "").strip()
                term = (request.form.get("term") or "").strip()
                url = (request.form.get("url") or "").strip()

                if not all([title, subject, grade, term, url]):
                    error_message = "يرجى تعبئة جميع بيانات التجربة."
                else:
                    insert_experiment(title, subject, grade, term, url)
                    success_message = "تمت إضافة التجربة بنجاح."
            elif action == "update":
                experiment_id = int(request.form.get("experiment_id") or 0)
                title = (request.form.get("title") or "").strip()
                subject = (request.form.get("subject") or "").strip()
                grade = (request.form.get("grade") or "").strip()
                term = (request.form.get("term") or "").strip()
                url = (request.form.get("url") or "").strip()

                if experiment_id <= 0 or not all([title, subject, grade, term, url]):
                    error_message = "يرجى تعبئة جميع بيانات التجربة قبل التعديل."
                else:
                    update_experiment(experiment_id, title, subject, grade, term, url)
                    success_message = "تم تعديل التجربة بنجاح."
                    edit_experiment = None

            elif action == "delete":
                experiment_id = int(request.form.get("experiment_id") or 0)
                if experiment_id > 0:
                    delete_experiment(experiment_id)
                    success_message = "تم حذف التجربة بنجاح."
                else:
                    error_message = "معرف التجربة غير صالح."
        except Exception as exc:
            error_message = f"تعذر تنفيذ العملية: {exc}"

    experiments = []
    try:
        experiments = list_experiments_for_admin()
    except Exception as exc:
        error_message = f"تعذر تحميل قائمة التجارب: {exc}"

    return render_template(
        "admin_experiments.html",
        current_user=session.get("user_name"),
        experiments=experiments,
        error_message=error_message,
        success_message=success_message,
        edit_experiment=edit_experiment,
        label_maps=get_label_maps(),
        local_experiment_files=list_local_experiment_files(),
    )


@app.route("/admin/supervisors", methods=["GET", "POST"])
def admin_supervisors():
    if not session.get("is_system_manager"):
        return redirect(url_for("home"))

    error_message = None
    success_message = None

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        try:
            if action == "add":
                full_name = (request.form.get("full_name") or "").strip()
                username = (request.form.get("username") or "").strip().lower()
                password = request.form.get("password") or ""
                is_system_manager = 1 if request.form.get("is_system_manager") == "1" else 0

                if not full_name or not username or not password:
                    error_message = "يرجى تعبئة جميع بيانات المشرف."
                elif len(password) < 6:
                    error_message = "كلمة المرور يجب أن تكون 6 أحرف على الأقل."
                elif get_user_by_username(username):
                    error_message = "اسم المستخدم مستخدم بالفعل."
                else:
                    create_supervisor(full_name, username, password, is_system_manager)
                    success_message = "تمت إضافة حساب المشرف بنجاح."

            elif action == "toggle_role":
                user_id = int(request.form.get("user_id") or 0)
                is_system_manager = 1 if request.form.get("is_system_manager") == "1" else 0
                if user_id > 0:
                    update_supervisor_role(user_id, is_system_manager)
                    success_message = "تم تحديث صلاحية المشرف بنجاح."
        except Exception as exc:
            error_message = f"تعذر تنفيذ العملية: {exc}"

    return render_template(
        "admin_supervisors.html",
        current_user=session.get("user_name"),
        supervisors=list_supervisors(),
        error_message=error_message,
        success_message=success_message,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


def is_safe_target(target: str) -> bool:
    return normalize_experiment_target(target) is not None


@app.route("/launch")
def launch():
    target = (request.args.get("target") or "").strip()

    if "user_name" not in session:
        return redirect(url_for("login", next=url_for("launch", target=target)))

    safe_target = normalize_experiment_target(target)
    if not safe_target:
        return redirect(url_for("home"))

    # تسجيل نشاط دخول التجربة
    username = session.get("username")
    if username and not session.get("is_approver"):
        # استخراج اسم التجربة من الرابط
        experiment_name = target.split('/')[-1].replace('.html', '') if target else 'تجربة غير محددة'
        log_student_activity(username, 'experiment_access', f'دخول التجربة: {experiment_name}')

    return redirect(safe_target)


@app.route("/ai-chat", methods=["GET", "POST"])
def ai_chat():
    if "user_name" not in session:
        return redirect(url_for("login", next=url_for("ai_chat")))

    response = None
    error_message = None

    if request.method == "POST":
        message = (request.form.get("message") or "").strip()
        if message:
            try:
                context = "أنت مساعد تعليمي في المعمل الافتراضي للعلوم. ساعد الطلاب في فهم المفاهيم العلمية وتصحيح الأخطاء في التجارب."
                response = get_ai_response(message, context)
            except Exception as e:
                error_message = f"خطأ في الاتصال بالذكاء الاصطناعي: {str(e)}"
        else:
            error_message = "يرجى إدخال رسالة."

    return render_template(
        "chat.html",
        current_user=session.get("user_name"),
        response=response,
        error_message=error_message,
    )


init_access_db()


@app.route("/evaluate-student/<int:student_id>", methods=["GET", "POST"])
def evaluate_student(student_id: int):
    if not session.get("is_approver"):
        return redirect(url_for("login", next=url_for("evaluate_student", student_id=student_id)))

    # الحصول على بيانات الطالب
    conn = get_access_connection()
    try:
        student = conn.execute(
            "SELECT * FROM users WHERE id = ? AND role = 'student'",
            (student_id,),
        ).fetchone()
    finally:
        conn.close()

    if not student:
        return "الطالب غير موجود", 404

    criteria = get_evaluation_criteria('student')
    experiments = list_experiments_for_admin()

    if request.method == "POST":
        try:
            experiment_id = int(request.form.get("experiment_id") or 0)
            evaluations = []

            for criterion in criteria:
                score = int(request.form.get(f"score_{criterion['id']}") or 0)
                comments = (request.form.get(f"comments_{criterion['id']}") or "").strip()

                if 1 <= score <= criterion['max_score']:
                    evaluations.append((criterion['id'], score, comments))

            if evaluations:
                submit_student_evaluation(student["username"], session.get("username"), experiment_id or None, evaluations)
                success_message = "تم إرسال التقييم بنجاح"
            else:
                error_message = "يرجى إدخال تقييمات صحيحة"

        except Exception as e:
            error_message = f"خطأ في حفظ التقييم: {str(e)}"

    return render_template(
        "student_evaluation.html",
        current_user=session.get("user_name"),
        student=student,
        criteria=criteria,
        experiments=experiments,
        success_message=success_message if 'success_message' in locals() else None,
        error_message=error_message if 'error_message' in locals() else None,
    )


@app.route("/evaluate-supervisor/<int:supervisor_id>", methods=["GET", "POST"])
def evaluate_supervisor(supervisor_id: int):
    if "user_name" not in session:
        return redirect(url_for("login", next=url_for("evaluate_supervisor", supervisor_id=supervisor_id)))

    # الحصول على بيانات المشرف
    conn = get_access_connection()
    try:
        supervisor = conn.execute(
            "SELECT * FROM users WHERE id = ? AND is_approver = 1",
            (supervisor_id,),
        ).fetchone()
    finally:
        conn.close()

    if not supervisor:
        return "المشرف غير موجود", 404

    criteria = get_evaluation_criteria('supervisor')

    if request.method == "POST":
        try:
            evaluations = []

            for criterion in criteria:
                score = int(request.form.get(f"score_{criterion['id']}") or 0)
                comments = (request.form.get(f"comments_{criterion['id']}") or "").strip()

                if 1 <= score <= criterion['max_score']:
                    evaluations.append((criterion['id'], score, comments))

            if evaluations:
                submit_supervisor_evaluation(supervisor["username"], session.get("username"), evaluations)
                success_message = "تم إرسال التقييم بنجاح"
            else:
                error_message = "يرجى إدخال تقييمات صحيحة"

        except Exception as e:
            error_message = f"خطأ في حفظ التقييم: {str(e)}"

    return render_template(
        "supervisor_evaluation.html",
        current_user=session.get("user_name"),
        supervisor=supervisor,
        criteria=criteria,
        success_message=success_message if 'success_message' in locals() else None,
        error_message=error_message if 'error_message' in locals() else None,
    )


@app.route("/evaluation-reports")
def evaluation_reports():
    if not session.get("is_approver"):
        return redirect(url_for("login", next=url_for("evaluation_reports")))

    stats = get_evaluation_stats()

    # الحصول على قائمة الطلاب
    conn = get_access_connection()
    try:
        students = conn.execute(
            "SELECT id, full_name FROM users WHERE role = 'student' AND status = 'active' ORDER BY full_name"
        ).fetchall()
    finally:
        conn.close()

    # الحصول على قائمة المشرفين
    supervisors = list_supervisors()

    return render_template(
        "evaluation_reports.html",
        current_user=session.get("user_name"),
        stats=stats,
        students=students,
        supervisors=supervisors,
    )


@app.route("/my-evaluations")
def my_evaluations():
    if "user_name" not in session:
        return redirect(url_for("login", next=url_for("my_evaluations")))

    # الحصول على معرف المستخدم الحالي
    conn = get_access_connection()
    try:
        user = conn.execute(
            "SELECT id, is_approver FROM users WHERE username = ?",
            (session.get("username"),),
        ).fetchone()
    finally:
        conn.close()

    if not user:
        return redirect(url_for("home"))

    username = session.get("username")
    is_approver = user["is_approver"]

    if is_approver:
        # عرض تقييمات المشرف
        evaluations = get_supervisor_evaluations(username)
        evaluation_type = "supervisor"
        activities = []
    else:
        # عرض تقييمات الطالب
        evaluations = get_student_evaluations(username)
        evaluation_type = "student"
        activities = get_student_activities(username)

    # الحصول على نتائج الاختبارات
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT str.*, t.title, t.subject
                FROM student_test_results str
                JOIN tests t ON str.test_id = t.id
                WHERE str.student_username = %s
                ORDER BY str.completed_at DESC
            """, (username,))
            test_results = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        "my_evaluations.html",
        current_user=session.get("user_name"),
        evaluations=evaluations,
        evaluation_type=evaluation_type,
        activities=activities,
        test_results=test_results,
    )


@app.route("/tests")
def tests():
    """عرض قائمة الاختبارات المتاحة للطلاب"""
    if "user_name" not in session:
        return redirect(url_for("login", next=url_for("tests")))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT t.*, 
                       COALESCE(str.percentage, 0) as best_score,
                       CASE WHEN str.id IS NOT NULL THEN 1 ELSE 0 END as completed
                FROM tests t
                LEFT JOIN student_test_results str ON t.id = str.test_id 
                    AND str.student_username = %s
                    AND str.percentage = (
                        SELECT MAX(percentage) FROM student_test_results 
                        WHERE test_id = t.id AND student_username = %s
                    )
                WHERE t.is_active = 1
                ORDER BY t.created_at DESC
            """, (session.get("username"), session.get("username")))
            tests_list = cursor.fetchall()
    finally:
        conn.close()

    return render_template("tests.html", tests=tests_list)


@app.route("/create-test", methods=["GET", "POST"])
def create_test():
    """إنشاء اختبار جديد (للمشرفين فقط)"""
    if "user_name" not in session or not session.get("is_approver"):
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        subject = request.form.get("subject")
        difficulty = request.form.get("difficulty")
        time_limit = request.form.get("time_limit")

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO tests (title, description, created_by, subject, difficulty, time_limit)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (title, description, session.get("username"), subject, difficulty, time_limit))
                test_id = cursor.lastrowid

                # إضافة الأسئلة
                questions = request.form.getlist("questions[]")
                question_types = request.form.getlist("question_types[]")
                correct_answers = request.form.getlist("correct_answers[]")
                points = request.form.getlist("points[]")

                for i, question in enumerate(questions):
                    cursor.execute("""
                        INSERT INTO questions (test_id, question_text, question_type, correct_answer, points)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (test_id, question, question_types[i], correct_answers[i], points[i]))

                    question_id = cursor.lastrowid

                    # إضافة الخيارات للأسئلة متعددة الخيارات
                    if question_types[i] == "multiple_choice":
                        options = request.form.getlist(f"options_{i}[]")
                        for option in options:
                            is_correct = 1 if option == correct_answers[i] else 0
                            cursor.execute("""
                                INSERT INTO answers (question_id, answer_text, is_correct)
                                VALUES (%s, %s, %s)
                            """, (question_id, option, is_correct))

                # تحديث عدد الأسئلة
                cursor.execute("UPDATE tests SET total_questions = %s WHERE id = %s", (len(questions), test_id))

            conn.commit()
            flash("تم إنشاء الاختبار بنجاح!", "success")
            return redirect(url_for("admin_experiments"))
        finally:
            conn.close()

    return render_template("create_test.html")


@app.route("/take-test/<int:test_id>")
def take_test(test_id):
    """أخذ الاختبار"""
    if "user_name" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # التحقق من وجود الاختبار
            cursor.execute("SELECT * FROM tests WHERE id = %s AND is_active = 1", (test_id,))
            test = cursor.fetchone()
            if not test:
                flash("الاختبار غير موجود أو غير متاح", "error")
                return redirect(url_for("tests"))

            # التحقق من إذا كان الطالب قد أكمل الاختبار من قبل
            cursor.execute("""
                SELECT id FROM student_test_results 
                WHERE test_id = %s AND student_username = %s
            """, (test_id, session.get("username")))
            if cursor.fetchone():
                flash("لقد أكملت هذا الاختبار من قبل", "info")
                return redirect(url_for("tests"))

            # الحصول على الأسئلة والخيارات
            cursor.execute("""
                SELECT q.*, GROUP_CONCAT(a.answer_text ORDER BY a.id) as options
                FROM questions q
                LEFT JOIN answers a ON q.id = a.question_id
                WHERE q.test_id = %s
                GROUP BY q.id
                ORDER BY q.id
            """, (test_id,))
            questions = cursor.fetchall()

            # تحويل options إلى قائمة
            for q in questions:
                if q['options']:
                    q['options'] = q['options'].split(',')
                else:
                    q['options'] = []

    finally:
        conn.close()

    return render_template("take_test.html", test=test, questions=questions)


@app.route("/submit-test", methods=["POST"])
def submit_test():
    """تقديم الاختبار وحساب الدرجة"""
    if "user_name" not in session:
        return redirect(url_for("login"))

    test_id = request.form.get("test_id")
    answers = request.form

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # الحصول على الأسئلة والإجابات الصحيحة
            cursor.execute("SELECT * FROM questions WHERE test_id = %s", (test_id,))
            questions = cursor.fetchall()

            total_score = 0
            max_score = 0

            for question in questions:
                max_score += question['points']
                student_answer = answers.get(f"answer_{question['id']}")
                
                if student_answer and student_answer.strip().lower() == question['correct_answer'].strip().lower():
                    total_score += question['points']

            percentage = (total_score / max_score * 100) if max_score > 0 else 0

            # حفظ النتيجة
            cursor.execute("""
                INSERT INTO student_test_results (student_username, test_id, score, total_score, percentage)
                VALUES (%s, %s, %s, %s, %s)
            """, (session.get("username"), test_id, total_score, max_score, percentage))

        conn.commit()
        flash(f"تم إكمال الاختبار! درجتك: {percentage:.1f}%", "success")
    finally:
        conn.close()

    return redirect(url_for("tests"))


@app.route("/student-dashboard")
def student_dashboard():
    if "user_name" not in session:
        return redirect(url_for("login", next=url_for("student_dashboard")))

    # الحصول على معرف المستخدم الحالي
    conn = get_access_connection()
    try:
        user = conn.execute(
            "SELECT id, is_approver FROM users WHERE username = ?",
            (session.get("username"),),
        ).fetchone()
    finally:
        conn.close()

    if not user:
        return redirect(url_for("home"))

    username = session.get("username")
    is_approver = user["is_approver"]

    # الحصول على البيانات
    all_data, subjects_list, error_message = load_experiments()
    evaluations = get_student_evaluations(username)
    files = get_student_files(username)
    activities = get_student_activities(username)

    return render_template(
        "student_dashboard.html",
        current_user=session.get("user_name"),
        all_data=all_data,
        subjects_list=subjects_list,
        evaluations=evaluations,
        files=files,
        activities=activities,
        error_message=error_message,
        is_approver=is_approver,  # تمرير حالة المشرف للـ template
    )


@app.route("/upload-files", methods=["GET", "POST"])
def upload_files():
    if not session.get("is_approver"):
        return redirect(url_for("login", next=url_for("upload_files")))

    error_message = None
    success_message = None

    if request.method == "POST":
        student_username = (request.form.get("student_username") or "").strip()
        if 'file' not in request.files:
            error_message = "لم يتم اختيار ملف."
        else:
            file = request.files['file']
            if file.filename == '':
                error_message = "لم يتم اختيار ملف."
            elif not student_username:
                error_message = "يرجى تحديد اسم الطالب."
            else:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                upload_student_file(filename, file.filename, session.get("username"), student_username, file_path)
                success_message = "تم رفع الملف بنجاح."

    # قائمة الطلاب
    conn = get_access_connection()
    try:
        students = conn.execute(
            "SELECT username, full_name FROM users WHERE is_approver = 0 ORDER BY full_name"
        ).fetchall()
    finally:
        conn.close()

    return render_template(
        "upload_files.html",
        current_user=session.get("user_name"),
        students=students,
        error_message=error_message,
        success_message=success_message,
    )


@app.route("/download/<int:file_id>")
def download_file(file_id):
    if "user_name" not in session:
        return redirect(url_for("login", next=url_for("download_file", file_id=file_id)))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT filename, student_username FROM student_files WHERE id = %s
            """, (file_id,))
            file_data = cursor.fetchone()
    finally:
        conn.close()

    if not file_data or file_data['student_username'] != session.get("username"):
        return "غير مصرح لك", 403

    # تسجيل نشاط تحميل الملف
    log_student_activity(session.get("username"), 'file_downloaded', f'تحميل الملف: {file_data["filename"]}')

    return send_from_directory(app.config['UPLOAD_FOLDER'], file_data['filename'], as_attachment=True)


# تهيئة جداول نظام التقييم
init_evaluation_tables()


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
