import sqlite3
from typing import Dict, Any, List
import json

class AgentMemory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        """Creates the necessary database tables if they don't exist."""
        with self.conn:
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                analysis_data TEXT
            )
            """)
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS detected_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_info TEXT
            )
            """)

    def log_analysis(self, analysis_data: Dict[str, Any]):
        """Logs a new analysis result to the database."""
        with self.conn:
            self.conn.execute(
                "INSERT INTO analysis_log (analysis_data) VALUES (?)",
                (json.dumps(analysis_data),)
            )

    def log_threat(self, threat_info: str):
        """Logs a new threat to the database."""
        with self.conn:
            self.conn.execute(
                "INSERT INTO detected_threats (threat_info) VALUES (?)",
                (threat_info,)
            )

    def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves the most recent analysis results."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT analysis_data FROM analysis_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [json.loads(row[0]) for row in rows]

    def get_recent_threats(self, limit: int = 10) -> List[str]:
        """Retrieves the most recent detected threats."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT threat_info FROM detected_threats ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [row[0] for row in rows]
