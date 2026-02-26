"""
Database module for storing network flows.
Uses SQLite for persistent storage with pagination support.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import threading

# Thread-safe database operations
db_lock = threading.Lock()

# Database path
DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "flows.db"

# Protocol filter: DB may store number ("6") or name ("TCP") from different sources. Match both.
PROTOCOL_FILTER_VALUES = {
    "TCP": ("6", "TCP"),
    "UDP": ("17", "UDP"),
    "ICMP": ("1", "ICMP"),
    "GRE": ("47", "GRE"),
    "ESP": ("50", "ESP"),
    "AH": ("51", "AH"),
    "OSPF": ("89", "OSPF"),
    "SCTP": ("132", "SCTP"),
}


def init_db():
    """Initialize database schema."""
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id TEXT PRIMARY KEY,
                analysis_id TEXT,
                upload_filename TEXT,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                duration REAL,
                total_fwd_packets INTEGER,
                total_bwd_packets INTEGER,
                total_length_fwd INTEGER,
                total_length_bwd INTEGER,
                flow_bytes_per_sec REAL,
                flow_packets_per_sec REAL,
                classification TEXT,
                confidence REAL,
                anomaly_score REAL,
                risk_score REAL,
                risk_level TEXT,
                is_anomaly BOOLEAN,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Backward-compatible schema upgrades for existing DBs.
        cursor.execute("PRAGMA table_info(flows)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        if "analysis_id" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN analysis_id TEXT")
        if "upload_filename" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN upload_filename TEXT")
        if "threat_type" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN threat_type TEXT")
        if "cve_refs" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN cve_refs TEXT")
        if "classification_reason" not in existing_columns:
            cursor.execute("ALTER TABLE flows ADD COLUMN classification_reason TEXT")

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp DESC);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_classification ON flows(classification);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_risk_level ON flows(risk_level);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analysis_id ON flows(analysis_id);
        """)
        
        conn.commit()
        conn.close()


def insert_flows(flows: List[Dict[str, Any]]) -> int:
    """Insert flows into database. Returns count of inserted flows."""
    if not flows:
        return 0
    
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        inserted = 0
        for flow in flows:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO flows (
                        id, analysis_id, upload_filename, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                        duration, total_fwd_packets, total_bwd_packets, total_length_fwd,
                        total_length_bwd, flow_bytes_per_sec, flow_packets_per_sec,
                        classification, threat_type, cve_refs, classification_reason,
                        confidence, anomaly_score, risk_score, risk_level, is_anomaly
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow.get('id'),
                    flow.get('analysis_id'),
                    flow.get('upload_filename'),
                    flow.get('timestamp'),
                    flow.get('src_ip'),
                    flow.get('dst_ip'),
                    flow.get('src_port'),
                    flow.get('dst_port'),
                    flow.get('protocol'),
                    flow.get('duration'),
                    flow.get('total_fwd_packets'),
                    flow.get('total_bwd_packets'),
                    flow.get('total_length_fwd'),
                    flow.get('total_length_bwd'),
                    flow.get('flow_bytes_per_sec'),
                    flow.get('flow_packets_per_sec'),
                    flow.get('classification'),
                    flow.get('threat_type') or '',
                    flow.get('cve_refs') or '',
                    flow.get('classification_reason') or '',
                    flow.get('confidence'),
                    flow.get('anomaly_score'),
                    flow.get('risk_score'),
                    flow.get('risk_level'),
                    flow.get('is_anomaly', False),
                ))
                inserted += 1
            except Exception as e:
                print(f"Error inserting flow {flow.get('id')}: {e}")
                continue
        
        conn.commit()
        conn.close()
        return inserted


def get_flows(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    threat_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    analysis_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Get paginated flows with optional filters. Returns (flows, total_count)."""
    
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Build WHERE clause
        where_clauses = []
        params = []
        
        if classification:
            where_clauses.append("LOWER(COALESCE(classification, '')) = LOWER(?)")
            params.append(classification.strip())
        if risk_level:
            where_clauses.append("LOWER(COALESCE(risk_level, '')) = LOWER(?)")
            params.append(risk_level.strip())
        if threat_type:
            where_clauses.append("LOWER(COALESCE(threat_type, '')) = LOWER(?)")
            params.append(threat_type.strip())
        if src_ip:
            where_clauses.append("LOWER(COALESCE(src_ip, '')) LIKE LOWER(?)")
            params.append(f"%{src_ip.strip()}%")
        if protocol:
            protocol_clean = protocol.strip()
            if protocol_clean.upper() in PROTOCOL_FILTER_VALUES:
                vals = PROTOCOL_FILTER_VALUES[protocol_clean.upper()]
                placeholders = ", ".join("?" for _ in vals)
                where_clauses.append(f"(COALESCE(protocol, '') IN ({placeholders}))")
                params.extend(vals)
            else:
                where_clauses.append("LOWER(COALESCE(protocol, '')) = LOWER(?)")
                params.append(protocol_clean)
        if analysis_id:
            where_clauses.append("LOWER(COALESCE(analysis_id, '')) = LOWER(?)")
            params.append(analysis_id.strip())
        
        where_sql = " AND ".join(where_clauses)
        where_sql = f"WHERE {where_sql}" if where_sql else ""
        
        # Get total count
        count_query = f"SELECT COUNT(*) as cnt FROM flows {where_sql}"
        cursor.execute(count_query, params)
        total = cursor.fetchone()['cnt']
        
        # Get paginated results
        offset = (page - 1) * per_page
        query = f"""
            SELECT * FROM flows {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query, params + [per_page, offset])
        rows = cursor.fetchall()
        
        flows = [dict(row) for row in rows]
        conn.close()
        
        return flows, total


def get_dashboard_stats() -> Dict[str, Any]:
    """Get aggregated statistics for dashboard."""
    
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get basic stats
        cursor.execute("""
            SELECT 
                COUNT(*) as total_flows,
                SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as total_anomalies,
                AVG(risk_score) as avg_risk_score
            FROM flows
        """)
        stats = dict(cursor.fetchone())
        
        total_flows = stats['total_flows'] or 0
        total_anomalies = stats['total_anomalies'] or 0
        avg_risk_score = stats['avg_risk_score'] or 0.0
        
        # Get attack distribution
        cursor.execute("""
            SELECT classification, COUNT(*) as count
            FROM flows
            GROUP BY classification
        """)
        attack_dist = {row['classification']: row['count'] for row in cursor.fetchall()}
        
        # Get risk distribution
        cursor.execute("""
            SELECT risk_level, COUNT(*) as count
            FROM flows
            GROUP BY risk_level
        """)
        risk_dist_db = {row['risk_level']: row['count'] for row in cursor.fetchall()}
        risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        risk_dist.update(risk_dist_db)
        
        # Get timeline (last 24 hours)
        cursor.execute("""
            SELECT 
                strftime('%H:00', timestamp) as hour,
                COUNT(*) as total,
                SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as anomalies
            FROM flows
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY strftime('%H:00', timestamp)
            ORDER BY hour
        """)
        timeline = [dict(row) for row in cursor.fetchall()]
        
        # Get protocol distribution
        cursor.execute("""
            SELECT protocol, COUNT(*) as count
            FROM flows
            GROUP BY protocol
        """)
        protocols = {row['protocol']: row['count'] for row in cursor.fetchall()}
        
        # Get top IPs
        cursor.execute("""
            SELECT src_ip, COUNT(*) as count
            FROM flows
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
        """)
        top_sources = [{"ip": row['src_ip'], "count": row['count']} for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count
            FROM flows
            WHERE dst_ip IS NOT NULL
            GROUP BY dst_ip
            ORDER BY count DESC
            LIMIT 10
        """)
        top_destinations = [{"ip": row['dst_ip'], "count": row['count']} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "total_flows": total_flows,
            "total_anomalies": total_anomalies,
            "anomaly_rate": round(total_anomalies / max(total_flows, 1) * 100, 1),
            "avg_risk_score": round(avg_risk_score, 3),
            "attack_distribution": attack_dist,
            "risk_distribution": risk_dist,
            "timeline": timeline,
            "protocols": protocols,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
        }


def get_traffic_trends(
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    threat_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    points: int = 72,
) -> Dict[str, Any]:
    """
    Return hourly aggregated trends for traffic analysis charts.
    Uses averages/counts so visualization remains stable for large datasets.
    """
    points = max(12, min(points, 500))

    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        where_clauses = []
        params = []

        if classification:
            where_clauses.append("LOWER(COALESCE(classification, '')) = LOWER(?)")
            params.append(classification.strip())
        if risk_level:
            where_clauses.append("LOWER(COALESCE(risk_level, '')) = LOWER(?)")
            params.append(risk_level.strip())
        if threat_type:
            where_clauses.append("LOWER(COALESCE(threat_type, '')) = LOWER(?)")
            params.append(threat_type.strip())
        if src_ip:
            where_clauses.append("LOWER(COALESCE(src_ip, '')) LIKE LOWER(?)")
            params.append(f"%{src_ip.strip()}%")
        if protocol:
            protocol_clean = protocol.strip()
            if protocol_clean.upper() in PROTOCOL_FILTER_VALUES:
                vals = PROTOCOL_FILTER_VALUES[protocol_clean.upper()]
                placeholders = ", ".join("?" for _ in vals)
                where_clauses.append(f"(COALESCE(protocol, '') IN ({placeholders}))")
                params.extend(vals)
            else:
                where_clauses.append("LOWER(COALESCE(protocol, '')) = LOWER(?)")
                params.append(protocol_clean)

        where_sql = " AND ".join(where_clauses)
        where_sql = f"WHERE {where_sql}" if where_sql else ""

        query = f"""
            SELECT
                substr(timestamp, 1, 16) as hour_bucket,
                COUNT(*) as total_flows,
                SUM(CASE WHEN COALESCE(is_anomaly, 0) = 1 THEN 1 ELSE 0 END) as anomaly_flows,
                SUM(CASE WHEN LOWER(COALESCE(classification, '')) != 'benign' THEN 1 ELSE 0 END) as threat_flows,
                AVG(COALESCE(risk_score, 0)) as avg_risk_score,
                AVG(COALESCE(confidence, 0)) as avg_confidence
            FROM flows
            {where_sql}
            GROUP BY hour_bucket
            ORDER BY hour_bucket DESC
            LIMIT ?
        """
        cursor.execute(query, params + [points])
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()

    rows.reverse()

    result_points = []
    for row in rows:
        total = row.get("total_flows", 0) or 0
        anomalies = row.get("anomaly_flows", 0) or 0
        threats = row.get("threat_flows", 0) or 0
        benign = max(0, total - threats)
        result_points.append({
            "hour": row.get("hour_bucket"),
            "total_flows": total,
            "anomaly_flows": anomalies,
            "threat_flows": threats,
            "benign_flows": benign,
            "anomaly_rate": round((anomalies / max(total, 1)) * 100, 2),
            "threat_rate": round((threats / max(total, 1)) * 100, 2),
            "avg_risk_score": float(row.get("avg_risk_score") or 0.0),
            "avg_confidence": float(row.get("avg_confidence") or 0.0),
        })

    return {
        "points": result_points,
        "count": len(result_points),
    }


def delete_old_flows(days: int = 7) -> int:
    """Delete flows older than specified days. Returns deleted count."""
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM flows
            WHERE created_at < datetime('now', '-' || ? || ' days')
        """, (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted


def get_total_flows_count() -> int:
    """Get total number of flows in database."""
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM flows")
        count = cursor.fetchone()[0]
        conn.close()
        return count


def get_anomaly_data(top_n: int = 50) -> Dict[str, Any]:
    """
    Return anomaly-focused data from uploaded flows.
    Treat rows as anomaly if:
    - is_anomaly = 1, OR
    - classification is not BENIGN.
    """
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        where_clause = """
            (COALESCE(is_anomaly, 0) = 1 OR LOWER(COALESCE(classification, '')) != 'benign')
        """

        cursor.execute(f"SELECT COUNT(*) as cnt FROM flows WHERE {where_clause}")
        total_anomalies = cursor.fetchone()["cnt"] or 0

        cursor.execute(f"""
            SELECT
                SUM(CASE WHEN anomaly_score >= 0.9 THEN 1 ELSE 0 END) as r_09_10,
                SUM(CASE WHEN anomaly_score >= 0.8 AND anomaly_score < 0.9 THEN 1 ELSE 0 END) as r_08_09,
                SUM(CASE WHEN anomaly_score >= 0.7 AND anomaly_score < 0.8 THEN 1 ELSE 0 END) as r_07_08,
                SUM(CASE WHEN anomaly_score >= 0.6 AND anomaly_score < 0.7 THEN 1 ELSE 0 END) as r_06_07,
                SUM(CASE WHEN anomaly_score >= 0.5 AND anomaly_score < 0.6 THEN 1 ELSE 0 END) as r_05_06,
                SUM(CASE WHEN anomaly_score < 0.5 OR anomaly_score IS NULL THEN 1 ELSE 0 END) as r_lt_05
            FROM flows
            WHERE {where_clause}
        """)
        ranges = dict(cursor.fetchone())
        score_distribution = {
            "0.9-1.0": ranges.get("r_09_10", 0) or 0,
            "0.8-0.9": ranges.get("r_08_09", 0) or 0,
            "0.7-0.8": ranges.get("r_07_08", 0) or 0,
            "0.6-0.7": ranges.get("r_06_07", 0) or 0,
            "0.5-0.6": ranges.get("r_05_06", 0) or 0,
            "< 0.5": ranges.get("r_lt_05", 0) or 0,
        }

        cursor.execute(f"""
            SELECT classification, COUNT(*) as count
            FROM flows
            WHERE {where_clause}
            GROUP BY classification
            ORDER BY count DESC
        """)
        attack_breakdown = {
            (row["classification"] if row["classification"] else "Unknown"): row["count"]
            for row in cursor.fetchall()
        }

        cursor.execute(f"""
            SELECT *
            FROM flows
            WHERE {where_clause}
            ORDER BY anomaly_score DESC
            LIMIT ?
        """, (top_n,))
        top_anomalies = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            "total_anomalies": total_anomalies,
            "top_anomalies": top_anomalies,
            "score_distribution": score_distribution,
            "attack_breakdown": attack_breakdown,
        }


def get_threat_data(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return threat data (all attacks/anomalies) with optional filters + pagination.
    Threat condition:
    - is_anomaly = 1, OR
    - classification != BENIGN
    """
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        where_clauses = [
            "(COALESCE(is_anomaly, 0) = 1 OR LOWER(COALESCE(classification, '')) != 'benign')"
        ]
        params = []

        if classification:
            where_clauses.append("LOWER(COALESCE(classification, '')) = LOWER(?)")
            params.append(classification.strip())
        if risk_level:
            where_clauses.append("LOWER(COALESCE(risk_level, '')) = LOWER(?)")
            params.append(risk_level.strip())
        if src_ip:
            where_clauses.append("LOWER(COALESCE(src_ip, '')) LIKE LOWER(?)")
            params.append(f"%{src_ip.strip()}%")
        if protocol:
            where_clauses.append("LOWER(COALESCE(protocol, '')) = LOWER(?)")
            params.append(protocol.strip())

        where_sql = " AND ".join(where_clauses)

        cursor.execute(f"SELECT COUNT(*) as cnt FROM flows WHERE {where_sql}", params)
        total_threats = cursor.fetchone()["cnt"] or 0

        cursor.execute(f"""
            SELECT
                SUM(CASE WHEN anomaly_score >= 0.9 THEN 1 ELSE 0 END) as r_09_10,
                SUM(CASE WHEN anomaly_score >= 0.8 AND anomaly_score < 0.9 THEN 1 ELSE 0 END) as r_08_09,
                SUM(CASE WHEN anomaly_score >= 0.7 AND anomaly_score < 0.8 THEN 1 ELSE 0 END) as r_07_08,
                SUM(CASE WHEN anomaly_score >= 0.6 AND anomaly_score < 0.7 THEN 1 ELSE 0 END) as r_06_07,
                SUM(CASE WHEN anomaly_score >= 0.5 AND anomaly_score < 0.6 THEN 1 ELSE 0 END) as r_05_06,
                SUM(CASE WHEN anomaly_score < 0.5 OR anomaly_score IS NULL THEN 1 ELSE 0 END) as r_lt_05
            FROM flows
            WHERE {where_sql}
        """, params)
        ranges = dict(cursor.fetchone())
        score_distribution = {
            "0.9-1.0": ranges.get("r_09_10", 0) or 0,
            "0.8-0.9": ranges.get("r_08_09", 0) or 0,
            "0.7-0.8": ranges.get("r_07_08", 0) or 0,
            "0.6-0.7": ranges.get("r_06_07", 0) or 0,
            "0.5-0.6": ranges.get("r_05_06", 0) or 0,
            "< 0.5": ranges.get("r_lt_05", 0) or 0,
        }

        cursor.execute(f"""
            SELECT classification, COUNT(*) as count
            FROM flows
            WHERE {where_sql}
            GROUP BY classification
            ORDER BY count DESC
        """, params)
        attack_breakdown = {
            (row["classification"] if row["classification"] else "Unknown"): row["count"]
            for row in cursor.fetchall()
        }

        offset = (page - 1) * per_page
        cursor.execute(f"""
            SELECT *
            FROM flows
            WHERE {where_sql}
            ORDER BY anomaly_score DESC, risk_score DESC
            LIMIT ? OFFSET ?
        """, params + [per_page, offset])
        threats = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            "total_anomalies": total_threats,
            "top_anomalies": threats,
            "score_distribution": score_distribution,
            "attack_breakdown": attack_breakdown,
            "total": total_threats,
            "page": page,
            "per_page": per_page,
            "total_pages": (total_threats + per_page - 1) // per_page,
        }
