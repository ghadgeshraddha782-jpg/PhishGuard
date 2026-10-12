from fastapi import APIRouter

from backend.database import get_connection

router = APIRouter()


@router.get("/dashboard/stats")
def get_dashboard_stats():
    connection = get_connection()
    cursor = connection.cursor()

    # Total analyses
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM analyses
    """)
    total = cursor.fetchone()["total"]

    # High risk / phishing
    cursor.execute("""
        SELECT COUNT(*) AS phishing
        FROM analyses
        WHERE classification = 'HIGH RISK / LIKELY PHISHING'
    """)
    phishing = cursor.fetchone()["phishing"]

    # Suspicious
    cursor.execute("""
        SELECT COUNT(*) AS suspicious
        FROM analyses
        WHERE classification = 'SUSPICIOUS'
    """)
    suspicious = cursor.fetchone()["suspicious"]

    # Low risk
    cursor.execute("""
        SELECT COUNT(*) AS low_risk
        FROM analyses
        WHERE classification = 'LOW RISK'
    """)
    low_risk = cursor.fetchone()["low_risk"]

    # Average risk score
    cursor.execute("""
        SELECT AVG(risk_score) AS average_risk_score
        FROM analyses
    """)
    average_risk_score = cursor.fetchone()["average_risk_score"]

    connection.close()

    return {
        "total_analyses": total,
        "phishing": phishing,
        "suspicious": suspicious,
        "low_risk": low_risk,
        "average_risk_score": round(
            average_risk_score or 0,
            2
        )
    }
@router.get("/dashboard/indicators")
def get_dashboard_indicators():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            indicator_type,
            COUNT(*) AS count
        FROM indicators
        GROUP BY indicator_type
        ORDER BY count DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    indicators = []

    for row in rows:
        indicators.append({
            "indicator_type": row["indicator_type"],
            "count": row["count"]
        })

    return {
        "indicators": indicators
    }
@router.delete("/analyses")
def delete_all_analyses():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM analyses")

    deleted_count = cursor.rowcount

    connection.commit()
    connection.close()

    return {
        "message": "All analyses deleted successfully",
        "deleted_count": deleted_count
    }
@router.get("/dashboard/risky-senders")
def get_risky_senders():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            sender_domain,
            COUNT(*) AS count,
            AVG(risk_score) AS average_risk_score
        FROM analyses
        WHERE risk_score >= 41
        GROUP BY sender_domain
        ORDER BY average_risk_score DESC
        LIMIT 5
    """)

    rows = cursor.fetchall()

    connection.close()

    risky_senders = []

    for row in rows:
        risky_senders.append({
            "sender_domain": row["sender_domain"],
            "count": row["count"],
            "average_risk_score": round(
                row["average_risk_score"] or 0,
                2
            )
        })

    return {
        "risky_senders": risky_senders
    }
@router.get("/dashboard/trend")
def get_dashboard_trend():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            DATE(created_at) AS analysis_date,
            COUNT(*) AS risky_count
        FROM analyses
        WHERE risk_score >= 41
          AND DATE(created_at) >= DATE('now', '-6 days')
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)
    """)

    rows = cursor.fetchall()

    connection.close()

    trend = []

    for row in rows:
        trend.append({
            "date": row["analysis_date"],
            "risky_count": row["risky_count"]
        })

    return {
        "trend": trend
    }