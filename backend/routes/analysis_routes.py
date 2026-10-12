from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timezone
from backend.auth_routes import get_current_user
from backend.auth_routes import require_admin
from backend.auth_routes import require_user
class ReviewCaseRequest(BaseModel):
    analysis_id: int
    reported_by: str

class ReviewDecisionRequest(BaseModel):
    status: str
    admin_notes: str = ""
    reviewed_by: str



from backend.services.email_analyzer import analyze_email
from backend.database import get_connection
from backend.services.url_analyzer import analyze_url


router = APIRouter()


# -------------------------------------------------
# REQUEST MODEL
# -------------------------------------------------

class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str
    urls: list[str] = []
    attachment_name: str = ""
class URLRequest(BaseModel):
    url: str


# -------------------------------------------------
# SAVE ANALYSIS TO DATABASE
# -------------------------------------------------

def save_analysis(result, sender, subject, user_id):
    """
    Save safe analysis metadata and detected indicators
    into the SQLite database.
    """

    connection = get_connection()
    cursor = connection.cursor()

    # ---------------------------------------------
    # 1. Extract sender domain
    # ---------------------------------------------

    sender_domain = ""

    if "@" in sender:
        sender_domain = sender.split("@")[-1].strip().lower()

    # ---------------------------------------------
    # 2. Extract risk information
    # ---------------------------------------------

    risk_analysis = result.get("risk_analysis", {})

    risk_score = int(
        risk_analysis.get("risk_score", 0)
    )

    classification = risk_analysis.get(
        "classification",
        "UNKNOWN"
    )

    # ---------------------------------------------
    # 3. Current timestamp
    # ---------------------------------------------

    created_at = datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------
    # 4. Save analysis
    # ---------------------------------------------

    
    cursor.execute(
    """
    INSERT INTO analyses (
        user_id,
        sender_domain,
        subject,
        risk_score,
        classification,
        created_at
    ) VALUES (?, ?, ?, ?, ?, ?)
    """,
    (
        user_id,
        sender_domain,
        subject,
        risk_score,
        classification,
        created_at,
    ),
)


    analysis_id = cursor.lastrowid

    # ---------------------------------------------
    # 5. Save detected indicators
    # ---------------------------------------------

    reasons = risk_analysis.get("reasons", [])

    for reason in reasons:

        indicator_type = reason.get(
            "indicator",
            "Unknown"
        )

        description = reason.get(
            "explanation",
            ""
        )

        points = int(
            reason.get("points", 0)
        )

        # Convert points into severity
        if points >= 20:
            severity = "HIGH"
        elif points >= 10:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        cursor.execute(
            """
            INSERT INTO indicators (
                analysis_id,
                indicator_type,
                description,
                severity
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                analysis_id,
                indicator_type,
                description,
                severity,
            )
        )
            # ---------------------------------------------
    # 6. Save URL analyses
    # ---------------------------------------------

    url_results = result.get("url_analysis", [])

    for url_result in url_results:

        original_url = url_result.get("url", "")

        url_risk_score = int(
            url_result.get("url_risk_score", 0)
        )

        url_findings = url_result.get(
            "url_findings",
            []
        )

        # Safe representation:
        # store the URL without query parameters
        safe_url = original_url.split("?")[0]

        cursor.execute(
            """
            INSERT INTO url_analyses (
                analysis_id,
                url_safe_representation,
                risk_score,
                findings
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                analysis_id,
                safe_url,
                url_risk_score,
                " | ".join(url_findings),
            )
        )

    connection.commit()
    connection.close()

    return analysis_id


# -------------------------------------------------
# ANALYZE EMAIL API
# -------------------------------------------------

@router.post("/analyze")
def analyze_email_endpoint(
    request: EmailRequest,
    user=Depends(get_current_user),
):
        
    # Validate required email inputs
    if not request.sender.strip():
        raise HTTPException(
            status_code=400,
            detail="Sender email is required."
        )

    if not request.body.strip():
        raise HTTPException(
            status_code=400,
            detail="Email body is required for phishing analysis."
        )


    result = analyze_email(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        urls=request.urls,
        attachment_name=request.attachment_name,
    )

    # Save analysis + indicators
    analysis_id = save_analysis(
    result,
    request.sender,
    request.subject,
    user["user_id"],
)
    

    # Add database ID to API response
    result["analysis_id"] = analysis_id

    return result
# -------------------------------------------------
# GET ANALYSIS HISTORY
# -------------------------------------------------

@router.get("/analyses")
def get_analyses():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            analysis_id,
            sender_domain,
            subject,
            risk_score,
            classification,
            created_at
        FROM analyses
        ORDER BY analysis_id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    analyses = []

    for row in rows:
        analyses.append({
            "analysis_id": row["analysis_id"],
            "sender_domain": row["sender_domain"],
            "subject": row["subject"],
            "risk_score": row["risk_score"],
            "classification": row["classification"],
            "created_at": row["created_at"],
        })

    return {
        "total": len(analyses),
        "analyses": analyses
    }
@router.get("/analyses/{analysis_id}")
def get_analysis_by_id(analysis_id: int):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            analysis_id,
            sender_domain,
            subject,
            risk_score,
            classification,
            created_at
        FROM analyses
        WHERE analysis_id = ?
        """,
        (analysis_id,)
    )

    row = cursor.fetchone()

    if row is None:
        connection.close()

        return {
            "error": "Analysis not found"
        }

    cursor.execute(
        """
        SELECT
            indicator_type,
            description,
            severity
        FROM indicators
        WHERE analysis_id = ?
        """,
        (analysis_id,)
    )

    indicator_rows = cursor.fetchall()

    cursor.execute(
        """
        SELECT
            url_safe_representation,
            risk_score,
            findings
        FROM url_analyses
        WHERE analysis_id = ?
        """,
        (analysis_id,)
    )

    url_rows = cursor.fetchall()

    connection.close()

    return {
        "analysis": {
            "analysis_id": row["analysis_id"],
            "sender_domain": row["sender_domain"],
            "subject": row["subject"],
            "risk_score": row["risk_score"],
            "classification": row["classification"],
            "created_at": row["created_at"],
        },
        "indicators": [
            {
                "indicator_type": item["indicator_type"],
                "description": item["description"],
                "severity": item["severity"],
            }
            for item in indicator_rows
        ],
        "url_analyses": [
            {
                "url_safe_representation": item["url_safe_representation"],
                "risk_score": item["risk_score"],
                "findings": item["findings"],
            }
            for item in url_rows
        ]
    }
@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id: int):
    connection = get_connection()
    cursor = connection.cursor()

    # Check whether analysis exists
    cursor.execute(
        """
        SELECT analysis_id
        FROM analyses
        WHERE analysis_id = ?
        """,
        (analysis_id,)
    )

    row = cursor.fetchone()

    if row is None:
        connection.close()

        return {
            "error": "Analysis not found"
        }

    # Preserve analyses that have admin review reports
    cursor.execute(
        """
        SELECT review_id
        FROM review_cases
        WHERE analysis_id = ?
        LIMIT 1
        """,
        (analysis_id,)
    )

    if cursor.fetchone() is not None:
        connection.close()
        raise HTTPException(
            status_code=409,
            detail="This analysis has an admin review report and cannot be deleted."
        )

    # Delete the analysis
    # Related indicators and URL analyses
    # will be deleted automatically because
    # foreign key cascade is enabled.
    cursor.execute(
        """
        DELETE FROM analyses
        WHERE analysis_id = ?
        """,
        (analysis_id,)
    )

    connection.commit()
    connection.close()

    return {
        "message": "Analysis deleted successfully",
        "analysis_id": analysis_id
    }
@router.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    result = analyze_url(request.url)

    return result

# -------------------------------------------------
# REPORT EXISTING ANALYSIS TO ADMIN
# -------------------------------------------------

@router.post("/review-cases")
def create_review_case(
    request: ReviewCaseRequest,
    user=Depends(require_user),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        # Check whether the analysis exists
        cursor.execute(
            """
            SELECT analysis_id
            FROM analyses
            WHERE analysis_id = ?
            """,
            (request.analysis_id,)
        )

        analysis = cursor.fetchone()

        if analysis is None:
            raise HTTPException(
                status_code=404,
                detail="Analysis not found"
            )

        # Prevent duplicate pending reports
        cursor.execute(
            """
            SELECT review_id
            FROM review_cases
            WHERE analysis_id = ?
              AND reported_by = ?
              AND status = 'PENDING'
            """,
            (
                request.analysis_id,
                user["email"]
            )
        )

        existing_case = cursor.fetchone()

        if existing_case is not None:
            raise HTTPException(
                status_code=409,
                detail="This analysis already has a pending review report"
            )

        # Create a review case without re-analyzing the email
        created_at = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            INSERT INTO review_cases (
                analysis_id,
                reported_by,
                status,
                created_at
            )
            VALUES (?, ?, 'PENDING', ?)
            """,
            (
                request.analysis_id,
                user["email"],
                created_at
            )
        )

        review_id = cursor.lastrowid
        connection.commit()

        return {
            "message": "Analysis reported to Admin successfully",
            "review_id": review_id,
            "analysis_id": request.analysis_id,
            "status": "PENDING"
        }

    finally:
        connection.close()

# -------------------------------------------------
# GET REVIEW CASES FOR ADMIN
# -------------------------------------------------

@router.get("/review-cases")
def get_review_cases(user=Depends(require_admin)):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                rc.review_id,
                rc.analysis_id,
                rc.reported_by,
                rc.status,
                rc.admin_notes,
                rc.reviewed_by,
                rc.created_at,
                rc.reviewed_at,
                a.sender_domain,
                a.subject,
                a.risk_score,
                a.classification
            FROM review_cases rc
            JOIN analyses a
                ON rc.analysis_id = a.analysis_id
            ORDER BY
                CASE WHEN rc.status = 'PENDING'
                     THEN 0 ELSE 1 END,
                rc.review_id DESC
            """
        )

        rows = cursor.fetchall()

        return {
            "total": len(rows),
            "review_cases": [
                dict(row) for row in rows
            ]
        }

    finally:
        connection.close()

# -------------------------------------------------
# ADMIN: UPDATE REVIEW DECISION
# -------------------------------------------------

@router.patch("/review-cases/{review_id}")
def update_review_case(
    review_id: int,
    request: ReviewDecisionRequest,
    user=Depends(require_admin),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        # Check whether the review case exists
        cursor.execute(
            """
            SELECT review_id
            FROM review_cases
            WHERE review_id = ?
            """,
            (review_id,)
        )

        existing_case = cursor.fetchone()

        if existing_case is None:
            raise HTTPException(
                status_code=404,
                detail="Review case not found"
            )

        # Update the review case with admin decision
        reviewed_at = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            UPDATE review_cases
            SET status = ?,
                admin_notes = ?,
                reviewed_by = ?,
                reviewed_at = ?
            WHERE review_id = ?
            """,
            (
                request.status.strip().upper(),
                request.admin_notes.strip(),
                request.reviewed_by.strip(),
                reviewed_at,
                review_id
            )
        )

        connection.commit()

        return {
            "message": "Review case updated successfully",
            "review_id": review_id,
            "status": request.status.strip().upper()
        }

    finally:
        connection.close()

# -------------------------------------------------
# GET REPORTS SUBMITTED BY A USER
# -------------------------------------------------

@router.get("/review-cases/user/{reported_by}")
def get_user_review_cases(
    reported_by: str,
    user=Depends(require_user),
):
    reported_by = user["email"]
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                rc.review_id,
                rc.analysis_id,
                rc.reported_by,
                rc.status,
                rc.admin_notes,
                rc.reviewed_by,
                rc.created_at,
                rc.reviewed_at,
                a.sender_domain,
                a.subject,
                a.risk_score,
                a.classification
            FROM review_cases rc
            JOIN analyses a
                ON rc.analysis_id = a.analysis_id
            WHERE rc.reported_by = ?
            ORDER BY rc.review_id DESC
            """,
            (reported_by.strip().lower(),)
        )

        rows = cursor.fetchall()

        return {
            "total": len(rows),
            "review_cases": [
                dict(row) for row in rows
            ]
        }

    finally:
        connection.close()
