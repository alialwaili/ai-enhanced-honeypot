"""
app.py — AI Meeting Notes & Action Extractor
High-interaction honeypot powered by an ML security engine.
"""

import os
import sqlite3
import logging
import calendar as cal_module
from datetime import datetime, date
from functools import wraps
from urllib.parse import quote as url_quote
from flask import (
    Flask, g, render_template, request,
    redirect, url_for, session, flash,
)
from werkzeug.security import generate_password_hash, check_password_hash

from brain import SecurityBrain

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["DATABASE"] = "honeypot.db"
app.secret_key = os.environ.get("SECRET_KEY", "miq-dev-key-change-in-production")

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
)

brain = SecurityBrain()
logging.info("SecurityBrain initialised — model trained and ready.")

PER_PAGE = 10


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(
            app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(app.config["DATABASE"])

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    NOT NULL UNIQUE,
            email     TEXT    NOT NULL UNIQUE,
            password  TEXT    NOT NULL,
            created   TEXT    NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS meetings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            title      TEXT    NOT NULL,
            date       TEXT    NOT NULL,
            leader     TEXT    NOT NULL,
            transcript TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            payload     TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            endpoint    TEXT NOT NULL,
            confidence  REAL NOT NULL
        )
    """)

    count = db.execute("SELECT COUNT(*) FROM meetings").fetchone()[0]
    if count == 0:
        seed = [
            ("Employee Engagement Survey Results", "2025-08-20", "Ammar Alhattaly",
             "Ammar Alhattaly presented the results of the annual employee engagement survey to the "
             "leadership team. Overall engagement score for 2025 was 74%, a six-point improvement on "
             "2024 and above the regional benchmark of 68%. Key strengths identified were leadership "
             "trust, job clarity, and team collaboration. Areas requiring improvement included career "
             "development visibility, internal communication frequency, and recognition practices. "
             "Response rate was 89%, the highest since the survey was introduced. Three priority action "
             "areas were agreed: launching a structured mentorship programme, increasing all-hands "
             "communications to monthly, and piloting a peer recognition scheme in Q4. "
             "Action items: HR to publish the full results report to all staff by Aug 27; HR to develop "
             "the mentorship programme framework by Sep 30; communications team to schedule the first "
             "redesigned all-hands session for October."),

            ("Partnership & Alliances Meeting", "2025-09-16", "Mohammed Alalawi",
             "Mohammed Alalawi led the quarterly partnership review covering Alwaili's strategic "
             "alliances with five key technology and service partners. The partnership with a leading "
             "ERP provider was expanded to include a co-selling agreement for the GCC market, with a "
             "joint pipeline of 1.2M OMR already identified. A memorandum of understanding with the "
             "Information Technology Authority of Oman was signed to collaborate on digital skills "
             "initiatives targeting recent graduates. Two underperforming partnerships were placed under "
             "review with continuation decisions expected by December. Two new alliance candidates in "
             "the cybersecurity and logistics technology spaces are under evaluation. "
             "Action items: Mohammed to brief the board on the ERP co-selling agreement at the October "
             "board meeting; business development to complete due diligence on new candidates by Oct 15; "
             "legal to prepare partnership framework agreements by Oct 30."),

            ("Board Meeting — Q3 Review", "2025-10-14", "Mohammed Alalawi",
             "Mohammed Alalawi presented the Q3 2025 performance summary to the board of directors. "
             "Revenue, EBITDA, and customer satisfaction metrics were all on or ahead of plan. The board "
             "approved the acquisition of a minority stake in a Muscat-based fintech startup to "
             "accelerate Alwaili's payments capabilities. Capital expenditure for the Salalah regional "
             "office fit-out was ratified at 380,000 OMR. The board reviewed and approved the updated "
             "risk register, with cybersecurity and regulatory compliance elevated to the top-two "
             "risk positions. A dividend distribution of 0.12 OMR per share was approved for Q3. "
             "Action items: Mohammed to lead fintech due diligence with a report by Nov 14; CFO to issue "
             "drawdown request for Salalah fit-out by Oct 25; legal to begin regulatory pre-notification "
             "for the minority stake acquisition."),

            ("Finance Quarterly Review — Q3", "2025-10-28", "Ahmed Alalawi",
             "Ahmed Alalawi chaired the Q3 finance review attended by divisional controllers and "
             "the external audit liaison. Revenue for the first nine months of 2025 reached 6.1M OMR, "
             "tracking at 101% of the year-to-date plan. Operating expenditure was 3% under budget "
             "owing to delayed hiring in the technology division and lower-than-forecast travel costs. "
             "Accounts receivable days outstanding increased to 47 days against a target of 35 days; "
             "the commercial team was tasked with an immediate collections drive. Provisions for "
             "doubtful debts were increased by 28,000 OMR following updated customer credit assessments. "
             "Action items: commercial team to present a collections action plan by Nov 4; finance to "
             "prepare the Q3 board pack by Nov 7; Ahmed to meet external auditors for the interim "
             "review on Nov 12."),

            ("Annual Strategy Review", "2025-11-05", "Mohammed Alalawi",
             "Mohammed Alalawi presided over Alwaili's annual strategy review attended by the "
             "executive leadership team and all divisional directors. The five-year strategic plan was "
             "assessed against Year 2 milestones: 80% of targets achieved, with digital services "
             "revenue outperforming projections by 18%. Three strategic priorities for 2026 were "
             "ratified: accelerating the digital transformation agenda, expanding into the Dhofar and "
             "Al Batinah regions, and strengthening the talent pipeline through the Alwaili Graduate "
             "Programme. A dedicated strategy execution office reporting directly to the CEO will be "
             "established in Q1 2026. Two non-core business units were identified for strategic review. "
             "Action items: each division head to submit their 2026 operational plan by Nov 25; HR to "
             "publish the Graduate Programme application window by Dec 1; CFO to model capital "
             "requirements for regional expansion and present to the board in January."),

            ("Digital Transformation Update", "2025-11-18", "Moosa Alaghbari",
             "Moosa Alaghbari delivered the bi-annual digital transformation progress report to the "
             "steering committee. Phase 1—legacy system decommissioning—is complete, resulting in an "
             "estimated 340,000 OMR per year in licensing savings. Phase 2, covering the enterprise "
             "data platform and customer-facing portal, is 45% complete and on track for Q2 2026 "
             "delivery. A new low-code development capability has been piloted within the operations "
             "division, enabling three internal workflow automations without engineering resource. The "
             "committee approved a budget increase of 120,000 OMR to accelerate AI integration across "
             "finance and HR functions. Data quality improvements have reduced reporting cycle time by "
             "31% compared to the previous system. "
             "Action items: Moosa to update the digital roadmap document by Nov 25; finance to "
             "process the budget amendment by Nov 30; operations to document automation wins and "
             "circulate as an internal case study by Dec 5."),

            ("Risk Management Update — Q3", "2025-11-25", "Osama Alharthy",
             "Osama Alharthy presented the Q3 risk register update to the risk and audit committee. "
             "The enterprise risk register contains 34 active risks: 5 high, 18 medium, and 11 low. "
             "Two new risks were added this quarter: customer concentration risk in the top-three "
             "accounts and supply chain disruption risk linked to a single-source hardware vendor. "
             "The business interruption insurance policy was reviewed and coverage limits were increased. "
             "A tabletop exercise simulating a ransomware incident was conducted with positive outcomes, "
             "identifying three process improvements that have since been implemented. A quarterly risk "
             "appetite statement was presented and approved by the committee for the first time. "
             "Action items: Osama to distribute the updated risk register to all division heads by "
             "Dec 2; procurement to source an alternative hardware vendor by Jan 31; insurance broker "
             "to confirm revised policy terms by Dec 15."),

            ("Vendor Negotiation Review", "2025-12-02", "Ahmed Ambosaidi",
             "Ahmed Ambosaidi convened the vendor review panel to assess performance across Alwaili's "
             "ten strategic suppliers. Six vendors received satisfactory ratings; two—covering facilities "
             "management and logistics—were placed on performance improvement plans with 90-day review "
             "clauses. Negotiations with the primary cloud provider concluded with a 22% reduction on "
             "committed spend in exchange for a three-year contract extension, saving approximately "
             "195,000 OMR over the term. A local IT hardware vendor from the Muscat Technology District "
             "was shortlisted to replace an underperforming overseas supplier, supporting Omanisation "
             "procurement targets. Vendor scorecards will be reviewed monthly going forward. "
             "Action items: procurement to issue performance improvement notices to the two "
             "underperforming vendors by Dec 9; legal to finalise the cloud provider contract amendment "
             "by Dec 20; Ahmed to present the new hardware vendor proposal to the CFO by Dec 15."),

            ("Compliance & Regulatory Update", "2025-12-09", "Ammar Alhattaly",
             "Ammar Alhattaly chaired the quarterly compliance committee meeting with legal, finance, "
             "and operations representatives. Updates to the Personal Data Protection Law (PDPL) were "
             "reviewed; Alwaili's data governance framework requires three amendments to achieve full "
             "compliance by the March 2026 regulatory deadline. An internal audit covering procurement "
             "and expense management found two minor control deficiencies, both now remediated. The "
             "legal team briefed the committee on upcoming changes to the Commercial Companies Law "
             "affecting subsidiary reporting requirements. Anti-bribery and corruption training "
             "completion rates reached 97% across all staff. "
             "Action items: data governance team to complete PDPL gap remediation by Jan 31; internal "
             "audit to publish the full findings report by Dec 20; legal to prepare a CFO briefing note "
             "on Commercial Companies Law implications by Jan 15."),

            ("IT Infrastructure Review", "2025-12-16", "Osama Alharthy",
             "Osama Alharthy led the end-of-year IT infrastructure review covering network, compute, "
             "storage, and end-user computing assets. Server utilisation across the primary data centre "
             "averaged 71% over the past quarter, with two nodes flagged for decommissioning. The WAN "
             "refresh connecting the Sohar and Salalah branches was completed on budget and two weeks "
             "ahead of schedule. End-user device refresh targeting 180 laptops for Q1 2026 was approved "
             "at a cost of 95,000 OMR. A proposal to migrate backup infrastructure to a hybrid cloud "
             "model was tabled, with an estimated annual saving of 42,000 OMR. Mean time to resolve "
             "IT incidents improved by 24% following the implementation of a new ITSM platform. "
             "Action items: Osama to circulate the hybrid cloud proposal with cost-benefit analysis "
             "by Jan 8; IT operations to begin the device refresh procurement process by Jan 12; "
             "network team to document all WAN configuration changes in the CMDB by Dec 31."),

            ("Annual Sales Performance Review", "2025-12-22", "Ahmed Alalawi",
             "Ahmed Alalawi presented the full-year 2025 sales performance review to the commercial "
             "leadership team. Total revenue reached 8.4M OMR, representing 103% of the annual "
             "target—the third consecutive year of target attainment. The enterprise segment was the "
             "strongest performer at 112% of target; the SME segment underperformed at 88% due to a "
             "mid-year pipeline gap. Four new enterprise logos were acquired including two "
             "government-affiliated entities and a regional bank. The sales incentive scheme was revised "
             "for 2026 to better weight new business acquisition relative to renewals. Average deal "
             "cycle time reduced from 94 to 71 days through process improvements in the pre-sales team. "
             "Action items: Ahmed to present the 2026 sales plan and revised quotas to the board by "
             "Jan 10; HR to update incentive scheme documentation by Jan 20; sales operations to "
             "reconfigure the CRM for the new territory structure by Jan 31."),

            ("Operations Efficiency Study", "2025-12-30", "Moosa Alaghbari",
             "Moosa Alaghbari presented findings from a three-month operational efficiency study "
             "commissioned to identify cost reduction and productivity improvement opportunities across "
             "Alwaili's core delivery functions. The study identified 14 improvement initiatives with a "
             "combined estimated annual benefit of 620,000 OMR. The top three initiatives—automated "
             "invoice processing, centralised asset management, and consolidation of regional "
             "procurement—were approved for immediate implementation. Seven further initiatives were "
             "approved for piloting in Q1 2026. Three initiatives were deferred pending further analysis. "
             "Process mapping workshops revealed duplication of effort in four cross-functional workflows. "
             "Action items: Moosa to establish a programme management office for approved initiatives "
             "by Jan 10; finance to model the phased benefit realisation schedule by Jan 15; operations "
             "managers to nominate initiative owners by Jan 8."),

            ("Customer Success Strategy 2026", "2026-01-05", "Ammar Alhattaly",
             "Ammar Alhattaly presented the revised customer success strategy for 2026 to the "
             "commercial leadership team. Net Promoter Score for Q4 2025 was 54, up from 47 in Q3 and "
             "significantly above the industry benchmark of 38. A new tiered service model—Standard, "
             "Professional, and Premier—was introduced to align support resources with customer lifetime "
             "value. The Premier tier, covering Alwaili's top 12 accounts, includes a dedicated customer "
             "success manager and quarterly executive business reviews. Annual churn rate for 2025 was "
             "4.2%, comfortably below the 5% target. Health scoring will be introduced in Q1 to enable "
             "proactive intervention for at-risk accounts. "
             "Action items: Ammar to assign dedicated CSMs to Premier accounts by Jan 15; operations "
             "to configure the new service tier workflows in the ticketing system by Jan 20; finance "
             "to update billing configurations for the new tier pricing by Jan 25."),

            ("Q4 Budget Planning", "2026-01-08", "Ahmed Alalawi",
             "Ahmed Alalawi opened the Q4 budget session with a consolidated financial overview "
             "across all seven Alwaili divisions. The finance team reported a 12% underspend in "
             "operational costs attributable to renegotiated supplier contracts and reduced travel "
             "expenditure. The board approved a 2.1M OMR reallocation toward cloud infrastructure and "
             "cybersecurity hardening. Regional heads raised concerns about delayed capital expenditure "
             "approvals affecting the Salalah branch expansion; these were escalated to the CFO for "
             "resolution within 10 working days. Workforce planning data was reviewed confirming 18 "
             "open requisitions across technology and commercial functions. "
             "Action items: finance team to submit a revised forecast model by Jan 15; procurement to "
             "finalise the vendor shortlist for the data centre upgrade by Jan 20; CFO to resolve "
             "the Salalah capex approval within 10 working days."),

            ("Training & Development Plan 2026", "2026-01-12", "Ammar Alhattaly",
             "Ammar Alhattaly presented Alwaili's 2026 Learning & Development framework to department "
             "heads. A total training budget of 180,000 OMR was confirmed, representing an 18% increase "
             "on 2025 reflecting Omanisation and talent retention commitments. Three flagship programmes "
             "were announced: a leadership accelerator for mid-level managers, a technical skills "
             "academy for engineering and IT staff, and a mandatory digital literacy programme for all "
             "employees. Partnership agreements with two accredited local training providers were signed. "
             "Sixty percent of all training hours will be delivered through the newly implemented LMS. "
             "The Alwaili Graduate Programme cohort for 2026 will comprise 15 graduates joining in "
             "September across five departments. "
             "Action items: Ammar to publish the 2026 training calendar by Jan 20; department heads to "
             "submit team priority development areas by Jan 17; IT to complete LMS configuration for "
             "new content modules by Jan 31."),

            ("Product Roadmap Review — H1", "2026-01-14", "Ahmed Ambosaidi",
             "Ahmed Ambosaidi led the H1 product roadmap session with representatives from engineering, "
             "design, and customer success. Three major features were reviewed: the unified client "
             "portal, the AI-assisted reporting module, and the mobile application refresh. The "
             "authentication overhaul was elevated to P0 priority following a security audit "
             "recommendation. The design team presented high-fidelity wireframes for the new onboarding "
             "flow, receiving overall approval with minor revisions requested on accessibility "
             "compliance. Capacity planning confirmed that two additional engineers are required in Q1 "
             "to maintain delivery commitments. "
             "Action items: PM to draft technical specifications by Jan 21; design to incorporate "
             "feedback and resubmit wireframes by Jan 28; engineering lead to provide updated capacity "
             "estimates and raise hiring requisitions by Jan 18."),

            ("HR Policy Update — Q1", "2026-01-20", "Ammar Alhattaly",
             "Ammar Alhattaly chaired the HR policy review attended by department heads and the legal "
             "team. The remote work framework was formally updated to allow two days per week from home "
             "for all non-operational staff. A flexible hours pilot allowing start times between 7:00 "
             "and 9:30 AM was approved for a 90-day trial beginning February 1st. Annual leave "
             "entitlement for staff with over five years of service was increased by two additional days "
             "in line with updated Omani Labour Law guidance. The probationary review process was "
             "streamlined from a three-stage to a two-stage assessment, reducing time-to-confirm by "
             "an average of 14 days. "
             "Action items: HR to distribute the updated employee handbook by Jan 25; department heads "
             "to brief their teams within one week of receipt; legal to review and approve the updated "
             "remote work agreement templates by Jan 22."),

            ("Engineering All-Hands", "2026-01-27", "Moosa Alaghbari",
             "Moosa Alaghbari opened the engineering all-hands by reviewing Q4 delivery metrics: "
             "94% of planned sprint points completed, up from 87% in Q3. The microservices migration "
             "project is 60% complete with the payments service successfully decoupled last week. Three "
             "major CI/CD pipeline improvements were shipped including parallel test execution, reducing "
             "average build time by 38%. The platform team demonstrated the new self-service deployment "
             "dashboard to positive reception across all squads. Two critical January incidents were "
             "reviewed; root cause analysis reports will be published in the internal wiki within 48 "
             "hours. Engineering headcount plan for Q1 was confirmed, with four offers already extended. "
             "Action items: platform team to publish the new deployment runbook by Feb 5; each squad "
             "to nominate a migration champion for their service transition by Feb 3; incident RCAs "
             "to be posted to the wiki by Jan 29."),

            ("Client Strategy Session", "2026-02-03", "Ahmed Alalawi",
             "Ahmed Alalawi facilitated the quarterly client strategy review with the sales, account "
             "management, and customer success leads. The top-10 account health scorecard showed seven "
             "accounts green, two amber, and one—Al-Nahda Group—red due to delayed renewal negotiations. "
             "An escalation plan for Al-Nahda Group was agreed: a senior executive call within five "
             "days and a tailored renewal proposal with a 10% loyalty discount. A new mid-market "
             "strategy targeting companies of 50–200 employees in the Muscat and Sohar industrial zones "
             "was introduced. Pipeline coverage for Q2 stands at 2.4x quota, considered healthy. "
             "Action items: sales director to schedule the Al-Nahda Group executive call by Feb 7; "
             "account team to prepare the renewal proposal by Feb 10; marketing to develop mid-market "
             "collateral by end of February."),

            ("Security Posture Review", "2026-02-10", "Osama Alharthy",
             "Osama Alharthy presented results of the annual third-party penetration test conducted by "
             "a licensed cybersecurity firm. Two high-severity findings were identified: an outdated TLS "
             "configuration on the legacy API gateway and insufficient session timeout controls on the "
             "admin panel; both have been patched within 72 hours. Three medium findings related to "
             "logging gaps and weak service account password policies were remediated during the review "
             "cycle. Zero critical findings were recorded for the second consecutive year. The business "
             "continuity and disaster recovery plan was reviewed, confirming the RTO of four hours and "
             "RPO of one hour remain achievable and were validated in a live failover test last month. "
             "Action items: DevSecOps to close the remaining four low-severity findings by EOQ; "
             "security team to schedule a Q2 tabletop exercise; all service account passwords to be "
             "rotated and stored in the approved vault by Feb 28."),

            ("Marketing Campaign Sync", "2026-02-17", "Ammar Alhattaly",
             "Ammar Alhattaly chaired the spring campaign alignment meeting with the creative, "
             "digital, and content teams. The Ramadan digital campaign concept was presented and "
             "approved; the theme 'Connect with Purpose' was selected from three creative proposals. "
             "Media buying budget of 85,000 OMR was confirmed, split across social media, programmatic "
             "display, and sponsored content on regional business portals. KPI targets were set at "
             "2 million impressions, 15,000 website visits, and 200 qualified leads over the six-week "
             "campaign window. Brand safety guidelines were updated to include new platform-specific "
             "restrictions agreed with the legal team. "
             "Action items: content team to deliver all copy assets by Feb 25; digital team to configure "
             "campaign tracking and UTM parameters by Feb 28; Ammar to submit the final media plan "
             "to finance for approval by Feb 20."),

            ("Product Launch Review — Alwaili Connect", "2026-02-24", "Ahmed Ambosaidi",
             "Ahmed Ambosaidi chaired the post-launch review for the Alwaili Connect client portal, "
             "which went live on February 10th. First-week adoption exceeded projections: 78% of "
             "eligible customers completed onboarding, with a portal satisfaction score of 4.3 out of 5. "
             "Three critical bugs identified in the first 48 hours were resolved within the agreed SLA "
             "window of four hours. The customer support team handled 142 inbound queries in the first "
             "week, primarily around password setup and permission configuration; a comprehensive FAQ "
             "has been published. Server performance under peak load was within acceptable thresholds "
             "with a maximum response time of 1.2 seconds. "
             "Action items: Ahmed to present a 30-day adoption report to the executive team on "
             "March 12; product team to release the first patch update by March 1; customer success "
             "to proactively contact the 22% of customers who have not yet activated their accounts."),

            ("Strategic Planning Session 2027", "2026-02-25", "Mohammed Alalawi",
             "Mohammed Alalawi facilitated the first horizon-planning session for Alwaili's 2027 "
             "strategic plan, attended by senior leadership and two external strategy advisors. The "
             "session focused on macro-environmental trends including Oman Vision 2040 priorities, "
             "regional digitalisation acceleration, and evolving customer expectations in the B2B "
             "technology sector. Four potential growth vectors were identified and pressure-tested: "
             "deepening penetration in government accounts, building a managed services capability, "
             "entering the Kingdom of Saudi Arabia market, and developing proprietary AI-powered "
             "analytics products. Scenario planning was conducted for three market conditions: base, "
             "optimistic, and stressed. Initial financial modelling suggests the managed services "
             "vector offers the strongest risk-adjusted return over a five-year horizon. "
             "Action items: each leadership team member to submit strategic inputs and assumptions "
             "by March 14; strategy team to synthesise inputs into a draft framework by March 28; "
             "a follow-up planning session is scheduled for April to review and refine the framework."),
        ]
        db.executemany(
            "INSERT INTO meetings (title, date, leader, transcript) VALUES (?,?,?,?)",
            seed,
        )

    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Security helper
# ---------------------------------------------------------------------------

def check_and_log(text: str, endpoint: str) -> bool:
    """Returns True if safe, False if malicious (and logs the attack)."""
    label, confidence = brain.classify(text)
    if label == 1:
        atype = brain.attack_type(text)
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        db = get_db()
        db.execute(
            "INSERT INTO attacks (ip, timestamp, payload, attack_type, endpoint, confidence)"
            " VALUES (?,?,?,?,?,?)",
            (ip, datetime.utcnow().isoformat(), text, atype, endpoint, confidence),
        )
        db.commit()
        logging.warning(
            "BLOCKED %s from %s | endpoint=%s | confidence=%.2f | payload=%r",
            atype, ip, endpoint, confidence, text[:120],
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not check_and_log(username, "/login:username"):
            return render_template("error.html"), 500

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password"], password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        if not user["is_active"]:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Validate inputs through the AI engine
        for field, value in [("username", username), ("email", email)]:
            if value and not check_and_log(value, f"/signup:{field}"):
                return render_template("error.html"), 500

        # Basic field validation
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("signup.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("signup.html")

        db = get_db()

        if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            flash("That username is already taken.", "error")
            return render_template("signup.html")

        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            flash("An account with that email already exists.", "error")
            return render_template("signup.html")

        db.execute(
            "INSERT INTO users (username, email, password, created) VALUES (?,?,?,?)",
            (username, email, generate_password_hash(password), datetime.utcnow().isoformat()),
        )
        db.commit()
        flash("Account created — please sign in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Main routes (all protected)
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    db = get_db()
    total_meetings = db.execute("SELECT COUNT(*) FROM meetings").fetchone()[0]
    unique_leaders = db.execute("SELECT COUNT(DISTINCT leader) FROM meetings").fetchone()[0]
    total_pages = max(1, (total_meetings + PER_PAGE - 1) // PER_PAGE)
    page = max(1, min(request.args.get("page", 1, type=int), total_pages))
    offset = (page - 1) * PER_PAGE
    meetings = db.execute(
        "SELECT * FROM meetings ORDER BY date DESC LIMIT ? OFFSET ?",
        (PER_PAGE, offset),
    ).fetchall()
    return render_template(
        "index.html",
        meetings=meetings,
        total_meetings=total_meetings,
        unique_leaders=unique_leaders,
        search_query="",
        filter_by="title",
        page=page,
        total_pages=total_pages,
        page_base_url="/?",
    )


@app.route("/search")
@login_required
def search():
    query     = request.args.get("q", "").strip()
    filter_by = request.args.get("filter", "title")

    if query and not check_and_log(query, "/search"):
        return render_template("error.html"), 500

    db = get_db()
    column = "leader" if filter_by == "leader" else "title"
    total_meetings = db.execute(
        f"SELECT COUNT(*) FROM meetings WHERE {column} LIKE ?",
        (f"%{query}%",),
    ).fetchone()[0]
    unique_leaders = db.execute("SELECT COUNT(DISTINCT leader) FROM meetings").fetchone()[0]
    total_pages = max(1, (total_meetings + PER_PAGE - 1) // PER_PAGE)
    page = max(1, min(request.args.get("page", 1, type=int), total_pages))
    offset = (page - 1) * PER_PAGE
    meetings = db.execute(
        f"SELECT * FROM meetings WHERE {column} LIKE ? ORDER BY date DESC LIMIT ? OFFSET ?",
        (f"%{query}%", PER_PAGE, offset),
    ).fetchall()
    return render_template(
        "index.html",
        meetings=meetings,
        total_meetings=total_meetings,
        unique_leaders=unique_leaders,
        search_query=query,
        filter_by=filter_by,
        page=page,
        total_pages=total_pages,
        page_base_url=f"/search?q={url_quote(query)}&filter={filter_by}&",
    )


@app.route("/add", methods=["POST"])
@login_required
def add_meeting():
    """Internal API endpoint — receives meeting data from external systems."""
    fields = {
        "title":      request.form.get("title", "").strip(),
        "date":       request.form.get("date", "").strip(),
        "leader":     request.form.get("leader", "").strip(),
        "transcript": request.form.get("transcript", "").strip(),
    }

    for field_name, value in fields.items():
        if value and not check_and_log(value, f"/add:{field_name}"):
            return render_template("error.html"), 500

    db = get_db()
    db.execute(
        "INSERT INTO meetings (title, date, leader, transcript) VALUES (?,?,?,?)",
        (fields["title"], fields["date"], fields["leader"], fields["transcript"]),
    )
    db.commit()
    return redirect(url_for("index"))


@app.route("/calendar")
@login_required
def calendar_view():
    db = get_db()
    rows = db.execute(
        "SELECT id, title, date, leader, transcript FROM meetings ORDER BY date"
    ).fetchall()

    # Build a lookup: date-string → list of meeting dicts
    meetings_by_date = {}
    for m in rows:
        entry = {
            "id":         m["id"],
            "title":      m["title"],
            "leader":     m["leader"],
            "transcript": m["transcript"] or "",
        }
        meetings_by_date.setdefault(m["date"], []).append(entry)

    # Build structured calendar data for 2026-2028
    years_data = []
    for year in [2026, 2027, 2028]:
        months = []
        for month in range(1, 13):
            weeks_raw = cal_module.monthcalendar(year, month)
            weeks = []
            for week in weeks_raw:
                cells = []
                for day in week:
                    if day == 0:
                        cells.append(None)
                    else:
                        date_str = f"{year}-{month:02d}-{day:02d}"
                        cells.append({"day": day, "date": date_str})
                weeks.append(cells)
            months.append({
                "name":   cal_module.month_name[month],
                "number": month,
                "weeks":  weeks,
            })
        years_data.append({"year": year, "months": months})

    return render_template(
        "calendar.html",
        years_data=years_data,
        meetings_by_date=meetings_by_date,
        today=date.today().isoformat(),
    )


@app.route("/attacks")
@login_required
def attack_log():
    db = get_db()
    attacks = db.execute(
        "SELECT * FROM attacks ORDER BY timestamp DESC"
    ).fetchall()
    return render_template("attacks.html", attacks=attacks)


@app.route("/delete/<int:meeting_id>", methods=["POST"])
@login_required
def delete_meeting(meeting_id: int):
    db = get_db()
    db.execute("DELETE FROM meetings WHERE id = ?", (meeting_id,))
    db.commit()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
