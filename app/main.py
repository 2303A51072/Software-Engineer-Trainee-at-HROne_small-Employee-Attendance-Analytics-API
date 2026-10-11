"""Employee Attendance & Analytics API."""
import calendar
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Annotated, Literal, Optional

from bson import json_util
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator
from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError

load_dotenv()

IST = timezone(timedelta(hours=5, minutes=30))
UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MIN_EPOCH_MS = 100_000_000_000
MAX_EPOCH_MS = 4_102_444_800_000
PRESENCE_STATUSES = ("PRESENT", "WFH", "ON_DUTY")
MONTH_PATTERN = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")

client = MongoClient(
    os.getenv("MONGO_URI", "mongodb://localhost:27017"),
    tz_aware=True,
    serverSelectionTimeoutMS=2000,
)
db = client[os.getenv("MONGO_DB", "attendance_db")]

app = FastAPI(title="Employee Attendance & Analytics API", version="2.0.0")
ADMIN_COOKIE = "attendance_admin"
ADMIN_SESSION_SECONDS = 8 * 60 * 60
EMPLOYEE_COOKIE = "attendance_employee"


class EmployeeLoginIn(BaseModel):
    emp_code: str = Field(pattern=r"^EMP\d{4,6}$")
    pin: str = Field(min_length=6, max_length=128)


class EmployeePinIn(BaseModel):
    pin: str = Field(min_length=6, max_length=128)


def employee_pin_hash(pin: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 310_000).hex()


def employee_session_token(emp_code: str, expires: int, pin_hash: str, secret: str) -> str:
    payload = base64.urlsafe_b64encode(f"{emp_code}|{expires}|{pin_hash}".encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def authenticated_employee(request: Request) -> Optional[dict]:
    secret = os.getenv("ADMIN_SESSION_SECRET")
    if not secret:
        return None
    token = request.cookies.get(EMPLOYEE_COOKIE, "")
    try:
        payload, signature = token.rsplit(".", 1)
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        emp_code, expires, pin_hash = decoded.rsplit("|", 2)
        if int(expires) <= int(datetime.now(UTC).timestamp()):
            return None
    except (ValueError, UnicodeDecodeError):
        return None
    employee = db.employees.find_one({"emp_code": emp_code, "left_on": {"$exists": False}})
    if employee is None or not hmac.compare_digest(employee.get("login_pin_hash", ""), pin_hash):
        return None
    return employee


def require_punch_access(request: Request, emp_code: str) -> None:
    if is_admin_authenticated(request):
        return
    employee = authenticated_employee(request)
    if employee is None or employee["emp_code"] != emp_code:
        raise HTTPException(401, "employee sign-in required to punch for this account")


class AdminLoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def admin_settings() -> tuple[str, str, str]:
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    secret = os.getenv("ADMIN_SESSION_SECRET")
    if not username or not password or not secret:
        raise HTTPException(503, "admin login is not configured")
    return username, password, secret


def admin_session_token(username: str, expires: int, secret: str) -> str:
    payload = base64.urlsafe_b64encode(f"{username}|{expires}".encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def is_admin_authenticated(request: Request) -> bool:
    try:
        username, _, secret = admin_settings()
    except HTTPException:
        return False
    token = request.cookies.get(ADMIN_COOKIE, "")
    try:
        payload, signature = token.rsplit(".", 1)
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        token_username, expires = decoded.rsplit("|", 1)
        return token_username == username and int(expires) > int(datetime.now(UTC).timestamp())
    except (ValueError, UnicodeDecodeError):
        return False


def require_admin(request: Request) -> None:
    if not is_admin_authenticated(request):
        raise HTTPException(401, "admin sign-in required")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).with_name("index.html"))


@app.get("/admin/session")
def admin_session(request: Request):
    configured = all(os.getenv(key) for key in ("ADMIN_USERNAME", "ADMIN_PASSWORD", "ADMIN_SESSION_SECRET"))
    return {"configured": configured, "authenticated": configured and is_admin_authenticated(request)}


@app.post("/admin/login")
def admin_login(body: AdminLoginIn, request: Request, response: Response):
    username, password, secret = admin_settings()
    if not (
        hmac.compare_digest(body.username, username)
        and hmac.compare_digest(body.password, password)
    ):
        raise HTTPException(401, "incorrect username or password")
    expires = int(datetime.now(UTC).timestamp()) + ADMIN_SESSION_SECONDS
    response.set_cookie(
        ADMIN_COOKIE,
        admin_session_token(username, expires, secret),
        max_age=ADMIN_SESSION_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "username": username}


@app.post("/admin/logout")
def admin_logout(response: Response):
    response.delete_cookie(ADMIN_COOKIE, path="/", httponly=True, samesite="strict")
    return {"authenticated": False}


@app.on_event("startup")
def create_indexes() -> None:
    db.employees.create_index([("emp_code", ASCENDING)], unique=True, name="employee_code_unique")
    db.employees.create_index(
        [("department", ASCENDING), ("joined_on", ASCENDING)],
        name="department_joined",
    )
    db.employees.create_index([("joined_on", ASCENDING)], name="employee_joined")
    db.attendance_logs.create_index(
        [("emp_code", ASCENDING), ("date", ASCENDING)],
        unique=True,
        name="employee_date_unique",
    )
    db.attendance_logs.create_index(
        [("emp_code", ASCENDING), ("punch_in", DESCENDING)],
        name="employee_latest_punch_in",
    )
    db.attendance_logs.create_index(
        [("date", DESCENDING), ("emp_code", ASCENDING)],
        name="attendance_date_employee",
    )
    db.attendance_logs.create_index(
        [("status", ASCENDING), ("date", DESCENDING), ("emp_code", ASCENDING)],
        name="attendance_status_date_employee",
    )
    db.attendance_logs.create_index(
        [("date", ASCENDING), ("late_minutes", ASCENDING), ("emp_code", ASCENDING)],
        name="attendance_date_late_employee",
    )


def to_datetime(epoch_ms: int) -> datetime:
    return (EPOCH + timedelta(milliseconds=epoch_ms)).replace(microsecond=0)


def truncate_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0)


def epoch_ms(value: Optional[datetime]) -> Optional[int]:
    if value is None:
        return None
    normalized = truncate_datetime(value)
    return int((normalized - EPOCH).total_seconds() * 1000)


def round_half_up(value: float | Decimal, places: int = 2) -> float:
    quantum = Decimal(1).scaleb(-places)
    return float(Decimal(str(value)).quantize(quantum, rounding=ROUND_HALF_UP))


def parse_clock(value: str) -> time:
    hour, minute = (int(part) for part in value.split(":"))
    return time(hour, minute, tzinfo=IST)


def local_datetime(day: date, clock: str) -> datetime:
    hour, minute = (int(part) for part in clock.split(":"))
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=IST)


def attendance_date(punch_in: datetime, employee: dict) -> date:
    local = truncate_datetime(punch_in).astimezone(IST)
    shift_start = parse_clock(employee["shift_start"])
    shift_end = parse_clock(employee["shift_end"])
    day = local.date()
    if shift_end <= shift_start and local.timetz().replace(tzinfo=IST) < shift_end:
        day -= timedelta(days=1)
    return day


def shift_start_for(record_date: date, employee: dict) -> datetime:
    return local_datetime(record_date, employee["shift_start"])


def shift_end_for(record_date: date, employee: dict) -> datetime:
    end = local_datetime(record_date, employee["shift_end"])
    if parse_clock(employee["shift_end"]) <= parse_clock(employee["shift_start"]):
        end += timedelta(days=1)
    return end


def compute_late_minutes(punch_in: datetime, record_date: date, employee: dict) -> int:
    start = shift_start_for(record_date, employee)
    elapsed = int((truncate_datetime(punch_in) - start.astimezone(UTC)).total_seconds())
    return elapsed // 60 if elapsed > 600 else 0


def compute_work_hours(punch_in: datetime, punch_out: datetime) -> float:
    seconds = int((truncate_datetime(punch_out) - truncate_datetime(punch_in)).total_seconds())
    hours = Decimal(seconds) / Decimal(3600)
    return float(hours.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def compute_overtime(punch_out: datetime, record_date: date, employee: dict) -> int:
    end = shift_end_for(record_date, employee).astimezone(UTC)
    seconds = int((truncate_datetime(punch_out) - end).total_seconds())
    return seconds // 60 if seconds >= 1800 else 0


def working_days(start: date, end: date) -> int:
    if start > end:
        return 0
    count = 0
    day = start
    while day <= end:
        if day.weekday() < 5:
            count += 1
        day += timedelta(days=1)
    return count


def month_bounds(month: str) -> tuple[date, date]:
    if not MONTH_PATTERN.fullmatch(month):
        raise HTTPException(422, "month must be YYYY-MM")
    year, month_number = (int(part) for part in month.split("-"))
    try:
        first = date(year, month_number, 1)
        last = date(year, month_number, calendar.monthrange(year, month_number)[1])
    except ValueError as exc:
        raise HTTPException(422, "month is not a valid calendar month") from exc
    return first, last


class EmployeeIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    emp_code: str = Field(pattern=r"^EMP\d{4,6}$")
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(max_length=120, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    department: str = Field(min_length=1, max_length=50)
    shift_start: str = Field(default="09:30", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    shift_end: str = Field(default="18:30", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    joined_on: str
    login_pin: Optional[str] = Field(default=None, min_length=6, max_length=128)

    @field_validator("joined_on")
    @classmethod
    def validate_joined_on(cls, value: str) -> str:
        try:
            if date.fromisoformat(value).isoformat() != value:
                raise ValueError
        except ValueError as exc:
            raise ValueError("joined_on must be YYYY-MM-DD") from exc
        return value

    @model_validator(mode="after")
    def validate_shift(self):
        if self.shift_start == self.shift_end:
            raise ValueError("shift_start and shift_end must differ")
        return self


class PunchInIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    emp_code: str
    punched_at: Optional[Annotated[StrictInt, Field(ge=MIN_EPOCH_MS, le=MAX_EPOCH_MS)]] = None
    status: Literal["PRESENT", "WFH", "ON_DUTY"] = "PRESENT"

    @model_validator(mode="after")
    def reject_null_timestamp(self):
        if "punched_at" in self.model_fields_set and self.punched_at is None:
            raise ValueError("punched_at cannot be null")
        return self


class PunchOutIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    emp_code: str
    punched_at: Optional[Annotated[StrictInt, Field(ge=MIN_EPOCH_MS, le=MAX_EPOCH_MS)]] = None

    @model_validator(mode="after")
    def reject_null_timestamp(self):
        if "punched_at" in self.model_fields_set and self.punched_at is None:
            raise ValueError("punched_at cannot be null")
        return self


class LeaveIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    emp_code: str = Field(pattern=r"^EMP\d{4,6}$")
    date: date


class RegularizeIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: Optional[Literal["PRESENT", "ABSENT", "LEAVE", "WFH", "ON_DUTY"]] = None
    punch_in: Optional[Annotated[StrictInt, Field(ge=MIN_EPOCH_MS, le=MAX_EPOCH_MS)]] = None
    punch_out: Optional[Annotated[StrictInt, Field(ge=MIN_EPOCH_MS, le=MAX_EPOCH_MS)]] = None
    reason: str = Field(min_length=5, max_length=200)
    regularized_by: str = Field(min_length=1, max_length=50)

    @model_validator(mode="after")
    def reject_null_correction_values(self):
        if any(getattr(self, field) is None for field in self.model_fields_set.intersection(
            {"status", "punch_in", "punch_out"}
        )):
            raise ValueError("status and punch times cannot be null")
        return self


def employee_response(document: dict) -> dict:
    return {
        "emp_code": document["emp_code"],
        "name": document["name"],
        "email": document["email"],
        "department": document["department"],
        "shift_start": document["shift_start"],
        "shift_end": document["shift_end"],
        "joined_on": document["joined_on"],
        "created_at": epoch_ms(document["created_at"]),
    }


@app.get("/employee/session")
def employee_session(request: Request):
    employee = authenticated_employee(request)
    return {
        "authenticated": employee is not None,
        "employee": (
            {"emp_code": employee["emp_code"], "name": employee["name"]}
            if employee is not None
            else None
        ),
    }


@app.post("/employee/login")
def employee_login(body: EmployeeLoginIn, request: Request, response: Response):
    employee = db.employees.find_one({"emp_code": body.emp_code, "left_on": {"$exists": False}})
    salt = employee.get("login_pin_salt") if employee is not None else None
    stored_hash = employee.get("login_pin_hash") if employee is not None else None
    supplied_hash = employee_pin_hash(body.pin, salt or "00" * 16)
    if employee is None or not stored_hash or not hmac.compare_digest(supplied_hash, stored_hash):
        raise HTTPException(401, "employee code or PIN is incorrect")
    secret = os.getenv("ADMIN_SESSION_SECRET")
    if not secret:
        raise HTTPException(503, "employee login is not configured")
    expires = int(datetime.now(UTC).timestamp()) + ADMIN_SESSION_SECONDS
    response.set_cookie(
        EMPLOYEE_COOKIE,
        employee_session_token(body.emp_code, expires, stored_hash, secret),
        max_age=ADMIN_SESSION_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "employee": {"emp_code": employee["emp_code"], "name": employee["name"]}}


@app.post("/employee/logout")
def employee_logout(response: Response):
    response.delete_cookie(EMPLOYEE_COOKIE, path="/", httponly=True, samesite="strict")
    return {"authenticated": False, "employee": None}


def attendance_response(document: dict) -> dict:
    return {
        "emp_code": document["emp_code"],
        "date": document["date"],
        "status": document["status"],
        "punch_in": epoch_ms(document.get("punch_in")),
        "punch_out": epoch_ms(document.get("punch_out")),
        "work_hours": document.get("work_hours"),
        "late_minutes": document.get("late_minutes", 0),
        "overtime_minutes": document.get("overtime_minutes", 0),
        "half_day": document.get("half_day", False),
        "history": [
            {
                "at": epoch_ms(entry["at"]),
                "by": entry["by"],
                "reason": entry["reason"],
                "changes": {
                    field: {
                        "from": epoch_ms(change["from"])
                        if field in ("punch_in", "punch_out")
                        else change["from"],
                        "to": epoch_ms(change["to"])
                        if field in ("punch_in", "punch_out")
                        else change["to"],
                    }
                    for field, change in entry["changes"].items()
                },
            }
            for entry in document.get("history", [])
        ],
    }


def monthly_pipeline(emp_code: str, start: date, end: date) -> list[dict]:
    return [
        {"$match": {"emp_code": emp_code, "date": {"$gte": start.isoformat(), "$lte": end.isoformat()}}},
        {
            "$addFields": {
                "_weekday": {
                    "$dayOfWeek": {
                        "$dateFromString": {"dateString": "$date", "format": "%Y-%m-%d", "timezone": "UTC"}
                    }
                }
            }
        },
        {
            "$group": {
                "_id": None,
                "present_days": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$in": ["$status", list(PRESENCE_STATUSES)]},
                                    {"$in": ["$_weekday", [2, 3, 4, 5, 6]]},
                                ]
                            },
                            {"$cond": [{"$ifNull": ["$half_day", False]}, 0.5, 1]},
                            0,
                        ]
                    }
                },
                "leave_days": {"$sum": {"$cond": [{"$eq": ["$status", "LEAVE"]}, 1, 0]}},
                "late_count": {"$sum": {"$cond": [{"$gt": [{"$ifNull": ["$late_minutes", 0]}, 0]}, 1, 0]}},
                "total_late_minutes": {"$sum": {"$ifNull": ["$late_minutes", 0]}},
                "total_overtime_minutes": {"$sum": {"$ifNull": ["$overtime_minutes", 0]}},
            }
        },
        {"$project": {"_id": 0}},
    ]


def department_summary_pipeline(start: date, end: date, department: Optional[str]) -> list[dict]:
    employee_match: dict = {"joined_on": {"$lte": end.isoformat()}}
    employee_match["$or"] = [
        {"left_on": {"$exists": False}},
        {"left_on": {"$gte": start.isoformat()}},
    ]
    if department is not None:
        employee_match["department"] = department
    return [
        {"$match": employee_match},
        {
            "$lookup": {
                "from": "attendance_logs",
                "let": {"employee_code": "$emp_code"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    {"$eq": ["$emp_code", "$$employee_code"]},
                                    {"$gte": ["$date", start.isoformat()]},
                                    {"$lte": ["$date", end.isoformat()]},
                                ]
                            }
                        }
                    },
                    {"$project": {"date": 1, "status": 1, "half_day": 1, "work_hours": 1, "late_minutes": 1}},
                ],
                "as": "logs",
            }
        },
        {"$unwind": {"path": "$logs", "preserveNullAndEmptyArrays": True}},
        {
            "$set": {
                "_has_log": {"$ne": [{"$ifNull": ["$logs.date", None]}, None]},
                "_weekday": {
                    "$dayOfWeek": {
                        "$dateFromString": {
                            "dateString": {"$ifNull": ["$logs.date", "1970-01-01"]},
                            "format": "%Y-%m-%d",
                            "timezone": "UTC",
                        }
                    }
                },
            }
        },
        {
            "$group": {
                "_id": "$department",
                "_employees": {"$addToSet": "$emp_code"},
                "present_days": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    "$_has_log",
                                    {"$in": ["$logs.status", list(PRESENCE_STATUSES)]},
                                    {"$in": ["$_weekday", [2, 3, 4, 5, 6]]},
                                ]
                            },
                            {"$cond": [{"$ifNull": ["$logs.half_day", False]}, 0.5, 1]},
                            0,
                        ]
                    }
                },
                "_hours_sum": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    "$_has_log",
                                    {"$in": ["$logs.status", list(PRESENCE_STATUSES)]},
                                    {"$ne": [{"$ifNull": ["$logs.work_hours", None]}, None]},
                                ]
                            },
                            "$logs.work_hours",
                            0,
                        ]
                    }
                },
                "_hours_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    "$_has_log",
                                    {"$in": ["$logs.status", list(PRESENCE_STATUSES)]},
                                    {"$ne": [{"$ifNull": ["$logs.work_hours", None]}, None]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
                "late_count": {
                    "$sum": {
                        "$cond": [
                            {"$and": ["$_has_log", {"$gt": [{"$ifNull": ["$logs.late_minutes", 0]}, 0]}]},
                            1,
                            0,
                        ]
                    }
                },
                "total_late_minutes": {"$sum": {"$cond": ["$_has_log", {"$ifNull": ["$logs.late_minutes", 0]}, 0]}},
                "leave_count": {
                    "$sum": {"$cond": [{"$and": ["$_has_log", {"$eq": ["$logs.status", "LEAVE"]}]}, 1, 0]}
                },
                "on_duty_count": {
                    "$sum": {"$cond": [{"$and": ["$_has_log", {"$eq": ["$logs.status", "ON_DUTY"]}]}, 1, 0]}
                },
            }
        },
        {
            "$project": {
                "_id": 0,
                "department": "$_id",
                "headcount": {"$size": "$_employees"},
                "present_days": 1,
                "avg_work_hours": {
                    "$cond": [{"$gt": ["$_hours_count", 0]}, {"$divide": ["$_hours_sum", "$_hours_count"]}, None]
                },
                "late_count": 1,
                "total_late_minutes": 1,
                "leave_count": 1,
                "on_duty_count": 1,
            }
        },
        {"$sort": {"department": 1}},
    ]


def leaderboard_pipeline(start: date, end: date, limit: int, department: Optional[str]) -> list[dict]:
    pipeline: list[dict] = [
        {
            "$match": {
                "date": {"$gte": start.isoformat(), "$lte": end.isoformat()},
                "late_minutes": {"$gt": 0},
            }
        },
        {
            "$group": {
                "_id": "$emp_code",
                "total_late_minutes": {"$sum": "$late_minutes"},
                "late_count": {"$sum": 1},
            }
        },
        {
            "$lookup": {
                "from": "employees",
                "localField": "_id",
                "foreignField": "emp_code",
                "as": "employee",
            }
        },
        {"$unwind": "$employee"},
    ]
    if department is not None:
        pipeline.append({"$match": {"employee.department": department}})
    pipeline.extend(
        [
            {
                "$setWindowFields": {
                    "sortBy": {"total_late_minutes": -1},
                    "output": {"rank": {"$rank": {}}},
                }
            },
            {"$match": {"rank": {"$lte": limit}}},
            {"$sort": {"total_late_minutes": -1, "_id": 1}},
            {
                "$project": {
                    "_id": 0,
                    "rank": 1,
                    "emp_code": "$_id",
                    "name": "$employee.name",
                    "department": "$employee.department",
                    "total_late_minutes": 1,
                    "late_count": 1,
                }
            },
        ]
    )
    return pipeline


def department_trend_pipeline(department: str, start: date, end: date) -> list[dict]:
    first = datetime.combine(start, time.min, tzinfo=UTC)
    after_last = datetime.combine(end + timedelta(days=1), time.min, tzinfo=UTC)
    return [
        {"$documents": [{"date": first}]},
        {"$densify": {"field": "date", "range": {"step": 1, "unit": "day", "bounds": [first, after_last]}}},
        {
            "$set": {
                "_day": {"$dateToString": {"date": "$date", "format": "%Y-%m-%d", "timezone": "UTC"}},
                "_weekday": {"$dayOfWeek": "$date"},
                "is_working_day": {"$not": [{"$in": [{"$dayOfWeek": "$date"}, [1, 7]]}]},
            }
        },
        {
            "$lookup": {
                "from": "employees",
                "let": {"day": "$_day"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    {"$eq": ["$department", department]},
                                    {"$lte": ["$joined_on", "$$day"]},
                                    {
                                        "$or": [
                                            {"$eq": [{"$ifNull": ["$left_on", None]}, None]},
                                            {"$gte": ["$left_on", "$$day"]},
                                        ]
                                    },
                                ]
                            }
                        }
                    },
                    {"$project": {"_id": 0, "emp_code": 1}},
                ],
                "as": "_employees",
            }
        },
        {
            "$set": {
                "_employee_codes": {
                    "$map": {"input": "$_employees", "as": "employee", "in": "$$employee.emp_code"}
                },
                "headcount": {"$size": "$_employees"},
            }
        },
        {
            "$lookup": {
                "from": "attendance_logs",
                "let": {"day": "$_day", "employee_codes": "$_employee_codes"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    {"$eq": ["$date", "$$day"]},
                                    {"$in": ["$emp_code", "$$employee_codes"]},
                                ]
                            }
                        }
                    },
                    {"$project": {"_id": 0, "status": 1, "half_day": 1, "late_minutes": 1}},
                ],
                "as": "_logs",
            }
        },
        {
            "$set": {
                "present_count": {
                    "$sum": {
                        "$map": {
                            "input": "$_logs",
                            "as": "log",
                            "in": {
                                "$cond": [
                                    {"$in": ["$$log.status", list(PRESENCE_STATUSES)]},
                                    {"$cond": [{"$ifNull": ["$$log.half_day", False]}, 0.5, 1]},
                                    0,
                                ]
                            },
                        }
                    }
                },
                "late_count": {
                    "$size": {
                        "$filter": {
                            "input": "$_logs",
                            "as": "log",
                            "cond": {"$gt": [{"$ifNull": ["$$log.late_minutes", 0]}, 0]},
                        }
                    }
                },
            }
        },
        {
            "$set": {
                "attendance_rate": {
                    "$cond": [
                        {"$and": ["$is_working_day", {"$gt": ["$headcount", 0]}]},
                        {"$divide": ["$present_count", "$headcount"]},
                        None,
                    ]
                }
            }
        },
        {
            "$setWindowFields": {
                "sortBy": {"date": 1},
                "output": {
                    "moving_avg_7d": {
                        "$avg": "$attendance_rate",
                        "window": {"documents": [-6, 0]},
                    }
                },
            }
        },
        {
            "$project": {
                "_id": 0,
                "date": "$_day",
                "is_working_day": 1,
                "headcount": 1,
                "present_count": 1,
                "late_count": 1,
                "attendance_rate": 1,
                "moving_avg_7d": 1,
            }
        },
        {"$sort": {"date": 1}},
    ]


def run_explain(collection: str, pipeline: Optional[list[dict]] = None, find_query: Optional[dict] = None,
                sort: Optional[dict] = None, skip: int = 0, limit: int = 0, database_aggregate: bool = False) -> dict:
    if find_query is not None:
        operation: dict = {"find": collection, "filter": find_query, "sort": sort or {}}
        if skip:
            operation["skip"] = skip
        if limit:
            operation["limit"] = limit
    else:
        operation = {
            "aggregate": 1 if database_aggregate else collection,
            "pipeline": pipeline or [],
            "cursor": {},
        }
        if database_aggregate:
            operation["allowDiskUse"] = True
    explain = db.command({"explain": operation, "verbosity": "executionStats"})
    return json.loads(json_util.dumps(explain))


@app.get("/health")
def health():
    try:
        client.admin.command("ping")
    except PyMongoError as exc:
        raise HTTPException(503, "MongoDB is unavailable") from exc
    return {"status": "ok"}


@app.post("/employees", status_code=201)
def create_employee(body: EmployeeIn, request: Request):
    require_admin(request)
    document = body.model_dump()
    login_pin = document.pop("login_pin")
    if login_pin:
        salt = secrets.token_hex(16)
        document["login_pin_salt"] = salt
        document["login_pin_hash"] = employee_pin_hash(login_pin, salt)
    document["created_at"] = truncate_datetime(datetime.now(UTC))
    try:
        db.employees.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(409, "emp_code already exists") from exc
    return employee_response(document)


@app.put("/employees/{emp_code}/login-pin", status_code=204)
def set_employee_login_pin(emp_code: str, body: EmployeePinIn, request: Request):
    require_admin(request)
    salt = secrets.token_hex(16)
    result = db.employees.update_one(
        {"emp_code": emp_code, "left_on": {"$exists": False}},
        {"$set": {"login_pin_salt": salt, "login_pin_hash": employee_pin_hash(body.pin, salt)}},
    )
    if result.matched_count == 0:
        raise HTTPException(404, "active employee not found")
    return Response(status_code=204)


@app.get("/employees")
def list_employees(
    department: Optional[str] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
):
    query: dict = {"left_on": {"$exists": False}}
    if department is not None:
        query["department"] = department
    total = db.employees.count_documents(query)
    documents = db.employees.find(query, {"_id": 0}).sort("emp_code", ASCENDING).skip(
        (page - 1) * page_size
    ).limit(page_size)
    return {
        "items": [employee_response(document) for document in documents],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@app.delete("/employees/{emp_code}", status_code=204)
def archive_employee(emp_code: str, request: Request):
    require_admin(request)
    today_ist = datetime.now(UTC).astimezone(IST).date().isoformat()
    result = db.employees.update_one(
        {"emp_code": emp_code, "left_on": {"$exists": False}},
        {"$set": {"left_on": today_ist}},
    )
    if result.matched_count == 0:
        if db.employees.find_one({"emp_code": emp_code}, {"_id": 1}) is None:
            raise HTTPException(404, "employee not found")
        raise HTTPException(409, "employee is already removed")
    return Response(status_code=204)


@app.post("/attendance/punch-in", status_code=201)
def punch_in(body: PunchInIn, request: Request):
    require_punch_access(request, body.emp_code)
    employee = db.employees.find_one({"emp_code": body.emp_code, "left_on": {"$exists": False}})
    if employee is None:
        raise HTTPException(404, "employee not found")
    punched_at = truncate_datetime(to_datetime(body.punched_at) if body.punched_at is not None else datetime.now(UTC))
    day = attendance_date(punched_at, employee)
    document = {
        "emp_code": body.emp_code,
        "date": day.isoformat(),
        "status": body.status,
        "punch_in": punched_at,
        "punch_out": None,
        "work_hours": None,
        "late_minutes": compute_late_minutes(punched_at, day, employee),
        "overtime_minutes": 0,
        "half_day": False,
        "history": [],
    }
    try:
        db.attendance_logs.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(409, "already punched in for this date") from exc
    return attendance_response(document)


@app.post("/attendance/punch-out")
def punch_out(body: PunchOutIn, request: Request):
    require_punch_access(request, body.emp_code)
    employee = db.employees.find_one({"emp_code": body.emp_code})
    if employee is None:
        raise HTTPException(404, "employee not found")
    punched_at = truncate_datetime(to_datetime(body.punched_at) if body.punched_at is not None else datetime.now(UTC))
    record = db.attendance_logs.find_one(
        {"emp_code": body.emp_code, "punch_in": {"$lte": punched_at}},
        sort=[("punch_in", DESCENDING)],
    )
    if record is None:
        raise HTTPException(404, "no punch-in found")
    if record.get("punch_out") is not None:
        raise HTTPException(409, "record is already punched out")
    punch_in_at = truncate_datetime(record["punch_in"])
    duration = (punched_at - punch_in_at).total_seconds()
    if duration <= 0 or duration > 24 * 60 * 60:
        raise HTTPException(422, "punched_at must be after punch_in and within 24 hours")
    record_date = date.fromisoformat(record["date"])
    hours = compute_work_hours(punch_in_at, punched_at)
    update = {
        "$set": {
            "punch_out": punched_at,
            "work_hours": hours,
            "overtime_minutes": compute_overtime(punched_at, record_date, employee),
            "half_day": hours < 4.50,
        }
    }
    current_out = record.get("punch_out")
    guard = {"$exists": False} if "punch_out" not in record else current_out
    updated = db.attendance_logs.find_one_and_update(
        {"_id": record["_id"], "punch_in": record["punch_in"], "punch_out": guard},
        update,
        return_document=ReturnDocument.AFTER,
    )
    if updated is None:
        raise HTTPException(409, "record is already punched out")
    return attendance_response(updated)


@app.get("/attendance")
def list_attendance(
    emp_code: Optional[str] = None,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    status: Optional[Literal["PRESENT", "ABSENT", "LEAVE", "WFH", "ON_DUTY"]] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
):
    if date_from and date_to and date_from > date_to:
        raise HTTPException(422, "date_from must be on or before date_to")
    query: dict = {}
    if emp_code is not None:
        query["emp_code"] = emp_code
    if status is not None:
        query["status"] = status
    if date_from or date_to:
        query["date"] = {}
        if date_from:
            query["date"]["$gte"] = date_from.isoformat()
        if date_to:
            query["date"]["$lte"] = date_to.isoformat()
    total = db.attendance_logs.count_documents(query)
    documents = db.attendance_logs.find(query).sort(
        [("date", DESCENDING), ("emp_code", ASCENDING)]
    ).skip((page - 1) * page_size).limit(page_size)
    return {
        "items": [attendance_response(document) for document in documents],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@app.post("/attendance/leave", status_code=201)
def mark_leave(body: LeaveIn, request: Request):
    require_admin(request)
    employee = db.employees.find_one({"emp_code": body.emp_code, "left_on": {"$exists": False}})
    if employee is None:
        raise HTTPException(404, "active employee not found")
    if body.date < date.fromisoformat(employee["joined_on"]):
        raise HTTPException(422, "leave date cannot be before the employee's start date")

    document = {
        "emp_code": body.emp_code,
        "date": body.date.isoformat(),
        "status": "LEAVE",
        "punch_in": None,
        "punch_out": None,
        "work_hours": None,
        "late_minutes": 0,
        "overtime_minutes": 0,
        "half_day": False,
        "history": [],
    }
    try:
        db.attendance_logs.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(409, "attendance already exists for this employee and date") from exc
    return attendance_response(document)


@app.patch("/attendance/{emp_code}/{date}")
def regularize_attendance(emp_code: str, date: date, body: RegularizeIn, request: Request):
    require_admin(request)
    date_text = date.isoformat()
    employee = db.employees.find_one({"emp_code": emp_code})
    if employee is None:
        raise HTTPException(404, "employee not found")
    record = db.attendance_logs.find_one({"emp_code": emp_code, "date": date_text})
    if record is None:
        raise HTTPException(404, "attendance record not found")

    supplied = body.model_fields_set
    if body.status in ("ABSENT", "LEAVE") and supplied.intersection({"punch_in", "punch_out"}):
        raise HTTPException(422, "ABSENT and LEAVE cannot be supplied with punch times")

    old_status = record["status"]
    old_in = truncate_datetime(record["punch_in"]) if record.get("punch_in") is not None else None
    old_out = truncate_datetime(record["punch_out"]) if record.get("punch_out") is not None else None
    new_status = body.status if "status" in supplied else old_status
    new_in = truncate_datetime(to_datetime(body.punch_in)) if "punch_in" in supplied else old_in
    new_out = truncate_datetime(to_datetime(body.punch_out)) if "punch_out" in supplied else old_out

    if new_status in ("ABSENT", "LEAVE"):
        new_in = None
        new_out = None
    else:
        if new_in is None:
            raise HTTPException(422, "presence status requires punch_in")
        if attendance_date(new_in, employee).isoformat() != date_text:
            raise HTTPException(422, "punch_in must belong to the record's attendance date")
        if new_out is not None:
            elapsed = (new_out - new_in).total_seconds()
            if elapsed <= 0 or elapsed > 24 * 60 * 60:
                raise HTTPException(422, "punch_out must be after punch_in and within 24 hours")

    new_late = compute_late_minutes(new_in, date, employee) if new_in is not None else 0
    new_hours = compute_work_hours(new_in, new_out) if new_in is not None and new_out is not None else None
    new_overtime = (
        compute_overtime(new_out, date, employee) if new_in is not None and new_out is not None else 0
    )
    new_half_day = new_hours < 4.50 if new_hours is not None else False

    previous = {
        "status": old_status,
        "punch_in": old_in,
        "punch_out": old_out,
        "work_hours": record.get("work_hours"),
        "late_minutes": record.get("late_minutes", 0),
        "overtime_minutes": record.get("overtime_minutes", 0),
        "half_day": record.get("half_day", False),
    }
    current = {
        "status": new_status,
        "punch_in": new_in,
        "punch_out": new_out,
        "work_hours": new_hours,
        "late_minutes": new_late,
        "overtime_minutes": new_overtime,
        "half_day": new_half_day,
    }
    changes = {
        key: {
            "from": epoch_ms(previous[key]) if key in ("punch_in", "punch_out") else previous[key],
            "to": epoch_ms(current[key]) if key in ("punch_in", "punch_out") else current[key],
        }
        for key in current
        if previous[key] != current[key]
    }
    if not changes:
        raise HTTPException(422, "request does not change the record")

    history = record.get("history", [])
    history_entry = {
        "at": truncate_datetime(datetime.now(UTC)),
        "by": body.regularized_by,
        "reason": body.reason,
        "changes": changes,
    }
    update = {
        "$set": {
            "status": new_status,
            "punch_in": new_in,
            "punch_out": new_out,
            "work_hours": new_hours,
            "late_minutes": new_late,
            "overtime_minutes": new_overtime,
            "half_day": new_half_day,
        },
        "$push": {"history": history_entry},
    }
    query: dict = {
        "_id": record["_id"],
        "status": old_status,
        "history": history if "history" in record else {"$exists": False},
    }
    for field in ("punch_in", "punch_out"):
        query[field] = record[field] if field in record else {"$exists": False}
    updated = db.attendance_logs.find_one_and_update(
        query,
        update,
        return_document=ReturnDocument.AFTER,
    )
    if updated is None:
        raise HTTPException(409, "record changed concurrently; retry the correction")
    return attendance_response(updated)


@app.get("/analytics/employees/{emp_code}/monthly")
def employee_monthly(emp_code: str, month: Annotated[str, Query(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")]):
    start, end = month_bounds(month)
    employee = db.employees.find_one({"emp_code": emp_code}, {"_id": 0, "joined_on": 1})
    if employee is None:
        raise HTTPException(404, "employee not found")
    result = next(db.attendance_logs.aggregate(monthly_pipeline(emp_code, start, end)), {})
    joined = date.fromisoformat(employee["joined_on"])
    workdays = working_days(max(start, joined), end)
    present_days = float(result.get("present_days", 0))
    attendance_pct = round_half_up(Decimal(str(present_days)) * 100 / workdays, 4) if workdays else None
    return {
        "emp_code": emp_code,
        "month": month,
        "working_days": workdays,
        "present_days": round_half_up(present_days),
        "leave_days": int(result.get("leave_days", 0)),
        "late_count": int(result.get("late_count", 0)),
        "total_late_minutes": int(result.get("total_late_minutes", 0)),
        "total_overtime_minutes": int(result.get("total_overtime_minutes", 0)),
        "attendance_pct": attendance_pct,
    }


@app.get("/analytics/departments/summary")
def department_summary(
    month: Annotated[str, Query(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")],
    department: Optional[str] = None,
):
    start, end = month_bounds(month)
    rows = list(db.employees.aggregate(department_summary_pipeline(start, end, department)))
    for row in rows:
        row["present_days"] = round_half_up(row["present_days"])
        row["avg_work_hours"] = (
            round_half_up(row["avg_work_hours"]) if row["avg_work_hours"] is not None else None
        )
    return {"month": month, "items": rows}


@app.get("/analytics/leaderboard/late")
def late_leaderboard(
    month: Annotated[str, Query(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
    department: Optional[str] = None,
):
    start, end = month_bounds(month)
    items = list(db.attendance_logs.aggregate(leaderboard_pipeline(start, end, limit, department)))
    for item in items:
        item["rank"] = int(item["rank"])
        item["total_late_minutes"] = int(item["total_late_minutes"])
        item["late_count"] = int(item["late_count"])
    return {"month": month, "items": items}


@app.get("/analytics/departments/{department}/trend")
def department_trend(department: str, from_date: date = Query(alias="from"), to_date: date = Query(alias="to")):
    if to_date < from_date:
        raise HTTPException(422, "to must be on or after from")
    if (to_date - from_date).days + 1 > 92:
        raise HTTPException(422, "date range cannot exceed 92 days")
    if db.employees.find_one({"department": department}, {"_id": 1}) is None:
        raise HTTPException(404, "department not found")
    rows = list(
        db.aggregate(
            department_trend_pipeline(department, from_date, to_date),
            allowDiskUse=True,
        )
    )
    for row in rows:
        row["present_count"] = round_half_up(row["present_count"])
        row["attendance_rate"] = (
            round_half_up(row["attendance_rate"], 4) if row["attendance_rate"] is not None else None
        )
        row["moving_avg_7d"] = (
            round_half_up(row["moving_avg_7d"], 4) if row["moving_avg_7d"] is not None else None
        )
    return {"department": department, "items": rows}


@app.get("/admin/explain/{endpoint}")
def explain_endpoint(
    endpoint: Literal[
        "attendance_list",
        "employee_monthly",
        "department_summary",
        "late_leaderboard",
        "department_trend",
    ],
    emp_code: Optional[str] = None,
    month: Optional[str] = Query(default=None, pattern=r"^\d{4}-(0[1-9]|1[0-2])$"),
    department: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    status: Optional[Literal["PRESENT", "ABSENT", "LEAVE", "WFH", "ON_DUTY"]] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    from_date: Optional[date] = Query(default=None, alias="from"),
    to_date: Optional[date] = Query(default=None, alias="to"),
):
    if endpoint == "attendance_list":
        if date_from and date_to and date_from > date_to:
            raise HTTPException(422, "date_from must be on or before date_to")
        query: dict = {}
        if emp_code is not None:
            query["emp_code"] = emp_code
        if status is not None:
            query["status"] = status
        if date_from or date_to:
            query["date"] = {}
            if date_from:
                query["date"]["$gte"] = date_from.isoformat()
            if date_to:
                query["date"]["$lte"] = date_to.isoformat()
        explain = run_explain(
            "attendance_logs",
            find_query=query,
            sort={"date": -1, "emp_code": 1},
            skip=(page - 1) * page_size,
            limit=page_size,
        )
        collection = "attendance_logs"
    elif endpoint == "employee_monthly":
        if emp_code is None or month is None:
            raise HTTPException(422, "emp_code and month are required")
        start, end = month_bounds(month)
        explain = run_explain("attendance_logs", monthly_pipeline(emp_code, start, end))
        collection = "attendance_logs"
    elif endpoint == "department_summary":
        if month is None:
            raise HTTPException(422, "month is required")
        start, end = month_bounds(month)
        explain = run_explain("employees", department_summary_pipeline(start, end, department))
        collection = "employees"
    elif endpoint == "late_leaderboard":
        if month is None:
            raise HTTPException(422, "month is required")
        start, end = month_bounds(month)
        explain = run_explain(
            "attendance_logs",
            leaderboard_pipeline(start, end, limit, department),
        )
        collection = "attendance_logs"
    else:
        if department is None or from_date is None or to_date is None:
            raise HTTPException(422, "department, from and to are required")
        if to_date < from_date or (to_date - from_date).days + 1 > 92:
            raise HTTPException(422, "invalid trend date range")
        explain = run_explain(
            "1",
            department_trend_pipeline(department, from_date, to_date),
            database_aggregate=True,
        )
        collection = "attendance_logs"
    return {"endpoint": endpoint, "collection": collection, "explain": explain}
