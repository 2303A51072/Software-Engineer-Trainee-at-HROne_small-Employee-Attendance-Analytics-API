# Employee Attendance & Analytics API

FastAPI and MongoDB implementation of the assignment contract in `openapi.yaml`. All application code is in
`app/main.py`; MongoDB 6.0 or newer is required.

## Run locally

1. Install Python 3.11+ and MongoDB 6.0+ (or use MongoDB Atlas).
2. Install dependencies: `pip install -r requirements.txt`
3. Set `MONGO_URI` and, optionally, `MONGO_DB` in the process environment. Configure admin access with
   `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and a long random `ADMIN_SESSION_SECRET` (at least 32 random bytes).
   For local use, put these values in a `.env` file in this directory; `.env` is ignored by Git.
4. From this directory, seed the sample records with `python sample_seed.py` (optional), then start:
   `uvicorn app.main:app --port 8000`

The API creates its indexes at startup. `GET /health` checks MongoDB availability. No `.env` file or database secrets are
included. The implementation covers the contracted employee and attendance operations, corrections and audit history,
analytics aggregations, and query explain endpoint.

The responsive attendance dashboard is available at `http://localhost:8000/` after starting the API. It provides a
today-at-a-glance breakdown, team attendance, department analytics, and late-arrival rankings with total time late.
Unrecorded attendance is shown separately from employees explicitly marked absent. Export any selected month's attendance
records to CSV, including local IST punch times and calculated durations; the export retrieves all pages for the month.
Sign in as admin to use punch-in/out, correct records, and mark an employee on leave for a selected date. Employee
creation and employee removal are also available to admins. Removed employees are archived from the active roster while
their attendance records and correction history remain available. Shift schedules are shown on the roster and punch
selector. Corrections are written to the audit history. Write endpoints return `401` when not signed in. Admin sessions
are HTTP-only, same-site cookies that expire after eight hours. The interactive API documentation remains available at
`http://localhost:8000/docs`.
