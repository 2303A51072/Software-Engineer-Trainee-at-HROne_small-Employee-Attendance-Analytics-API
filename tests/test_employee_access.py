import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, Response

os.environ["ADMIN_USERNAME"] = "test-admin"
os.environ["ADMIN_PASSWORD"] = "test-password"
os.environ["ADMIN_SESSION_SECRET"] = "test-session-secret-that-is-long-enough"

from app import main


class FakeEmployees:
    def __init__(self):
        salt = "12" * 16
        self.documents = {
            "EMP0001": {
                "emp_code": "EMP0001",
                "name": "Asha Rao",
                "email": "asha@example.com",
                "department": "Engineering",
                "shift_start": "09:30",
                "shift_end": "18:30",
                "joined_on": "2026-01-05",
                "login_pin_salt": salt,
                "login_pin_hash": main.employee_pin_hash("secret1", salt),
            },
            "EMP0002": {
                "emp_code": "EMP0002",
                "name": "Vikram Shah",
                "email": "vikram@example.com",
                "department": "Engineering",
                "shift_start": "09:30",
                "shift_end": "18:30",
                "joined_on": "2026-07-13",
                "login_pin_salt": salt,
                "login_pin_hash": main.employee_pin_hash("secret2", salt),
            },
        }

    def find_one(self, query, projection=None):
        employee = self.documents.get(query["emp_code"])
        if employee is None or ("left_on" in query and "left_on" in employee):
            return None
        return employee

    def update_one(self, query, update):
        employee = self.documents.get(query["emp_code"])
        if employee is None:
            return type("Result", (), {"matched_count": 0})()
        employee.update(update["$set"])
        return type("Result", (), {"matched_count": 1})()

    def insert_one(self, document):
        self.documents[document["emp_code"]] = document


class FakeAttendance:
    def __init__(self):
        self.documents = []

    def insert_one(self, document):
        if any(
            row["emp_code"] == document["emp_code"] and row["date"] == document["date"]
            for row in self.documents
        ):
            raise main.DuplicateKeyError("duplicate")
        self.documents.append(document)


class FakeDatabase:
    def __init__(self):
        self.employees = FakeEmployees()
        self.attendance_logs = FakeAttendance()


class EmployeeAccessTests(unittest.TestCase):
    def setUp(self):
        self.database = FakeDatabase()
        self.database_patcher = patch.object(main, "db", self.database)
        self.database_patcher.start()
        self.employee_request = self.request()

    def tearDown(self):
        self.database_patcher.stop()

    @staticmethod
    def request(cookies=None):
        return SimpleNamespace(cookies=cookies or {}, url=SimpleNamespace(scheme="http"))

    def test_employee_can_sign_in_and_punch_only_for_self(self):
        result = main.employee_login(
            main.EmployeeLoginIn(emp_code="EMP0001", pin="secret1"),
            self.employee_request,
            Response(),
        )
        self.assertEqual(result["employee"]["emp_code"], "EMP0001")
        self.employee_request.cookies[main.EMPLOYEE_COOKIE] = main.employee_session_token(
            "EMP0001",
            int(datetime.now(timezone.utc).timestamp()) + main.ADMIN_SESSION_SECONDS,
            self.database.employees.documents["EMP0001"]["login_pin_hash"],
            os.environ["ADMIN_SESSION_SECRET"],
        )

        own_punch = main.punch_in(main.PunchInIn(emp_code="EMP0001"), self.employee_request)
        self.assertEqual(own_punch["emp_code"], "EMP0001")

        with self.assertRaises(HTTPException) as error:
            main.punch_in(main.PunchInIn(emp_code="EMP0002"), self.employee_request)
        self.assertEqual(error.exception.status_code, 401)
        self.assertEqual(len(self.database.attendance_logs.documents), 1)

    def test_invalid_pin_and_unsigned_punch_are_rejected(self):
        with self.assertRaises(HTTPException) as error:
            main.employee_login(
                main.EmployeeLoginIn(emp_code="EMP0001", pin="incorrect"),
                self.employee_request,
                Response(),
            )
        self.assertEqual(error.exception.status_code, 401)

        with self.assertRaises(HTTPException) as error:
            main.punch_in(main.PunchInIn(emp_code="EMP0001"), self.employee_request)
        self.assertEqual(error.exception.status_code, 401)
        self.assertEqual(self.database.attendance_logs.documents, [])

    def test_changing_pin_revokes_existing_employee_session(self):
        old_hash = self.database.employees.documents["EMP0001"]["login_pin_hash"]
        self.employee_request.cookies[main.EMPLOYEE_COOKIE] = main.employee_session_token(
            "EMP0001",
            int(datetime.now(timezone.utc).timestamp()) + main.ADMIN_SESSION_SECONDS,
            old_hash,
            os.environ["ADMIN_SESSION_SECRET"],
        )
        admin_request = self.request(
            {
                main.ADMIN_COOKIE: main.admin_session_token(
                    "test-admin",
                    int(datetime.now(timezone.utc).timestamp()) + main.ADMIN_SESSION_SECONDS,
                    os.environ["ADMIN_SESSION_SECRET"],
                )
            }
        )

        update = main.set_employee_login_pin("EMP0001", main.EmployeePinIn(pin="newpin1"), admin_request)
        self.assertEqual(update.status_code, 204)
        self.assertFalse(main.employee_session(self.employee_request)["authenticated"])

        re_login = main.employee_login(
            main.EmployeeLoginIn(emp_code="EMP0001", pin="newpin1"),
            self.employee_request,
            Response(),
        )
        self.assertEqual(re_login["employee"]["emp_code"], "EMP0001")

    def test_admin_created_employee_stores_only_a_salted_pin_hash(self):
        admin_request = self.request(
            {
                main.ADMIN_COOKIE: main.admin_session_token(
                    "test-admin",
                    int(datetime.now(timezone.utc).timestamp()) + main.ADMIN_SESSION_SECONDS,
                    os.environ["ADMIN_SESSION_SECRET"],
                )
            }
        )
        employee = main.create_employee(
            main.EmployeeIn(
                emp_code="EMP0003",
                name="Neha Iyer",
                email="neha@example.com",
                department="Sales",
                joined_on="2026-02-01",
                login_pin="secret3",
            ),
            admin_request,
        )
        stored = self.database.employees.documents["EMP0003"]
        self.assertEqual(employee["emp_code"], "EMP0003")
        self.assertNotIn("login_pin", employee)
        self.assertNotIn("secret3", str(stored))
        self.assertEqual(
            stored["login_pin_hash"],
            main.employee_pin_hash("secret3", stored["login_pin_salt"]),
        )


if __name__ == "__main__":
    unittest.main()
