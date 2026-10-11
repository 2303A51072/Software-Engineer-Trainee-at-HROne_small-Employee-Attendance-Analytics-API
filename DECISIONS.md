# DECISIONS.md

1. **Indexes.** `employee_code_unique` protects employee identity. `department_joined` supports department headcount filters, and `employee_joined` supports month-end eligibility when no department is specified. `employee_date_unique` guarantees one attendance document per employee/day and supports employee-month queries; `employee_latest_punch_in` finds the latest punch efficiently. The date/employee and status/date/employee indexes support attendance listing; date/late/employee supports late-log queries. I considered a separate email index but rejected it because this contract has no email lookup.

2. **Punch-in race.** Both requests may read the employee and calculate the same attendance date. MongoDB's unique `(emp_code, date)` index serializes the inserts: one succeeds and returns 201; the other gets `DuplicateKeyError`, which the API maps to 409.

3. **Ties.** `$rank` gives tied totals the same competition rank. The pipeline filters by `rank <= limit`, so it returns all tied employees at the cutoff, sorted by late minutes and then employee code.

4. **Headcount.** The summary starts with eligible employees and left-looks-up attendance, preserving employees with no logs. It groups by department and deduplicates employee codes for headcount.

5. **100x data.** I would benchmark the real workload, review index selectivity and working-set size, then consider pre-aggregated daily summaries for analytics while retaining the raw attendance records as the source of truth.
