Reports Directory — Prevent Overwrite of Saved Reports
=======================================================
Captured 2026-04-08.

Status: Pending

Problem
-------
Currently, generating a new report can overwrite previously saved
reports. There is no dedicated reports directory with versioning or
timestamped filenames to preserve historical output.

Proposed Change
---------------
Set up a dedicated reports/ directory. Each report should be saved
with a unique, timestamped filename (e.g. report_2026-04-08_143207.html)
so that new runs never stomp on previous results.

Considerations
--------------
- Naming convention: include target, date/time, and scan profile.
- Add a reports index or listing page so users can browse past reports.
- Consider a configurable retention policy or max-reports limit.
- Ensure .gitignore excludes the reports directory from version control.
