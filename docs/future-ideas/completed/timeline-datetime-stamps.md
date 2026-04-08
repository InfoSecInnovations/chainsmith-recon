Timeline Visualization — Date/Time Stamps
==========================================
Captured 2026-04-08.

Status: Pending

Problem
-------
The timeline visualization currently lacks visible date/time stamps,
making it difficult to correlate events with when they actually occurred.

Proposed Change
---------------
Add human-readable date/time stamps to the timeline visualization so
users can see exactly when each event happened. Timestamps should be
visible inline or on hover, and respect the user's locale/timezone
preferences.

Considerations
--------------
- Determine whether timestamps appear inline or on hover (or both).
- Long-running scans may span hours; ensure the time axis scales well.
- Consider relative ("2 min ago") vs. absolute ("14:32:07") display,
  or both.
