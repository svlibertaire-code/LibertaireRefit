# Refit App — Security Fixes & UI Improvements

## Security Fixes

### 1. Move old SQLite database to backup
- **File:** `/opt/refit/refit.db` (57KB, stale from pre-PostgreSQL migration)
- **Action:** `mkdir -p /opt/refit/backups && mv /opt/refit/refit.db /opt/refit/backups/`
- **Risk:** Low — stale data, but unnecessary attack surface

### 2. Verify systemd service picks up changes cleanly
- **Action:** `systemctl restart refit`
- **Verify:** `curl -k https://localhost:8080/login` returns HTTP 200

## UI Improvements Already Applied

### 3. ✅ Dashboard overall progress bar
- **Status:** DONE — Added percentage of "Done" tasks with visual progress bar
- **Code:** `overall_pct = int((c.get('Done', 0) / total_tasks) * 100)`

### 4. ✅ Tasks page search filter
- **Status:** DONE — Added client-side search box above filters
- **Code:** `filterTasks()` JavaScript function

## UI Improvements Remaining

### 5. Add search to Inventory/Gear page
- **File:** `/opt/refit/refit_app.py`, inventory route (~line 1034)
- **Pattern:** Same as tasks page — search box + JS filter function
- **Fields to search:** item name, reference, notes, compartment, system

### 6. Add relative timestamps to task cards
- **File:** `/opt/refit/refit_app.py`, tasks route (~line 494)
- **Pattern:** Same as BikeSpares — "Updated 2h ago", "3 days ago"
- **Data:** Use `t['updated_at']` from tasks table

### 7. Add delete confirmation modal
- **File:** `/opt/refit/refit_app.py`, task detail page (~line 733)
- **Pattern:** Same themed modal as BikeSpares (dark background, red confirm button)
- **Apply to:** Task delete, inventory item delete

### 8. Verify no duplicate JavaScript functions
- **Check:** `filterTasks()` should appear exactly once in the file
- **Fix:** Remove any duplicate if found

## Testing Checklist

- [ ] Dashboard shows overall progress bar correctly
- [ ] Task search filters live without page reload
- [ ] Inventory search works (after implementation)
- [ ] Relative timestamps display correctly
- [ ] Delete modal appears before removing items
- [ ] No 500 errors on any page
- [ ] Mobile layout still works (responsive)

## Notes

- Dark theme must be preserved throughout
- All changes are in `refit_app.py` (single-file app, no templates directory)
- Service runs via systemd on port 8080 with self-signed SSL
- PostgreSQL backend with RealDictCursor
