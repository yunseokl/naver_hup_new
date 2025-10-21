# Flask Application Template & Routes Audit Report
**Application:** Naver HUP (네이버 광고 슬롯 관리 시스템)  
**Location:** /home/user/naver_hup_new  
**Audit Date:** 2024  
**Thoroughness Level:** Very Thorough

---

## EXECUTIVE SUMMARY

The Flask application has **3 critical issues** that will cause runtime errors:
- 1 broken link reference (missing endpoint)
- 2 missing template files

The application also has **7 unused API routes** that should be reviewed for deprecation.

**Status:** 2 Critical Issues | 2 Best Practice Warnings | 5 Code Quality Concerns

---

## CRITICAL ISSUES (Must Fix)

### ISSUE 1: Broken Link - Missing Route Endpoint
**Severity:** CRITICAL  
**Status:** Not Deployed

**File:** `/home/user/naver_hup_new/templates/downloads/index.html`  
**Line:** 43  

**Current Code:**
```html
<a href="{{ url_for('download_project_zip') }}" class="btn btn-primary btn-lg">
    <i data-feather="download" class="me-2"></i> 다운로드
</a>
```

**Issue:** References endpoint `'download_project_zip'` which does not exist in `app.py`

**Error When Triggered:**
```
werkzeug.routing.exceptions.BuildError: Could not build url for endpoint 'download_project_zip' with values {}
```

**Root Cause:** The endpoint is referenced in the template but the corresponding route is not implemented in `app.py`

**Solution (Choose One):**

**Option A - Implement the missing route (Recommended if feature is needed):**
```python
@app.route('/download-project-zip')
def download_project_zip():
    """Download the entire project as a ZIP file"""
    # Implementation here
    pass
```

**Option B - Remove the template if feature is not needed:**
```bash
rm /home/user/naver_hup_new/templates/downloads/index.html
```

**Option C - Change link to existing endpoint (Temporary fix):**
```html
<a href="{{ url_for('index') }}" class="btn btn-primary btn-lg">
    <i data-feather="download" class="me-2"></i> 다운로드
</a>
```

---

### ISSUE 2: Missing Template File - agency/upload_shopping_slots.html
**Severity:** CRITICAL  
**Impact:** Accessing `/shopping-slots/upload` route will fail

**Route Definition in app.py:**
```
File: /home/user/naver_hup_new/app.py
Line: 2910-2912
Route: @app.route('/shopping-slots/upload', methods=['GET', 'POST'])
Endpoint Name: upload_shopping_slots
```

**Template Reference in app.py:**
```
File: /home/user/naver_hup_new/app.py
Line: 3016
Code: return render_template('agency/upload_shopping_slots.html')
```

**Expected File Location:** `/home/user/naver_hup_new/templates/agency/upload_shopping_slots.html`  
**File Status:** DOES NOT EXIST

**Error When Triggered:**
```
jinja2.exceptions.TemplateNotFound: agency/upload_shopping_slots.html
```

**Solution:** Create the missing template file:
1. Create `/home/user/naver_hup_new/templates/agency/upload_shopping_slots.html`
2. Follow the same structure as `agency/create_shopping_slot.html`
3. Include file upload form elements for bulk slot uploads

**Example Template Structure:**
```html
{% extends 'layout.html' %}

{% block title %}쇼핑 슬롯 일괄 업로드{% endblock %}

{% block content %}
<div class="container mt-4">
    <h2>쇼핑 슬롯 일괄 업로드</h2>
    
    <div class="card">
        <div class="card-body">
            <form method="POST" enctype="multipart/form-data" action="{{ url_for('upload_shopping_slots') }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="mb-3">
                    <label for="file" class="form-label">엑셀 파일 업로드</label>
                    <input type="file" class="form-control" id="file" name="file" accept=".xlsx,.xls" required>
                </div>
                <button type="submit" class="btn btn-primary">업로드</button>
            </form>
        </div>
    </div>
</div>
{% endblock %}
```

---

### ISSUE 3: Missing Template File - agency/upload_place_slots.html
**Severity:** CRITICAL  
**Impact:** Accessing `/place-slots/upload` route will fail

**Route Definition in app.py:**
```
File: /home/user/naver_hup_new/app.py
Line: 3387-3389
Route: @app.route('/place-slots/upload', methods=['GET', 'POST'])
Endpoint Name: upload_place_slots
```

**Template Reference in app.py:**
```
File: /home/user/naver_hup_new/app.py
Line: 3498
Code: return render_template('agency/upload_place_slots.html')
```

**Expected File Location:** `/home/user/naver_hup_new/templates/agency/upload_place_slots.html`  
**File Status:** DOES NOT EXIST

**Error When Triggered:**
```
jinja2.exceptions.TemplateNotFound: agency/upload_place_slots.html
```

**Solution:** Create the missing template file:
1. Create `/home/user/naver_hup_new/templates/agency/upload_place_slots.html`
2. Follow the same structure as `agency/create_place_slot.html`
3. Include file upload form elements for bulk place slot uploads

---

## BEST PRACTICE WARNINGS

### WARNING 1: Forms Without Explicit Action Attributes
**Severity:** LOW  
**Category:** Code Quality / Best Practice

These forms work correctly but lack explicit action attributes for clarity.

**File 1:** `/home/user/naver_hup_new/templates/refund/request_shopping_refund.html`  
**Line:** 58

**Current Code:**
```html
<form method="post" class="mt-4">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

**Issue:** Form lacks explicit action attribute. While this defaults to POST to the current URL (which works), it's better practice to explicitly specify the action.

**Current Behavior:** POSTs to `/refund/shopping-slot/<slot_id>` (correct by default)  
**Recommended Fix:**
```html
<form method="post" action="{{ url_for('request_shopping_slot_refund', slot_id=slot.id) }}" class="mt-4">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

---

**File 2:** `/home/user/naver_hup_new/templates/refund/request_place_refund.html`  
**Line:** 58

**Current Code:**
```html
<form method="post" class="mt-4">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

**Recommended Fix:**
```html
<form method="post" action="{{ url_for('request_place_slot_refund', slot_id=slot.id) }}" class="mt-4">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

---

### WARNING 2: GET Forms Without Explicit Action Attributes
**Severity:** LOW  
**Category:** Code Quality / Best Practice  
**Status:** ACCEPTABLE (These are filter/search forms)

These GET forms lack explicit action attributes but follow an acceptable pattern for filter forms.

**File 1:** `/home/user/naver_hup_new/templates/admin/settlements.html`  
**Line:** 20  
**Purpose:** Filtering form  
**Current Behavior:** Correctly submits to same URL for filtering  
**Current Code:**
```html
<form class="row g-3" method="GET">
    <div class="col-md-5">
        <select class="form-select" id="filter-period" name="period">
            ...
        </select>
    </div>
    ...
</form>
```

**File 2:** `/home/user/naver_hup_new/templates/admin/refunds.html`  
**Line:** 28  
**Purpose:** Filtering form  
**Current Behavior:** Correctly submits to same URL for filtering  
**Current Code:**
```html
<form method="get" class="row g-3">
    <div class="col-md-3">
        <select class="form-select" id="status" name="status">
            ...
        </select>
    </div>
    ...
</form>
```

**Note:** These are standard patterns for filter forms and work correctly. No fix required.

---

## CODE QUALITY CONCERNS

### CONCERN 1: Unused/Undocumented API Routes
**Severity:** MEDIUM  
**Category:** Code Maintenance

These routes are defined in `app.py` but are not referenced in any templates or shown in any redirects. They may be:
- Legacy/deprecated endpoints no longer in use
- Internal API endpoints used by external systems
- Endpoints that should be removed

**Unused Routes:**

| Endpoint | Route | Purpose |
|----------|-------|---------|
| `toggle_slot` | `/distributor/toggle-slot/<int:slot_id>` | Appears to toggle slot state |
| `select_shopping_slot` | `/shopping-slots/select/<int:slot_id>` | Selection functionality |
| `save_slot_api` | `/api/save-slot` (POST) | Internal API endpoint |
| `save_slots_bulk_api` | `/api/save-slots-bulk` (POST) | Bulk save API |
| `toggle_slot_api` | `/api/toggle-slot` (POST) | Toggle API endpoint |
| `admin_bulk_approve` | `/admin/bulk-approve` (POST) | Bulk approval |
| `page_not_found` | Error handler | 404 page |

**Recommendation:**
1. Document which routes are intended for internal use vs. external API
2. Remove routes that are no longer needed
3. Update templates to use API endpoints if they should be active
4. Add comments to routes explaining their purpose

---

## VERIFICATION RESULTS

### PASSED CHECKS
- ✓ All `url_for()` calls reference valid routes (except `download_project_zip`)
- ✓ No hardcoded URLs found in `href` attributes
- ✓ No hardcoded URLs found in form `action` attributes
- ✓ No circular redirect patterns detected
- ✓ All template inheritance is valid (`{% extends 'layout.html' %}`)
- ✓ All template includes are valid (`{% include 'admin/sidebar.html' %}`)
- ✓ Navigation links in `layout.html` are all valid
- ✓ Navigation links in `admin/sidebar.html` are all valid
- ✓ All form action attributes that are specified are correct

### FAILED CHECKS
- ✗ 1 broken link endpoint (`download_project_zip`)
- ✗ 2 missing template files
- ✗ 5 unused routes (need review)

---

## ENDPOINT SUMMARY

**Total Routes Defined:** 67  
**Total Endpoints Used in Templates:** 63  
**Endpoints Used in Redirects:** 4  
**Unused/Unknown Endpoints:** 7  

### Routes by Functional Category:

**Authentication (4)**
- `login` - User login
- `logout` - User logout  
- `register` - User registration
- `admin_register` - Admin user registration

**Admin Dashboard (1)**
- `admin_dashboard` - Admin dashboard view

**Admin Users (2)**
- `users` - User management list
- `approve_user` - Approve/reject user registration

**Admin Approvals (2)**
- `admin_approvals` - View pending slot approvals
- `admin_approve_request` - Approve/reject slot approval

**Admin Shopping Slots (5)**
- `admin_shopping_slots` - List shopping slots
- `admin_create_shopping_slot` - Create new shopping slot
- `admin_edit_shopping_slot` - Edit shopping slot
- `admin_delete_shopping_slot` - Delete shopping slot
- `admin_shopping_slots` - Paginated list view

**Admin Place Slots (5)**
- `admin_place_slots` - List place slots
- `admin_create_place_slot` - Create new place slot
- `admin_edit_place_slot` - Edit place slot
- `admin_delete_place_slot` - Delete place slot
- `admin_place_slots` - Paginated list view

**Admin Settlements (3)**
- `admin_settlements` - View settlements
- `admin_settlement_detail` - Settlement details
- `admin_settlement_action` - Process settlement action

**Admin Refunds (2)**
- `admin_refunds` - View refund requests
- `admin_approve_refund` - Approve/reject refund

**Distributor Dashboard (1)**
- `distributor_dashboard` - Distributor dashboard

**Distributor Management (2)**
- `distributor_agencies` - View managed agencies
- `request_slot_quota` - Request slot quota

**Distributor Slots (5)**
- `distributor_slots` - List distributor slots (shopping/place)
- `create_distributor_slot` - Create slot for agency
- `delete_distributor_slot` - Delete slot
- `upload_distributor_slots` - Bulk upload slots
- `export_slots` - Export slot template

**Distributor Approvals (2)**
- `distributor_approvals` - View quota approvals
- `distributor_approve_quota` - Approve quota request
- `distributor_approve_request` - Approve slot request

**Distributor Settlements (2)**
- `distributor_settlements` - View settlements
- `distributor_settlement_detail` - Settlement details

**Agency Dashboard (1)**
- `agency_dashboard` - Agency dashboard

**Agency Slots - Shopping (4)**
- `agency_shopping_slots` - List agency shopping slots
- `create_shopping_slot` - Create shopping slot
- `edit_shopping_slot` - Edit shopping slot (POST)
- `delete_shopping_slot` - Delete shopping slot
- `upload_shopping_slots` - Bulk upload shopping slots

**Agency Slots - Place (4)**
- `agency_place_slots` - List agency place slots
- `create_place_slot` - Create place slot
- `edit_place_slot` - Edit place slot (POST)
- `delete_place_slot` - Delete place slot
- `upload_place_slots` - Bulk upload place slots

**Refunds (2)**
- `request_shopping_slot_refund` - Request shopping slot refund
- `request_place_slot_refund` - Request place slot refund

**Public Pages (3)**
- `index` - Landing page
- `shopping` - Shopping data entry
- `place` - Place data entry
- `success` - Success page

**Bulk Operations (6)**
- `bulk_save_shopping_slots` - Bulk save shopping slots (POST)
- `bulk_save_place_slots` - Bulk save place slots (POST)
- `bulk_delete_shopping_slots` - Bulk delete shopping slots (POST)
- `bulk_delete_place_slots` - Bulk delete place slots (POST)
- `selected_delete_shopping_slots` - Delete selected slots (POST)
- `selected_delete_place_slots` - Delete selected slots (POST)

---

## TEMPLATE FILE VERIFICATION

### All Referenced Templates Status:

| Template | Status | Notes |
|----------|--------|-------|
| admin/approvals.html | ✓ EXISTS | Approval management |
| admin/create_settlement.html | ✓ EXISTS | Settlement creation |
| admin/dashboard.html | ✓ EXISTS | Admin dashboard |
| admin/edit_place_slot.html | ✓ EXISTS | Place slot edit |
| admin/edit_shopping_slot.html | ✓ EXISTS | Shopping slot edit |
| admin/place_slots.html | ✓ EXISTS | Place slots list |
| admin/refunds.html | ✓ EXISTS | Refund management |
| admin/register.html | ✓ EXISTS | Admin user registration |
| admin/settlement_detail.html | ✓ EXISTS | Settlement details |
| admin/settlements.html | ✓ EXISTS | Settlements list |
| admin/shopping_slots.html | ✓ EXISTS | Shopping slots list |
| admin/users.html | ✓ EXISTS | User management |
| agency/create_place_slot.html | ✓ EXISTS | Place slot creation |
| agency/create_shopping_slot.html | ✓ EXISTS | Shopping slot creation |
| agency/dashboard.html | ✓ EXISTS | Agency dashboard |
| agency/place_slots.html | ✓ EXISTS | Place slots list |
| agency/settlement_detail.html | ✓ EXISTS | Settlement details |
| agency/settlements.html | ✓ EXISTS | Settlements list |
| agency/shopping_slots.html | ✓ EXISTS | Shopping slots list |
| agency/upload_place_slots.html | ✗ MISSING | **CRITICAL** |
| agency/upload_shopping_slots.html | ✗ MISSING | **CRITICAL** |
| auth/login.html | ✓ EXISTS | Login page |
| auth/register.html | ✓ EXISTS | User registration |
| distributor/agencies.html | ✓ EXISTS | Agencies list |
| distributor/approvals.html | ✓ EXISTS | Quota approvals |
| distributor/dashboard.html | ✓ EXISTS | Distributor dashboard |
| distributor/settlement_detail.html | ✓ EXISTS | Settlement details |
| distributor/settlements.html | ✓ EXISTS | Settlements list |
| distributor/slots.html | ✓ EXISTS | Slots management |
| errors/403.html | ✓ EXISTS | Access forbidden |
| errors/404.html | ✓ EXISTS | Not found |
| errors/500.html | ✓ EXISTS | Server error |
| index.html | ✓ EXISTS | Landing page |
| layout.html | ✓ EXISTS | Base template |
| place.html | ✓ EXISTS | Place data entry |
| refund/request_place_refund.html | ✓ EXISTS | Place refund request |
| refund/request_shopping_refund.html | ✓ EXISTS | Shopping refund request |
| request_slot_quota.html | ✓ EXISTS | Quota request form |
| shopping.html | ✓ EXISTS | Shopping data entry |
| success.html | ✓ EXISTS | Success page |

**Total Templates:** 40  
**Existing:** 38  
**Missing:** 2

---

## RECOMMENDATIONS BY PRIORITY

### Priority 1: CRITICAL (Fix Immediately Before Deployment)

1. **Create missing template:** `agency/upload_shopping_slots.html`
   - Location: `/home/user/naver_hup_new/templates/agency/upload_shopping_slots.html`
   - Affected route: `/shopping-slots/upload` (GET/POST)
   - Time estimate: 30 minutes

2. **Create missing template:** `agency/upload_place_slots.html`
   - Location: `/home/user/naver_hup_new/templates/agency/upload_place_slots.html`
   - Affected route: `/place-slots/upload` (GET/POST)
   - Time estimate: 30 minutes

3. **Fix broken endpoint:** `download_project_zip`
   - Either implement the route or remove the template
   - Choose between Option A (implement), Option B (remove), or Option C (change link)
   - Time estimate: 15-30 minutes

### Priority 2: HIGH (Best Practice)

1. **Add explicit action attributes to refund forms**
   - Files: `request_shopping_refund.html`, `request_place_refund.html`
   - Improves code clarity and maintainability
   - Time estimate: 10 minutes

2. **Review and document unused routes**
   - Clarify purpose of 5 unused API endpoints
   - Document which are deprecated vs. intended for external use
   - Time estimate: 30 minutes

### Priority 3: MEDIUM (Optional Code Quality)

1. **Consider adding explicit action attributes to filter forms**
   - While current implementation is acceptable, makes intent clearer
   - Files: `admin/settlements.html`, `admin/refunds.html`
   - Time estimate: 5 minutes

---

## TESTING CHECKLIST

After implementing fixes, verify the following:

- [ ] Navigate to `/shopping-slots/upload` - should display upload form (agency user)
- [ ] Navigate to `/place-slots/upload` - should display upload form (agency user)
- [ ] Upload Excel file with shopping slots - should process successfully
- [ ] Upload Excel file with place slots - should process successfully
- [ ] Test `download_project_zip` endpoint (if implemented)
- [ ] Verify all navigation links work correctly
- [ ] Test role-based access (admin, distributor, agency)
- [ ] Test form submissions for refund requests
- [ ] Test filter forms in admin pages
- [ ] Test pagination links

---

## SUMMARY STATISTICS

| Metric | Value |
|--------|-------|
| Total Routes | 67 |
| Routes Used in Templates | 63 |
| Broken Links | 1 |
| Missing Templates | 2 |
| Forms without action | 2 |
| Unused Routes | 5 |
| Navigation Links Verified | 50+ |
| Template Files Verified | 40 |
| Hardcoded URLs Found | 0 |
| Circular Redirects | 0 |

**Overall Status:** ⚠️ **NOT READY FOR DEPLOYMENT**

All critical issues must be resolved before production deployment.

