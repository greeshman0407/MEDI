"""MediConnect backend API tests - auth, symptoms, doctors, appointments, pharmacy, lab."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", os.environ.get("BACKEND_URL", "http://localhost:8000")).rstrip("/")
API = f"{BASE_URL}/api"

TEST_EMAIL = "test@mediconnect.app"
TEST_PASS = "test1234"


@pytest.fixture(scope="session")
def token():
    # try login first, register if fails
    r = requests.post(f"{API}/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASS}, timeout=30)
    if r.status_code != 200:
        r = requests.post(f"{API}/auth/register", json={"name": "Test User", "email": TEST_EMAIL, "password": TEST_PASS}, timeout=30)
    assert r.status_code == 200, f"auth failed: {r.status_code} {r.text}"
    return r.json()["token"]


@pytest.fixture
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---- AUTH ----
def test_register_duplicate_rejected(token):
    r = requests.post(f"{API}/auth/register", json={"name": "Dup", "email": TEST_EMAIL, "password": TEST_PASS}, timeout=30)
    assert r.status_code == 400

def test_register_new_user():
    email = f"TEST_{uuid.uuid4().hex[:8]}@mediconnect.app"
    r = requests.post(f"{API}/auth/register", json={"name": "Temp", "email": email, "password": "pwd12345"}, timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert "token" in data and data["user"]["email"] == email
    assert "id" in data["user"]

def test_login_success(token):
    assert isinstance(token, str) and len(token) > 20

def test_login_invalid():
    r = requests.post(f"{API}/auth/login", json={"email": TEST_EMAIL, "password": "wrong"}, timeout=30)
    assert r.status_code == 401

def test_me(auth_headers):
    r = requests.get(f"{API}/auth/me", headers=auth_headers, timeout=30)
    assert r.status_code == 200
    assert r.json()["email"] == TEST_EMAIL
    assert "_id" not in r.json()

def test_me_without_token():
    r = requests.get(f"{API}/auth/me", timeout=30)
    assert r.status_code == 401


# ---- DOCTORS ----
def test_list_doctors():
    r = requests.get(f"{API}/doctors", timeout=30)
    assert r.status_code == 200
    docs = r.json()
    assert isinstance(docs, list) and len(docs) >= 8
    assert all("_id" not in d for d in docs)
    assert all("id" in d and "specialty" in d for d in docs)

def test_list_doctors_filter():
    r = requests.get(f"{API}/doctors", params={"specialty": "Cardiologist"}, timeout=30)
    assert r.status_code == 200
    docs = r.json()
    assert len(docs) >= 1
    assert all(d["specialty"] == "Cardiologist" for d in docs)

def test_doctor_detail():
    r = requests.get(f"{API}/doctors/doc-1", timeout=30)
    assert r.status_code == 200
    assert r.json()["id"] == "doc-1"

def test_doctor_detail_404():
    r = requests.get(f"{API}/doctors/nope", timeout=30)
    assert r.status_code == 404


# ---- APPOINTMENTS ----
def test_create_and_get_appointment(auth_headers):
    payload = {"doctor_id": "doc-1", "date": "2026-02-15", "time": "10:00", "mode": "video", "notes": "TEST_"}
    r = requests.post(f"{API}/appointments", json=payload, headers=auth_headers, timeout=30)
    assert r.status_code == 200, r.text
    appt = r.json()
    assert appt["doctor_id"] == "doc-1" and appt["status"] == "confirmed"
    assert "room_id" in appt and "_id" not in appt
    aid = appt["id"]

    r2 = requests.get(f"{API}/appointments/{aid}", headers=auth_headers, timeout=30)
    assert r2.status_code == 200 and r2.json()["id"] == aid

    r3 = requests.get(f"{API}/appointments", headers=auth_headers, timeout=30)
    assert r3.status_code == 200 and any(a["id"] == aid for a in r3.json())

def test_appointment_requires_auth():
    r = requests.post(f"{API}/appointments", json={"doctor_id": "doc-1", "date": "2026-02-15", "time": "10:00"}, timeout=30)
    assert r.status_code == 401

def test_appointment_bad_doctor(auth_headers):
    r = requests.post(f"{API}/appointments", json={"doctor_id": "nope", "date": "2026-02-15", "time": "10:00"}, headers=auth_headers, timeout=30)
    assert r.status_code == 404


# ---- MEDICINES & ORDERS ----
def test_list_medicines():
    r = requests.get(f"{API}/medicines", timeout=30)
    assert r.status_code == 200
    meds = r.json()
    assert len(meds) >= 8 and all("_id" not in m for m in meds)

def test_medicines_search():
    r = requests.get(f"{API}/medicines", params={"search": "para"}, timeout=30)
    assert r.status_code == 200
    meds = r.json()
    assert len(meds) >= 1 and any("Paracetamol" in m["name"] for m in meds)

def test_create_order(auth_headers):
    payload = {
        "items": [{"medicine_id": "med-1", "name": "Paracetamol 500mg", "price": 45, "quantity": 2},
                  {"medicine_id": "med-2", "name": "Vitamin D3 60K", "price": 180, "quantity": 1}],
        "address": "TEST_123 Road", "phone": "9999999999"
    }
    r = requests.post(f"{API}/orders", json=payload, headers=auth_headers, timeout=30)
    assert r.status_code == 200, r.text
    o = r.json()
    assert o["total"] == 45 * 2 + 180
    assert o["payment_mode"] == "Cash on Delivery"
    assert "_id" not in o

    r2 = requests.get(f"{API}/orders", headers=auth_headers, timeout=30)
    assert r2.status_code == 200 and any(x["id"] == o["id"] for x in r2.json())


# ---- LAB ----
def test_list_lab_tests():
    r = requests.get(f"{API}/lab-tests", timeout=30)
    assert r.status_code == 200
    assert len(r.json()) >= 8

def test_create_lab_booking(auth_headers):
    payload = {"test_ids": ["lab-1", "lab-2"], "address": "TEST_Addr", "phone": "9999999999",
               "date": "2026-02-20", "time_slot": "08:00-09:00"}
    r = requests.post(f"{API}/lab-bookings", json=payload, headers=auth_headers, timeout=30)
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["total"] == 350 + 650
    assert len(b["tests"]) == 2 and "_id" not in b

    r2 = requests.get(f"{API}/lab-bookings", headers=auth_headers, timeout=30)
    assert r2.status_code == 200 and any(x["id"] == b["id"] for x in r2.json())


# ---- SYMPTOMS (LLM) ----
def test_symptom_analyze(auth_headers):
    payload = {"symptoms": "mild headache, slight fever for 2 days", "age": 30, "gender": "male"}
    r = requests.post(f"{API}/symptoms/analyze", json=payload, headers=auth_headers, timeout=90)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["analysis"] and isinstance(data["possible_conditions"], list)
    assert len(data["possible_conditions"]) == 3
    assert data["recommended_specialty"]
    assert data["urgency"] in ["Low", "Medium", "High"]

def test_symptom_requires_auth():
    r = requests.post(f"{API}/symptoms/analyze", json={"symptoms": "x"}, timeout=30)
    assert r.status_code == 401
