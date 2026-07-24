from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt as pyjwt


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ['JWT_SECRET']
EMERGENT_LLM_KEY = os.environ['EMERGENT_LLM_KEY']

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ---------------- MODELS ----------------
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str
    name: str
    email: str

class TokenOut(BaseModel):
    token: str
    user: User

class SymptomRequest(BaseModel):
    symptoms: str
    age: Optional[int] = None
    gender: Optional[str] = None

class SymptomResponse(BaseModel):
    analysis: str
    possible_conditions: List[str]
    recommended_specialty: str
    urgency: str

class AppointmentCreate(BaseModel):
    doctor_id: str
    date: str
    time: str
    mode: str = "video"
    notes: Optional[str] = ""

class OrderItem(BaseModel):
    medicine_id: str
    name: str
    price: float
    quantity: int

class OrderCreate(BaseModel):
    items: List[OrderItem]
    address: str
    phone: str

class LabBookingCreate(BaseModel):
    test_ids: List[str]
    address: str
    phone: str
    date: str
    time_slot: str

# ---------------- AUTH ----------------
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@api_router.post("/auth/register", response_model=TokenOut)
async def register(data: UserCreate):
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "name": data.name,
        "email": data.email,
        "password": hash_password(data.password),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(doc)
    token = create_token(user_id)
    return TokenOut(token=token, user=User(id=user_id, name=data.name, email=data.email))

@api_router.post("/auth/login", response_model=TokenOut)
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email})
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user["id"])
    return TokenOut(token=token, user=User(id=user["id"], name=user["name"], email=user["email"]))

@api_router.get("/auth/me", response_model=User)
async def me(user=Depends(get_current_user)):
    return User(id=user["id"], name=user["name"], email=user["email"])

# ---------------- SYMPTOM CHECKER ----------------
def analyze_symptoms_logic(symptoms: str, age: Optional[int] = None, gender: Optional[str] = None) -> dict:
    """Smart symptom analyzer using keyword matching and medical knowledge."""
    symptoms_lower = symptoms.lower()
    
    # Symptom-to-condition mapping
    symptom_keywords = {
        "chest pain": {"conditions": ["Angina", "Heart Attack Risk", "Acid Reflux"], "specialty": "Cardiologist", "urgency": "High"},
        "severe headache": {"conditions": ["Migraine", "Tension Headache", "Meningitis"], "specialty": "Neurologist", "urgency": "High"},
        "fever": {"conditions": ["Common Cold", "Flu", "Infection"], "specialty": "General Physician", "urgency": "Medium"},
        "cough": {"conditions": ["Bronchitis", "Asthma", "Pneumonia"], "specialty": "General Physician", "urgency": "Medium"},
        "rash": {"conditions": ["Allergic Reaction", "Dermatitis", "Infection"], "specialty": "Dermatologist", "urgency": "Medium"},
        "joint pain": {"conditions": ["Arthritis", "Sprain", "Inflammation"], "specialty": "Orthopedic", "urgency": "Low"},
        "anxiety": {"conditions": ["Generalized Anxiety", "Panic Disorder", "Stress"], "specialty": "Psychiatrist", "urgency": "Medium"},
        "ear pain": {"conditions": ["Ear Infection", "Earwax Buildup", "TMJ Disorder"], "specialty": "ENT", "urgency": "Medium"},
        "sore throat": {"conditions": ["Strep Throat", "Common Cold", "Laryngitis"], "specialty": "ENT", "urgency": "Low"},
        "stomach pain": {"conditions": ["Gastritis", "IBS", "Food Poisoning"], "specialty": "General Physician", "urgency": "Low"},
        "dizziness": {"conditions": ["Low Blood Pressure", "Inner Ear Disorder", "Anemia"], "specialty": "General Physician", "urgency": "Medium"},
        "shortness of breath": {"conditions": ["Asthma", "Pneumonia", "Anxiety"], "specialty": "Cardiologist", "urgency": "High"},
    }
    
    # Find matching symptoms
    matched = {}
    for keyword, data in symptom_keywords.items():
        if keyword in symptoms_lower:
            matched = data
            break
    
    # Default response if no specific match
    if not matched:
        matched = {
            "conditions": ["Viral Infection", "Common Cold", "Fatigue"],
            "specialty": "General Physician",
            "urgency": "Low"
        }
    
    # Adjust urgency based on age
    if age and age > 60:
        if matched["urgency"] == "Low":
            matched["urgency"] = "Medium"
        elif matched["urgency"] == "Medium":
            matched["urgency"] = "High"
    
    analysis = f"Based on your reported symptoms ({symptoms}), these are possible conditions to consider. "
    if matched["urgency"] == "High":
        analysis += "Please seek medical attention promptly. "
    analysis += f"A {matched['specialty']} would be best suited to evaluate your condition."
    
    return {
        "analysis": analysis,
        "possible_conditions": matched["conditions"],
        "recommended_specialty": matched["specialty"],
        "urgency": matched["urgency"]
    }

@api_router.post("/symptoms/analyze", response_model=SymptomResponse)
async def analyze_symptoms(req: SymptomRequest, user=Depends(get_current_user)):
    try:
        # Use intelligent symptom analyzer
        result_dict = analyze_symptoms_logic(req.symptoms, req.age, req.gender)
        result = SymptomResponse(
            analysis=result_dict["analysis"],
            possible_conditions=result_dict["possible_conditions"],
            recommended_specialty=result_dict["recommended_specialty"],
            urgency=result_dict["urgency"]
        )
    except Exception as e:
        logger.error(f"Symptom analysis error: {e}")
        result = SymptomResponse(
            analysis="Unable to analyze symptoms. Please consult a physician for proper evaluation.",
            possible_conditions=["Common cold", "Viral infection", "General fatigue"],
            recommended_specialty="General Physician",
            urgency="Low",
        )
    
    # Save history
    await db.symptom_logs.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "symptoms": req.symptoms,
        "result": result.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    return result

# ---------------- DOCTORS ----------------
@api_router.get("/doctors")
async def list_doctors(specialty: Optional[str] = None):
    query = {}
    if specialty:
        query["specialty"] = specialty
    docs = await db.doctors.find(query, {"_id": 0}).to_list(200)
    return docs

@api_router.get("/doctors/{doctor_id}")
async def get_doctor(doctor_id: str):
    doc = await db.doctors.find_one({"id": doctor_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Doctor not found")
    return doc

# ---------------- APPOINTMENTS ----------------
@api_router.post("/appointments")
async def create_appointment(data: AppointmentCreate, user=Depends(get_current_user)):
    doctor = await db.doctors.find_one({"id": data.doctor_id}, {"_id": 0})
    if not doctor:
        raise HTTPException(404, "Doctor not found")
    appt = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "doctor_id": data.doctor_id,
        "doctor_name": doctor["name"],
        "doctor_specialty": doctor["specialty"],
        "date": data.date,
        "time": data.time,
        "mode": data.mode,
        "notes": data.notes,
        "status": "confirmed",
        "room_id": str(uuid.uuid4())[:8],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.appointments.insert_one(appt)
    appt.pop("_id", None)
    return appt

@api_router.get("/appointments")
async def list_appointments(user=Depends(get_current_user)):
    items = await db.appointments.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items

@api_router.get("/appointments/{appt_id}")
async def get_appointment(appt_id: str, user=Depends(get_current_user)):
    appt = await db.appointments.find_one({"id": appt_id, "user_id": user["id"]}, {"_id": 0})
    if not appt:
        raise HTTPException(404, "Appointment not found")
    return appt

# ---------------- MEDICINES & ORDERS ----------------
@api_router.get("/medicines")
async def list_medicines(search: Optional[str] = None):
    query = {}
    if search:
        query["name"] = {"$regex": search, "$options": "i"}
    items = await db.medicines.find(query, {"_id": 0}).to_list(500)
    return items

@api_router.post("/orders")
async def create_order(data: OrderCreate, user=Depends(get_current_user)):
    total = sum(item.price * item.quantity for item in data.items)
    order = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "items": [i.model_dump() for i in data.items],
        "address": data.address,
        "phone": data.phone,
        "total": total,
        "status": "processing",
        "payment_mode": "Cash on Delivery",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.orders.insert_one(order)
    order.pop("_id", None)
    return order

@api_router.get("/orders")
async def list_orders(user=Depends(get_current_user)):
    items = await db.orders.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items

# ---------------- LAB TESTS ----------------
@api_router.get("/lab-tests")
async def list_lab_tests():
    items = await db.lab_tests.find({}, {"_id": 0}).to_list(200)
    return items

@api_router.post("/lab-bookings")
async def create_lab_booking(data: LabBookingCreate, user=Depends(get_current_user)):
    tests = await db.lab_tests.find({"id": {"$in": data.test_ids}}, {"_id": 0}).to_list(100)
    total = sum(t["price"] for t in tests)
    booking = {
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "tests": tests,
        "address": data.address,
        "phone": data.phone,
        "date": data.date,
        "time_slot": data.time_slot,
        "total": total,
        "status": "scheduled",
        "technician_name": "Ramesh K.",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.lab_bookings.insert_one(booking)
    booking.pop("_id", None)
    return booking

@api_router.get("/lab-bookings")
async def list_lab_bookings(user=Depends(get_current_user)):
    items = await db.lab_bookings.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return items

# ---------------- SEED ----------------
SEED_DOCTORS = [
    {"id":"doc-1","name":"Dr. Aditi Sharma","specialty":"Cardiologist","experience":12,"rating":4.8,"fee":800,"distance_km":1.2,"clinic":"Heart Care Clinic","city":"Mumbai","bio":"Specializes in interventional cardiology with a decade of experience.","image":"https://images.unsplash.com/photo-1758691463393-a2aa9900af8a?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["09:00","10:00","11:30","14:00","16:00"]},
    {"id":"doc-2","name":"Dr. Rohan Mehta","specialty":"Dermatologist","experience":8,"rating":4.6,"fee":600,"distance_km":2.1,"clinic":"Skin & Aesthetics","city":"Mumbai","bio":"Cosmetic and clinical dermatology expert.","image":"https://images.unsplash.com/photo-1678940805950-73f2127f9d4e?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["10:00","11:00","13:00","15:30","17:00"]},
    {"id":"doc-3","name":"Dr. Priya Nair","specialty":"General Physician","experience":15,"rating":4.9,"fee":500,"distance_km":0.8,"clinic":"Family Health Center","city":"Mumbai","bio":"Primary care physician for adults and families.","image":"https://images.unsplash.com/photo-1612349317150-e413f6a5b16d?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["08:30","09:30","11:00","13:30","15:00","17:30"]},
    {"id":"doc-4","name":"Dr. Vikram Iyer","specialty":"Neurologist","experience":18,"rating":4.7,"fee":1200,"distance_km":3.4,"clinic":"NeuroMind Institute","city":"Mumbai","bio":"Focus on stroke, epilepsy, and migraine care.","image":"https://images.unsplash.com/photo-1537368910025-700350fe46c7?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["10:00","12:00","14:30","16:30"]},
    {"id":"doc-5","name":"Dr. Sneha Kapoor","specialty":"Pediatrician","experience":10,"rating":4.9,"fee":700,"distance_km":1.6,"clinic":"Little Stars Clinic","city":"Mumbai","bio":"Gentle pediatric care for newborns to teens.","image":"https://images.unsplash.com/photo-1594824476967-48c8b964273f?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["09:00","10:30","12:00","15:00","16:30"]},
    {"id":"doc-6","name":"Dr. Arjun Desai","specialty":"Orthopedic","experience":14,"rating":4.5,"fee":900,"distance_km":2.9,"clinic":"Bone & Joint Center","city":"Mumbai","bio":"Sports injuries and joint replacement specialist.","image":"https://images.unsplash.com/photo-1582750433449-648ed127bb54?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["09:30","11:30","14:00","16:00"]},
    {"id":"doc-7","name":"Dr. Kavya Reddy","specialty":"Psychiatrist","experience":9,"rating":4.8,"fee":1000,"distance_km":4.1,"clinic":"Mindful Wellness","city":"Mumbai","bio":"Anxiety, depression & therapy-informed care.","image":"https://images.unsplash.com/photo-1559839734-2b71ea197ec2?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["10:00","12:30","15:00","17:00"]},
    {"id":"doc-8","name":"Dr. Ishaan Bose","specialty":"ENT","experience":11,"rating":4.6,"fee":650,"distance_km":2.3,"clinic":"Ear Nose Throat Care","city":"Mumbai","bio":"Sinus, hearing and throat specialist.","image":"https://images.unsplash.com/photo-1622253692010-333f2da6031d?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","available_slots":["09:00","11:00","13:30","16:00"]},
]

SEED_MEDICINES = [
    {"id":"med-1","name":"Paracetamol 500mg","brand":"Crocin","price":45,"mrp":55,"category":"Pain Relief","description":"Fever & mild pain relief — strip of 15 tablets.","image":"https://images.unsplash.com/photo-1633171036157-78d53387fdc0?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":False},
    {"id":"med-2","name":"Vitamin D3 60K","brand":"HealthKart","price":180,"mrp":220,"category":"Vitamins","description":"Weekly Vitamin D3 capsules — pack of 4.","image":"https://images.unsplash.com/photo-1550572017-edd951b55104?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":False},
    {"id":"med-3","name":"Azithromycin 500mg","brand":"Azithral","price":120,"mrp":140,"category":"Antibiotic","description":"Antibiotic — strip of 5 tablets.","image":"https://images.unsplash.com/photo-1576671081837-49000212a370?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":True},
    {"id":"med-4","name":"Cough Syrup 100ml","brand":"Benadryl","price":95,"mrp":110,"category":"Cold & Cough","description":"Soothing cough syrup for dry cough.","image":"https://images.unsplash.com/photo-1585435557343-3b092031a831?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":False},
    {"id":"med-5","name":"Multivitamin Tablets","brand":"Revital","price":320,"mrp":380,"category":"Vitamins","description":"Daily wellness — bottle of 30 tablets.","image":"https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":False},
    {"id":"med-6","name":"ORS Hydration Powder","brand":"Electral","price":22,"mrp":25,"category":"Hydration","description":"Oral rehydration salts — sachet.","image":"https://images.unsplash.com/photo-1471864190281-a93a3070b6de?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":False},
    {"id":"med-7","name":"Antacid Gel","brand":"Digene","price":130,"mrp":150,"category":"Digestive","description":"Fast relief from acidity & heartburn — 200ml.","image":"https://images.unsplash.com/photo-1587854692152-cbe660dbde88?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":False},
    {"id":"med-8","name":"Pain Relief Spray","brand":"Volini","price":210,"mrp":240,"category":"Pain Relief","description":"Topical spray for muscle & joint pain.","image":"https://images.unsplash.com/photo-1587854692152-cbe660dbde88?crop=entropy&cs=srgb&fm=jpg&q=85&w=400","prescription_required":False},
]

SEED_LAB_TESTS = [
    {"id":"lab-1","name":"Complete Blood Count (CBC)","price":350,"description":"Measures red cells, white cells & platelets.","prep":"No fasting required.","turnaround":"Same day"},
    {"id":"lab-2","name":"Lipid Profile","price":650,"description":"Cholesterol & triglyceride panel.","prep":"12-hour fasting required.","turnaround":"24 hours"},
    {"id":"lab-3","name":"Thyroid Profile (T3/T4/TSH)","price":550,"description":"Thyroid hormone function test.","prep":"No fasting required.","turnaround":"24 hours"},
    {"id":"lab-4","name":"HbA1c (Diabetes)","price":450,"description":"3-month average blood sugar.","prep":"No fasting required.","turnaround":"Same day"},
    {"id":"lab-5","name":"Vitamin D & B12","price":1100,"description":"Vitamin deficiency panel.","prep":"No fasting required.","turnaround":"48 hours"},
    {"id":"lab-6","name":"Liver Function Test","price":600,"description":"Evaluates liver enzymes & proteins.","prep":"8-hour fasting preferred.","turnaround":"24 hours"},
    {"id":"lab-7","name":"Full Body Checkup","price":2200,"description":"60+ parameter preventive health check.","prep":"10-hour fasting required.","turnaround":"48 hours"},
    {"id":"lab-8","name":"COVID-19 RT-PCR","price":500,"description":"Nasal swab PCR test.","prep":"No preparation.","turnaround":"24 hours"},
]

@app.on_event("startup")
async def seed():
    if await db.doctors.count_documents({}) == 0:
        await db.doctors.insert_many(SEED_DOCTORS)
    if await db.medicines.count_documents({}) == 0:
        await db.medicines.insert_many(SEED_MEDICINES)
    if await db.lab_tests.count_documents({}) == 0:
        await db.lab_tests.insert_many(SEED_LAB_TESTS)

@api_router.get("/")
async def root():
    return {"message": "MediConnect API"}

# Add CORS middleware BEFORE including router
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
