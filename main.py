
from datetime import date, datetime, timedelta, timezone
import os

import jwt
from jwt.exceptions import InvalidTokenError

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy.orm import Session
from database import Base, engine


import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from fastapi import BackgroundTasks
from database import PasswordReset_db

from database import User_db, Income_db, get_db


app = FastAPI(title="Income Manager API")

Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://flourishing-biscochitos-866e4f.netlify.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set JWT_SECRET_KEY in your environment before running.
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Set the JWT_SECRET_KEY environment variable")

ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# Request models
class Register(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class Login(BaseModel):
    email: EmailStr
    password: str


class IncomeCreate(BaseModel):
    Date: date
    amnt: int = Field(gt=0)


class IncomeUpdate(BaseModel):
    Date: date
    amnt: int = Field(gt=0)


# Create JWT token
def create_access_token(user_id: int):
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_MINUTES
    )

    return jwt.encode(
        {"sub": str(user_id), "exp": expires},
        SECRET_KEY,
        algorithm=ALGORITHM
    )


# Get currently authenticated user
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        user_id = int(payload.get("sub"))
    except (InvalidTokenError, TypeError, ValueError):
        raise credentials_error

    user = db.query(User_db).filter(
        User_db.id == user_id
    ).first()

    if user is None:
        raise credentials_error

    return user


# Register
@app.post("/register", status_code=201)
def register(data: Register, db: Session = Depends(get_db)):
    email = data.email.lower()

    existing = db.query(User_db).filter(
        User_db.email == email
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Email is already registered"
        )

    user = User_db(
        name=data.name,
        email=email,
        hashed_password=password_hash.hash(data.password)
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Registration successful",
        "name": user.name,
        "email": user.email
    }


# Login
@app.post("/login")
def login(data: Login, db: Session = Depends(get_db)):
    user = db.query(User_db).filter(
        User_db.email == data.email.lower()
    ).first()

    if not user or not password_hash.verify(
        data.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )

    token = create_access_token(user.id)

    return {
        "access_token": token,
        "token_type": "bearer",
        "name": user.name,
        "email": user.email
    }


# Current profile
@app.get("/me")
def get_profile(user: User_db = Depends(get_current_user)):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email
    }


# Add income for logged-in user
@app.post("/income")
def add_income(
    data: IncomeCreate,
    db: Session = Depends(get_db),
    user: User_db = Depends(get_current_user)
):
    existing = db.query(Income_db).filter(
        Income_db.user_id == user.id,
        Income_db.date == data.Date
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Income already exists for this date. Update it instead."
        )

    record = Income_db(
        date=data.Date,
        amnt=data.amnt,
        user_id=user.id
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return {"message": "Income saved successfully"}


# Get only the logged-in user's income
@app.get("/incomes")
def get_incomes(
    db: Session = Depends(get_db),
    user: User_db = Depends(get_current_user)
):
    records = db.query(Income_db).filter(
        Income_db.user_id == user.id
    ).order_by(Income_db.date.asc()).all()

    return [
        {"date": str(record.date), "amnt": record.amnt}
        for record in records
    ]


# Update only the logged-in user's income
@app.put("/upincome")
def update_income(
    data: IncomeUpdate,
    db: Session = Depends(get_db),
    user: User_db = Depends(get_current_user)
):
    record = db.query(Income_db).filter(
        Income_db.user_id == user.id,
        Income_db.date == data.Date
    ).first()

    if not record:
        raise HTTPException(
            status_code=404,
            detail="No income record found for this date"
        )

    record.amnt = data.amnt
    db.commit()

    return {"message": "Income updated successfully"}


def send_reset_email(email: str, token: str):
    frontend_url = os.getenv("FRONTEND_URL")

    if not frontend_url:
        raise RuntimeError("FRONTEND_URL is not configured")

    reset_link = f"{frontend_url}/index.html?token={token}"

    message = EmailMessage()
    message["Subject"] = "Income Manager - Reset Password"
    message["From"] = os.environ["SMTP_EMAIL"]
    message["To"] = email
    message.set_content(
        "You requested a password reset.\n\n"
        f"Open this link to reset your password:\n{reset_link}\n\n"
        "This link expires in 15 minutes. "
        "If you did not request this, ignore this email."
    )

    with smtplib.SMTP(
        os.getenv("SMTP_HOST", "smtp.gmail.com"),
        int(os.getenv("SMTP_PORT", "587"))
    ) as server:
        server.starttls()
        server.login(
            os.environ["SMTP_EMAIL"],
            os.environ["SMTP_PASSWORD"]
        )
        server.send_message(message)

class ForgotPassword(BaseModel):
    email: EmailStr


@app.post("/forgot-password")
def forgot_password(
    data: ForgotPassword,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    email = str(data.email).lower().strip()
    user = db.query(User_db).filter(
        User_db.email == email
    ).first()

    # Same response whether the email exists or not
    response = {
        "message": "If the account exists, a reset link will be sent."
    }

    if not user:
        return response

    # Invalidate previous unused reset links
    old_tokens = db.query(PasswordReset_db).filter(
        PasswordReset_db.user_id == user.id,
        PasswordReset_db.used == False
    ).all()

    for old_token in old_tokens:
        old_token.used = True

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(
        raw_token.encode()
    ).hexdigest()

    reset_record = PasswordReset_db(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc).replace(
            tzinfo=None
        ) + timedelta(minutes=15),
        used=False
    )

    db.add(reset_record)
    db.commit()

    background_tasks.add_task(
        send_reset_email, email, raw_token
    )

    return response

class ResetPassword(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


@app.post("/reset-password")
def reset_password(
    data: ResetPassword,
    db: Session = Depends(get_db)
):
    token_hash = hashlib.sha256(
        data.token.encode()
    ).hexdigest()

    record = db.query(PasswordReset_db).filter(
        PasswordReset_db.token_hash == token_hash,
        PasswordReset_db.used == False
    ).first()

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or already used reset link"
        )

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if record.expires_at <= now:
        record.used = True
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Reset link expired. Please request another."
        )

    user = db.query(User_db).filter(
        User_db.id == record.user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid reset request"
        )

    # Use the same password-hashing method as registration
    user.hashed_password = password_hash.hash(
        data.new_password
    )
    record.used = True
    db.commit()

    return {"message": "Password reset successful. Please log in."}