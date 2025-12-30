# database.py

from sqlalchemy import create_engine, Column, String, Integer, DateTime, LargeBinary, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime, timezone
import os

# Configuration PostgreSQL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/comptaflow"
)

# Fix pour Render (postgresql:// -> postgresql+psycopg2://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ============ MODELS ============

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    full_name = Column(String)
    subscription_tier = Column(String, default="free")  # free, premium, pro
    stripe_customer_id = Column(String, nullable=True)  # Seule colonne Stripe nécessaire
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relations
    uploads = relationship("Upload", back_populates="user")
    usage_logs = relationship("UsageLog", back_populates="user")
    failed_conversions = relationship("FailedConversion", back_populates="user")

class Upload(Base):
    __tablename__ = "uploads"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    filename = Column(String, nullable=False)
    bank_type = Column(String)
    transaction_count = Column(Integer, default=0)
    excel_data = Column(LargeBinary)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Relation
    user = relationship("User", back_populates="uploads")

class UsageLog(Base):
    __tablename__ = "usage_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    month = Column(Integer, nullable=False)
    year = Column(Integer, nullable=False)
    uploads_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Relation
    user = relationship("User", back_populates="usage_logs")

class GuestConversion(Base):
    __tablename__ = "guest_conversions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address = Column(String, nullable=False, unique=True)
    user_agent = Column(String)
    converted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class FailedConversion(Base):
    __tablename__ = "failed_conversions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    user_email = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    bank_name = Column(String)
    error_message = Column(Text)
    user_comment = Column(Text)
    file_content = Column(Text)  # PDF en base64
    reported_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status = Column(String, default="pending")  # pending, reviewed, fixed
    admin_notes = Column(Text)
    
    # Relation
    user = relationship("User", back_populates="failed_conversions")

# ============ DEPENDENCY ============

def get_db():
    """Dépendance pour obtenir une session DB"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============ CREATE TABLES ============

def init_db():
    """Créer toutes les tables"""
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    print("🔨 Création des tables...")
    init_db()
    print("✅ Tables créées avec succès!")
