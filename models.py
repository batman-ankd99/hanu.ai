from db import db

class Finding(db.Model):
    __tablename__ = "findings"
    __table_args__ = {"extend_existing": True}  # ✅ IMPORTANT FIX

    id = db.Column(db.Integer, primary_key=True)

    service = db.Column(db.String(100))
    resource_type = db.Column(db.String(100))
    resource_id = db.Column(db.String(200))

    finding = db.Column(db.Text)
    severity = db.Column(db.String(50))

    status = db.Column(db.String(50), default="open")
