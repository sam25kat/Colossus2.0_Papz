from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class FileMetadata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    category = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    metadata = db.Column(db.Text)


import fitz  # PyMuPDF for PDF
from PIL import Image
import pytesseract
import io
import openai



def extract_metadata(file):
    filename = file.filename
    content = ""

    if filename.lower().endswith('.pdf'):
        doc = fitz.open(stream=file.read(), filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        content = text
    elif filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        img = Image.open(file.stream)
        content = pytesseract.image_to_string(img)
    
    # Summarize using ChatGPT
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": f"Extract and summarize metadata from this content:\n{content}"}],
        max_tokens=300
    )
    metadata_summary = response.choices[0].message.content.strip()
    return metadata_summary



