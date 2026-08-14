from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from src.database import Database
from datetime import datetime
import os

class PDFReport:
    def __init__(self): self.db = Database()
    def generate(self, filename='reports/report.pdf'):
        os.makedirs('reports', exist_ok=True)
        c = canvas.Canvas(filename, pagesize=letter)
        c.drawString(100, 750, f"NeuroSnare Report - {datetime.now()}")
        stats = self.db.get_stats()
        c.drawString(100, 730, f"Total Attacks: {stats['total_attacks']}")
        c.drawString(100, 710, f"Redirected: {stats['redirected']}")
        c.drawString(100, 690, f"Unique IPs: {stats['unique_ips']}")
        c.save()
        return filename
