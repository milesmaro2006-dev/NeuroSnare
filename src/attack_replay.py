from src.database import Database
class AttackReplay:
    def __init__(self): self.db = Database()
    def get_session_timeline(self, session_id): return self.db.get_timeline(session_id)
    def generate_summary(self, session_id):
        events = self.db.get_timeline(session_id)
        return '\n'.join([f"{e[2]} - {e[3]}: {e[4]}" for e in events])
