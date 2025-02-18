from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///fishing_competition.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Model zawodów
class Competition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    participants = db.relationship("Participant", backref="competition", cascade="all, delete-orphan")

# Model zawodnika
class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    surname = db.Column(db.String(100), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    competition_id = db.Column(db.Integer, db.ForeignKey("competition.id"), nullable=False)

with app.app_context():
    db.create_all()

# Endpoint do pobierania zawodów
@app.route("/competitions", methods=["GET"])
def get_competitions():
    competitions = Competition.query.all()
    return jsonify([{ "id": c.id, "name": c.name, "date": c.date, "location": c.location, "participants": [{ "id": p.id, "name": p.name, "surname": p.surname, "weight": p.weight } for p in c.participants] } for c in competitions])

# Endpoint do dodawania zawodów
@app.route("/competitions", methods=["POST"])
def add_competition():
    data = request.json
    new_competition = Competition(name=data["name"], date=data["date"], location=data["location"])
    db.session.add(new_competition)
    db.session.commit()
    return jsonify({"message": "Competition added successfully!"}), 201

# Endpoint do pobierania zawodników
@app.route("/participants", methods=["GET"])
def get_participants():
    competition_id = request.args.get("competition_id")
    if competition_id:
        participants = Participant.query.filter_by(competition_id=competition_id).all()
    else:
        participants = Participant.query.all()
    return jsonify([{ "id": p.id, "name": p.name, "surname": p.surname, "weight": p.weight, "competition_id": p.competition_id } for p in participants])

# Endpoint do dodawania zawodników
@app.route("/participant", methods=["POST"])
def add_participant():
    data = request.json
    new_participant = Participant(name=data["name"], surname=data["surname"], weight=data["weight"], competition_id=data["competition_id"])
    db.session.add(new_participant)
    db.session.commit()
    return jsonify({"message": "Participant added successfully!"}), 201

# Endpoint do edytowania zawodnika
@app.route("/participant/<int:participant_id>", methods=["PUT"])
def update_participant(participant_id):
    data = request.json
    participant = Participant.query.get_or_404(participant_id)
    participant.name = data.get("name", participant.name)
    participant.surname = data.get("surname", participant.surname)
    participant.weight = data.get("weight", participant.weight)
    db.session.commit()
    return jsonify({"message": "Participant updated successfully!"})

# Endpoint do usuwania zawodnika
@app.route("/participant/<int:participant_id>", methods=["DELETE"])
def delete_participant(participant_id):
    participant = Participant.query.get_or_404(participant_id)
    db.session.delete(participant)
    db.session.commit()
    return jsonify({"message": "Participant deleted successfully!"})

if __name__ == "__main__":
    app.run(debug=True)
