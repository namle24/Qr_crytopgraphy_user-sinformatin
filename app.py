# app.py
from flask import Flask, render_template, request, send_file, jsonify
from secure_ticket import SecureTicketSystem, TicketInfo
import os
from datetime import datetime
import json

app = Flask(__name__)
ticket_system = SecureTicketSystem()

# Ensure the uploads directory exists
if not os.path.exists('static/qr_codes'):
    os.makedirs('static/qr_codes')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate_ticket', methods=['POST'])
def generate_ticket():
    try:
        # Get form data
        ticket_info = TicketInfo(
            full_name=request.form['full_name'],
            birth_date=request.form['birth_date'],
            id_number=request.form['id_number'],
            address=request.form['address'],
            departure_time=request.form['departure_time'],
            ticket_class=request.form['ticket_class'],
            seat_number=request.form['seat_number'],
            departure_station=request.form['departure_station'],
            arrival_station=request.form['arrival_station']
        )

        # Generate secure ticket with encryption
        ticket_data = ticket_system.create_secure_ticket(ticket_info)

        # Save QR code to static folder
        qr_filename = f"qr_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
        qr_path = os.path.join('static/qr_codes', qr_filename)
        os.rename(ticket_data['qr_code'], qr_path)

        # Decrypt public data for display
        public_info = ticket_system.decrypt_ticket_data(ticket_data['public_data'])

        # Store private data in server (simulated here)
        server_storage = {
            'ticket_id': qr_filename,
            'server_data': ticket_data['server_data']
        }

        return render_template('ticket.html',
                               ticket_info=public_info,
                               qr_path=qr_path)

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/verify_ticket', methods=['POST'])
def verify_ticket():
    try:
        qr_data = request.form['qr_data']
        server_data = request.form['server_data']

        is_valid = ticket_system.verify_ticket(qr_data, server_data)
        return jsonify({'valid': is_valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)