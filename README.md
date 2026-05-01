# Libertaire Refit

A Flask web application for tracking boat refit tasks, inventory, systems, and progress.

## Features

- **Task Management**: Create, edit, and track refit tasks with status, priority, and phase
- **Inventory Tracking**: Manage parts, costs, purchase status, and delivery dates
- **Systems & Compartments**: Organize work by boat systems and physical spaces
- **Cable & Hose Tracking**: Dedicated modules for electrical and plumbing runs
- **Photo Logging**: Attach photos to task log entries
- **Dark Theme**: Optimized for workshop and marine environments

## Tech Stack

- **Backend**: Flask 3.x, Python 3.12
- **Database**: PostgreSQL (via psycopg2-binary)
- **Auth**: bcrypt password hashing + session cookies
- **Rate Limiting**: Flask-Limiter (30 req/min on API mutations)
- **Security**: Input sanitization, MIME validation, cache-control headers
- **Server**: Gunicorn behind systemd

## Quick Start

```bash
# Clone
git clone https://github.com/svlibertaire-code/LibertaireRefit.git
cd LibertaireRefit

# Virtual environment
python3 -m venv venv
source venv/bin/activate

# Dependencies
pip install -r requirements.txt

# Database setup (PostgreSQL required)
# Edit DB_NAME, DB_USER, DB_PASSWORD in refit_app.py
# Then run the app once to auto-create tables

# Development
python refit_app.py

# Production (systemd)
sudo systemctl start refit
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_NAME` | PostgreSQL database name | `refit` |
| `DB_USER` | Database user | `refit_user` |
| `DB_PASSWORD` | Database password | *(required)* |
| `DB_HOST` | Database host | `localhost` |
| `SECRET_KEY` | Flask session key | *(auto-generated)* |
| `ADMIN_PASSWORD_HASH` | bcrypt hash of admin password | *(required)* |

## Security Notes

- App is designed to run behind a private network (Tailscale) or VPN
- No CSRF tokens — acceptable for non-internet-facing deployments
- Rate limiting enabled on all mutating API endpoints
- File uploads validated by extension + MIME type + size (10MB max)
- All user inputs sanitized via `sanitize_text()` helper

## Project Structure

```
LibertaireRefit/
├── refit_app.py          # Main Flask application
├── requirements.txt      # Python dependencies
├── static/
│   ├── icon.svg          # App icon
│   └── uploads/          # Photo uploads (created at runtime)
├── .gitignore
└── README.md
```

## License

MIT
