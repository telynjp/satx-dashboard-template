# SATX Dashboard Template

A reusable Flask + SQLite + Chart.js dashboard template for San Antonio data projects. Fork this template and adapt it for your domain.

## Architecture

```
backend/
├── app.py                    # Flask routes + Chart.js chart config
├── config.py                 # DB path, environment detection
├── security.py               # API keys, rate limiting, IP allowlist
├── scheduler.py              # Background daily refresh thread
├── generate_api_key.py       # CLI tool for API key generation
├── database.py               # Main entity schema + CRUD + stats
├── fetch_data.py             # ETL: Open Data Portal → SQLite
├── insights.py               # Cross-table analytics engine
├── templates/                # Jinja2 templates (Chart.js)
│   ├── base.html             # Layout: navbar, mobile menu, footer
│   ├── dashboard.html        # Main dashboard with charts + map
│   ├── entity_list.html      # Paginated/filterable data table
│   └── ...
└── static/
    ├── css/style.css         # Grid system, responsive breakpoints
    └── *.geojson             # Map data (optional)
```

## Key Patterns to Reuse

### 1. Database Layer (`database.py`)

Each entity follows this pattern:
- `init_<entity>_table()` — CREATE TABLE IF NOT EXISTS + indexes
- `insert_<entity>_records(records)` — INSERT OR IGNORE (dedup by UNIQUE key)
- `get_<entity>_stats(days)` — Aggregated statistics for dashboard
- `get_<entity>_list(page, per_page, filters)` — Paginated listing
- `get_<entity>_filter_options()` — Distinct values for filter dropdowns
- `log_fetch(count, start, end)` — Fetch history tracking

### 2. Analytics Engine (`insights.py`)

Cross-table analytics that combine multiple entities:
- Weighted composite scoring (e.g., `entity_A * 3 + entity_B * 2`)
- Multi-period comparisons (30d vs 60d vs 90d)
- Trend detection with moving averages
- Severity/quality index calculation
- Key findings generation (improvements, concerns, overview)

### 3. API Security (`security.py`)

Reusable as-is:
- SHA-256 hashed API key storage
- Per-identifier rate limiting (60 req/60s default)
- IP allowlist with RFC 1918 private network support
- CSP headers for Chart.js CDN
- Decorators: `@require_api_key`, `@rate_limit`, `@ip_restrict`

### 4. Scheduler (`scheduler.py`)

Background thread that runs daily refresh at a configured time:
- Uses `schedule` library in a daemon thread
- Sequential refresh of all data sources
- Automatic retry on failure
- Started at Flask app startup

### 5. Template Patterns (`templates/`)

- `base.html` — Responsive navbar with dropdown nav, hamburger menu, footer
- `dashboard.html` — Stat cards grid + Chart.js charts + data tables
- `entity_list.html` — Filter form + responsive table + pagination

### 6. Chart.js Integration

Charts are rendered inline in Jinja2 templates:
```html
<script>
new Chart(document.getElementById('myChart'), {
    type: 'bar',
    data: {
        labels: {{ labels | tojson }},
        datasets: [{
            data: {{ data | tojson }}
        }]
    }
});
</script>
```

## Quick Start

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Fetch initial data (customize fetch_data.py for your source)
python fetch_data.py

# 4. Run the app
python app.py
# → http://localhost:5001

# 5. Generate API key
python generate_api_key.py "My App"
```

## Customization Checklist

- [ ] Update `config.py` with your database name
- [ ] Create entity-specific `*_database.py` modules (copy `database.py` pattern)
- [ ] Update `fetch_data.py` with your data source API
- [ ] Update `insights.py` with your analytics calculations
- [ ] Update `app.py` routes for your entities
- [ ] Update `templates/` for your dashboard views
- [ ] Update `static/css/style.css` for your branding
- [ ] Update `scheduler.py` refresh functions
- [ ] Update CORS origins in `app.py`

## Data Sources

This template is designed for the San Antonio Open Data Portal:
- CKAN API: `https://data.sanantonio.gov/api/3/action/datastore_search`
- Resource IDs are entity-specific (update in `fetch_data.py`)

## Tech Stack

- **Backend**: Python 3.8+, Flask, SQLite
- **Frontend**: Chart.js (CDN), Bootstrap, responsive CSS
- **Security**: API keys, rate limiting, IP allowlist
- **Deployment**: Docker + gunicorn

## License

MIT
