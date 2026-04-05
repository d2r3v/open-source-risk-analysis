# Start database
docker-compose up -d

# Load schema
docker exec -i osv-postgres psql -U postgres -d osv_analysis < sql/schema.sql

# Run data pipeline
node scripts/js/fetch_librariesio.js
node scripts/js/fetch_osv.js

# Generate visuals
python scripts/python/generate_visualizations.py