# CTI-Aggregator

**CTI-Aggregator** is a cyber threat intelligence aggregator that pulls Indicators of Compromise (IOCs) from multiple sources, normalizes them into a unified schema, and stores them in a PostgreSQL database. It supports cross-source deduplication, ensuring that the same indicator from different feeds is merged rather than duplicated.

## Setting up PostgreSQL

Install PostgreSQL using the download for your OS: [EnterpriseDB Downloads](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads).

* **Permissions**: You cannot complete the install without having administrative-level permissions on your device.

* **Installation**: During installation, you will set up a password for your PostgreSQL server/database. Once the installation is complete, open up pgAdmin4 and use the password to login.

* **Database Creation**: Right-click on Databases and create a new database named `cti_db`. You can name the database whatever you would like, but will have to change the routing accordingly.

* **Configuration**: In the project folder, open the `cti` folder and the `settings.py` file. There are lines referring to the database (around lines 83-92). The name of the database, user, and password are set up by you, the admin. The default port is 5432 and can be changed in pgAdmin.

* **Environment**: This database is completely local. Any changes or issues with the database will not affect others unless they are connected to your specific database.

## Setting up Python

Install a Python version of your choosing from [python.org](https://www.python.org/downloads/) (Version 3.11 is recommended).

* **Virtual Environment**: Open terminal as administrator and change directory into the project folder. Use `python -m venv venv` to create a folder to deploy a python virtual environment.

* **Activation (Windows)**: Change directory into `venv` and then `Scripts` in the terminal. Use `.\activate` to enter your virtual environment. If there is a permissions issue, use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and then `.\activate` again.

* **Activation (macOS/Linux)**: Use `source venv/bin/activate`.

## Setting up Django

From the project folder, inside of the virtual environment, use the following commands:

```bash
pip install django psycopg2-binary requests pandas stix2 python-dotenv
python manage.py migrate
python manage.py createsuperuser
```


## Ingesting Intelligence


API Keys:

Create a `.env` file in the project root and add your keys. This file is gitignored and should never be committed.

```
OTX_API_KEY=your_otx_key_here
THREATFOX_API_KEY=your_threatfox_key_here
```


### Options

```bash
# Fetch all feeds 
python manage.py ingest_all

# Fetch OTX only, override page limit
python manage.py ingest_otx --pages 3

# Fetch ThreatFox only, last 7 days
python manage.py ingest_threatfox --days 7

# Ingest local STIX files
python manage.py ingest_stix_folder sample_stix

# Pull from a TAXII server with credentials
python manage.py ingest_taxii https://your-server/taxii2/ --username admin --password secret
```

---

## Running the Web Server

1. Make sure you are connected to your server in pgAdmin.
2. Activate your virtual environment.
3. Run the following command:

```bash
python manage.py runserver
```
