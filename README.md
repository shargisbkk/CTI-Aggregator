# CTI-Aggregator
Cyber threat intelligence aggregator used to pull data from different sources, normalize the data, and store the data in a PostgreSQL database

# Setting up PostgreSQL
Install PostgreSQL using the download for your OS https://www.enterprisedb.com/downloads/postgres-postgresql-downloads
You cannot complete the install without having administrative-level permissions on your device
During installation you will set up a password for your PostgreSQL server/database
Once the installation is complete, open up pgAdmin4 and use the password to login
Rightclick on Databases and create a new database named cti_db
You can name the database whatever you would like, but will have to change the routing accordingly
In the project folder open up the cti folder and settings.py file
There are lines refering to the database around line 83-92
The name of the database, user, and password are set up by you, the admin
The default port is 5432 and can be changed in pgAdmin
This database is completely local
Any changes or issues with the database will not affect other, unless they are connected to your database

# Setting up Python
Install Python version of your choosing from https://www.python.org/downloads/
I installed version 3.11
Open terminal as administrator and change directory into the project folder
Use "python -m venv venv" to create a folder to deploy a python virtual environment
you will change directory into venv and then Scripts in the terminal
Now you should use ".\activate" to enter your virtual environment
If there is a permissions issue use "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
then use ".\activate" again

# Setting up Django
from the project folder, inside of the virtual environment use the following commands
```
pip install django
pip install psycopg[binary]
pip install requests stix2 pandas taxii2client
python manage.py migrate
python manage.py createsuperuser
```
You can make the superuser whatever name, email, and password you want

# Running the server
Make sure you are connected to your server in pgAdmin
You will have to go into the project folder from the terminal and activate your virtual environment
You can then use the command "python manage.py runserver" to run your server for testing.

# Ingesting threat intelligence

## OTX (AlienVault)
You will need a free OTX API key:
1. Sign up at https://otx.alienvault.com
2. After logging in, go to your profile settings page
3. Copy the API key shown under "OTX Key"

Run ingestion with:
```
python -B manage.py ingest_otx YOUR_API_KEY
```

By default this fetches both the public activity feed and your subscribed feed, deduplicates, normalizes, and saves to the database.

### Options
```
--pages N            Limit to N pages per feed (default 0 = all pages). Start with --pages 3 for a quick test.
--feed activity      Fetch only the public activity feed
--feed subscribed    Fetch only pulses from users you follow
--source NAME        Tag all saved records with a custom source name (default: otx)
```

Examples:
```
python -B manage.py ingest_otx YOUR_KEY --pages 3
python -B manage.py ingest_otx YOUR_KEY --feed activity --pages 5
python -B manage.py ingest_otx YOUR_KEY --feed subscribed --source otx-subscribed
```

## ThreatFox (abuse.ch)
You will need a free ThreatFox API key:
1. Sign up at https://auth.abuse.ch/
2. After logging in, go to https://threatfox.abuse.ch/api/ and copy your API key

Run ingestion with:
```
python -B manage.py ingest_threatfox YOUR_API_KEY
```

### Options
```
--days N      How many days back to fetch IOCs (default: 1). Use --days 7 for a week.
--source NAME Tag all saved records with a custom source name (default: threatfox)
```

Examples:
```
python -B manage.py ingest_threatfox YOUR_KEY --days 3
python -B manage.py ingest_threatfox YOUR_KEY --days 7 --source threatfox-week
```

## STIX files (local folder)
Place your .json STIX bundle files in a folder and run:
```
python -B manage.py ingest_stix_folder /path/to/folder --source my-source
```

Sample STIX files are included in the `sample_stix/` folder for testing:
```
python -B manage.py ingest_stix_folder sample_stix --source sample
```

## TAXII server
To pull from a TAXII 2.1 server:
```
python -B manage.py ingest_taxii https://your-taxii-server/taxii/ --source taxii-source
```

Data from all sources is saved to the `indicators_of_compromise` table in your database.

# GOOD LUCK HAVE FUN BREAK THINGS
