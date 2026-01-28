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
<<<<<<< HEAD
    This database is completely local
    Any changes or issues with the database will not affect other, unless they are connected to your database
=======
>>>>>>> 66e961b01abe3976dc03c87e782694a3b0840d40

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
pip install django psycopg2-binary
python manage.py migrate
python manage.py createsuperuser
You can make the superuser whatever name, email, and password you want

# Running the server
Make sure you are connected to your server in pgAdmin
You will have to go into the project folder from the terminal and activate your virtual environment
You can then use the command "python manage.py runserver" to run your server for testing.

# GOOD LUCK HAVE FUN BREAK THINGS
