# Star Wars Ship Database API
This is a web API for Star Wars ships. 

I made this site as a demo for web API's It is written in Python Flask and it demonstrates user signup/login, JASON Web Tokens (JWT), REST APIs, SQL Alchemy, SQLLite, and storing hashed passwords.

I used the following web tutorials: https://github.com/PrettyPrinted/building_user_login_system, 

## To Run
You will need to install the dependencies in requirements.txt. You can run the following in the same top level folder for the application.

The app will need the following environment variables to be set:

FLASK_APP=joels_flask_api  
FLASK_ENV=development  

You will also need to set these variables to your apropriate settings:  

SQLALCHEMY_DATABASE_URI  
SECRET_KEY  

If you are using a new Linux VM, you may have to install wheel.

```bash
pip3 install wheel
```

Activate python virtual environment and install packages in requirements.txt

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Then you will need to initialize the database. You can start a python session to initialize the db.
```bash
python3
```


```python
from application import db
db.create_all()
exit()
```

Then you can run the flask app

```bash
flask run
```