from app import app,User,db,bcrypt
#getpass() hides the password whle you type,so it will not appear in the terminal screen
from getpass import getpass
def create_admin():
  username=input("Username: ").strip()
  email=input("Email: ").strip()
  password=getpass("Strong password: ")
  confirm_password=getpass("Confirm password: ")
  if not username or not password:
    print("Username and password required")
  #validations
  if len(password)<12:
    print("Password must be atleat 12 characters")
  elif password!=confirm_password:
    print("Passwords must match")
  elif User.query.filter_by(username=username).first():
    print("Username already exists")
  elif User.query.filter_by(email=email).first():
    print("Email already exists")
  else:
    hashed_password=bcrypt.generate_password_hash(password).decode("utf-8")
    #save user to the database
    user=User(
        username=username,
        email=email,
        password=hashed_password,
        is_admin=True
    )
    db.session.add(user)
    db.session.commit()
    print("Admin account created successfully")


if __name__=="__main__":
  with app.app_context():
    create_admin()