from main import app, User

# Create an application context
with app.app_context():
    # Query all data from the User table
    all_users = User.query.all()

    # Print the data
    for user in all_users:
        print(user.id, user.hname, user.city, user.email, user.username, user.phoneno, user.treatment, user.estimated, user.password, user.status)
