from drone_api import app, routes

if __name__ == '__main__':
    app.run(debug=False)
#turn debug off when launching to not expose to hackers