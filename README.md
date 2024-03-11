## About

This is a Python demo of DIY OAuth2 Authorization Server (very simple and supporting only one client) and a Client using it. Implementation uses Flask, JWT and Mongo DB.

`client` directory contains client application and configuration files. 

`server` directory contains authentication server and configuration files.


## Running Locally

Run:

```
docker-compose up --build
```

Client app now should run on the port `:8080` and server on `:8081`. 

**Before testing you need to create a test user**:

```
curl -XPOST -H "Content-Type: application/json" -d '{"username":"ig0rm", "password":"qwerty123456"}' localhost:8081/create_user
```
Output should be similar to this:

```
User created: 65eec704b38c95fbc36f673c
```

Now navigate to the `localhost:8080`. You should see the page that offers you to login:

![Login](/doc/screenshot.png)

After you press the "Login" button you will be redirected to the authentication server running on localhost:8081. 

![Auth window](/doc/screenshot_2.png)

Server issues JWT authentication token and redirects you back to the client than now show you as logged in:

![Logged user](/doc/screenshot_3.png)




