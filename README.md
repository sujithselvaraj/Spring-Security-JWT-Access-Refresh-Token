# Spring-Security-JWT-Access-Refresh-Token


Refer to the pom.xml for the dependencies need to be added.

We are using MySQl DataBase 
So do create a database called userservice in the terminal

mysql> create database userservice;
Query OK, 1 row affected (0.00 sec)


We are also using the Auth0 jwt dependencies in the project.
Do add it


After creating a project hit the postman

http://localhost:8080/api/login with post request


http://localhost:8080/api/users with get request


http://localhost:8080/api/token/refresh with get request


Dont forget to add the body and header whereever neccessary


You can also use the jwt debugger to access the token information with the access token and refresh token

https://jwt.io/#debugger-io
