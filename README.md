# Spring Security

This repo is composed of a backend java api server.  The intended use is for demo and learning purposes only.



***********************************
***  IDE compile and run notes ****
***********************************


API server (The backend java files can be found in src/main)
-----------
1. Choose to test either A) Form login or B) JWT API authentication functionality
2. For A(form login), uncomment the top version of the overriden method (below), and comment out the top version 
  protected void configure(HttpSecurity http) in class ApplicationSecurityConfig.java
3. For B(JWT API authentication), uncomment the bottom version of the same method, comment out the top version.


Test functionality
----------------

To test form login authentication

1. navigate to localhost:8080/management/api/v1/students
2. the page will redirect to /login
3. login with user "linda", password "password", perhaps tick "remember me" to test authentication persistence
4. Upon successful login, the page will redirect to /courses
5. Linda will be able to access /management/api/v1/students REST API with authorization: ROLE_ADMIN, but not /api/v1/students/1
6. Logout from /logout
7. login with user "annasmith", password "password", perhaps tick "remember me" to test authentication persistence
8. Anna will be unable to access /management/api/v1/students REST API with authorization: ROLE_ADMIN, but can access /api/v1/students/1


To test JWT API authentication

1. Using Postman, send a POST to localhost:8080/login as user "linda", password "password".
2. Receive the 200 response and copy the AUTHORIZATION token starting with "bearer".
3. Using Postman, send a POST to localhost:8080/management/api/v1/students with no user credentials but adding Linda's AUTHORIZATION token to the header,
and in the body, send a raw JSON { "studentName": "rick" }, and observe a 200 response to the successful post attempt
4. Using Postman, send a POST to localhost:8080/login as user "annasmith", password "password".
5. Receive the 200 response and copy the AUTHORIZATION token starting with "bearer".
6. Using Postman, send a POST to localhost:8080/management/api/v1/students with no user credentials but adding Anna's AUTHORIZATION token to the header,
and in the body, send a raw JSON { "studentName": "rick" }, and observe a 403 response to the unsuccessful post attempt
