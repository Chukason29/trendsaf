# Project Title

## POST /signup/registration
- Used for registering new users
- expection from client is a json body
    {
        "firstname":"Jamo",
        "lastname": Aphrodisu",
        "email" : "abraham@trendsaf.com",
        "password": "12345"
    }
- Expected Server Responses
    if any of the expected json is missing parameter 
        `{
            "error": 422,
            "message": "missing parameter",
            "status": false
        }`
    
    if email is with the wrong format
        {
            "message": "invalid email"
        }
    If email exists already
        {
            "exists": true,
            "is_verified": false,
            "message": "Account with email already exists"
        }
    For a successfull registration
        {
            "id": "IjAyMjQwNDJmLTBhNjItNDI5YS1hM2E1LWI5ZTUyODNlNTY4NiI.4u8HnVUIzqT0Feh334fX2XX28lo",
            "is_confirmed": false,
            "is_verified": false,
            "message": "Registration successful",
            "status": 200
        }
    On successfull registration a verification code will be sent to the user's email 
NOTE: Do well to keep tab of "id" as it will be used for verification and code resend

## 2. PATCH  /verification/<string:id>
- Used to verify a user

- Expectation from client
- the user's id should be appended to the verification page url
- On the request body is a json
    {
        "code" : "Yb785g1K"
    }

- Expected Server's Response
    If any of the expected json is missing parameter 
        `{
            "error": 422,
            "message": "missing parameter",
            "status": false
        }`

    If code isn't valid or url is invalid
        `{
            "error": 401,
            "message": "unauthorized access",
            "status": false
        }`

    On Successful verification
        `{
            "is_confirmed": false,
            "is_verified": true,
            "message": "verification successful",
            "status": "verified"
        }`


## 3. PATCH  /code_resend/<string:id>

- Used for resending verification code  

- Expected Server Response
    If wrong request method is used
    `{
        "error": 405,
        "message": "api call method not permitted",
        "status": false
    }`
- On successful code resend
    `{
        "message": "code re-sent to email",
        "status": 200
    }`

## 4. POST /auth/confirmation
- Used to confirm the user and add user profile

- Expectations from client
    Get the cookie named csrf_token from the browswer and add to the header of the request
    on the header the parameter name should be 'X-CSRF-TOKEN'
    your header will look like the below

    {
        "X-CSRF-TOKEN" : csrf_token
    }

- On the body of the request, implement the following
replace the null values with your form values
     {
        "company_name" : "",
        "company_type": "",
        "company_size": "",
        "start_year": "",
        "annual_revenue": "",
        "company_role": "",
        "phone": "",
        "province": "",
        "country": "",
    }

- Access the non-HTTPOnly cookie "csrf_token" from cookie store and send it as a header in your request
    with parameter 'X-CSRF-TOKEN'

-H {
    "X-CSRF-TOKEN": "value of the cookie csrf_token"
}

## 5. POST /auth/login
- Used for authenticating users
- Expectation from client
    A json is appended to the body of  the request
    {
       "email" : "apercu@trendsaf.com",
       "password" : "12345" 
    }


- Expected Server Responses 
- If user doesn't exist or wrong password
    {
        "status": False
        "message": "wrong email or password"
    }
-  On successfull authentication and verified.. Remember to redirect the user to the verification page if is_verified is False
    {
        "status": true,
        "is_confirmed": false,
        "is_verified": true,
        "message": "Not verified"
    }

    On successfull authentication, verification and confirmation.. Remember to redirect the user to the confirmation page if is_confirmed is False

    {
        "status": True,
        "is_verified": True,
        "is_confirmed": True,
        "user_role" : "",
        "company_name": "",
        "company_type" : "",
        "company_size" : "",
        "start_year": "",
        "province" : "",
        "access_token": "",
        "csrf_token": ""
    }

    Note: the status parameter is the primary parameter


## 6. /auth/password_reset_request
- Used for requesting password reset

- Expected request from client
    {
        "email":"nhamo@trendsaf.co"
    }

- Expected Server Responses all things being equal
    If user does not exist
    {
        "message": "User does not exit",
        "status": false
    }

    If user exists and mail is sent successfully.... Remember to let the user know that the email link last for just 15 minutes
    {
        "message": "link sent successfully",
        "status": true
    }

## 7. /auth/password_reset
- Used for requesting password reset

- Expected request from client

    Add the token from the url as a parameter in the request body

    {
        "token":"ImJmYmQ0Nzc2LTY5ZmUtNGY0Ni05YTgyLTUxMmNjMDkyNzc1OSI.ZvnWvg.rUkUIs4_8r0o4qD3cI9ny0t8oVU",
        "password": "123456789"
    }

-  Expected Server Responses
    On successful password reset
    {
        "message": "password changed successfully",
        "status": true
    }