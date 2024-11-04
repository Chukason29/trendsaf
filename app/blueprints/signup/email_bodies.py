verify_email_message = f"""<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <link rel="stylesheet" href='{BASE_URL}/signup/style.css'>
    <title>BaseFood Email Verification</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap');
        
    </style>
</head>
<body>
    <div class='header'>
        <img src='./basefood_logo.png' alt='BaseFood Logo' style='max-width: 200px;'>
    </div>
    <div class='content'>
        <h2>Hello [User's Name],</h2>
        <p>Welcome to baseFood! Please verify your email address by clicking the button below:</p>
        <a href='[Verification_Link]' target='_blank' class='button'>Verify Email</a>
        <p>If the button above doesn't work, you can also click on the link below or copy and paste it into your browser:</p>
        <p><a href='[Verification_Link]' target='_blank'>[Verification_Link]</a></p>
        <p>If you didn't create an account with baseFood, please ignore this email.</p>
    </div>
    <div class='footer'>
        <p>&copy; 2024 trendsAf. All rights reserved.</p>
    </div>
</body>
</html>"""