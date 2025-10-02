

export const verificationTokenEmailTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Email Verification</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
  <div style="max-width: 600px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h1 style="text-align: center; color: #333;">Welcome to Akamify 👋</h1>
    <p>Thank you for signing up. To verify your email, please use the code below:</p>
    <div style="font-size: 28px; font-weight: bold; background: #f0f0f0; padding: 10px 20px; display: inline-block; border-radius: 5px; margin: 20px 0;">
      {verificationToken}
    </div>
    <p>This code is valid for 10 minutes. Do not share this code with anyone.</p>
    <p>If you did not request this, you can ignore this email.</p>
    <hr />
    <p style="font-size: 12px; color: #888;">
      Akamify Technologies © 2025 <br/>
      Need help? <a href="mailto:support@akamify.com">Contact Support</a><br/>
      Don’t want emails from us? <a href="https://akamify.com/unsubscribe">Unsubscribe</a>
    </p>
  </div>
</body>
</html>
`;


export const welcomeEmailTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Welcome to Akamify</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
  <div style="max-width: 600px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h1 style="text-align: center; color: #333;">🎉 Welcome to Akamify, 
    
    {name}!
    
    </h1>
    <p>We're thrilled to have you on board. Your email has been successfully verified, and you're all set to start exploring our platform.</p>
    <p>Here’s what you can do next:</p>
    <ul>
      <li>✔️ Access your dashboard</li>
      <li>📈 Start using our tools and services</li>
      <li>🙋‍♂️ Reach out to support if you have questions</li>
    </ul>
    <p>If you ever need assistance, feel free to reach out at any time.</p>
    <p>Welcome once again to the Akamify family – let’s build something amazing together 🚀</p>
    <hr />
    <p style="font-size: 12px; color: #888;">
      Akamify Technologies © 2025 <br/>
      Need help? <a href="mailto:support@akamify.com">Contact Support</a><br/>
      Don’t want emails from us? <a href="https://akamify.com/unsubscribe">Unsubscribe</a>
    </p>
  </div>
</body>
</html>
`;



export const passwordResetEmailTemplate = `
  <div style="font-family:sans-serif">
    <h2>Reset Your Password</h2>
    <p>Click the link below to reset your password:</p>
    <a href="{resetUrl}" style="color:blue">Reset Password</a>
    <p>This link is valid for 15 minutes only.</p>
  </div>
`;
