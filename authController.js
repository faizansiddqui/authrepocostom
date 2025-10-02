import bcrypt from 'bcryptjs';
import { generateVerificationToken } from '../utils/generateVerificationToken.js';
import { GenerateAccessToken, generateRefreshToken } from '../utils/generateJwtToken.js';
import User from '../models/user.js'
import { sendPasswordResetEmail, sendVerificationEmail, sendWelcomeEmail } from '../resend/email.js';
import crypto from "crypto"
import { setTokenCookies } from '../utils/setTokenCookies.js';
import jwt from 'jsonwebtoken';
import { redis } from '../config/redisClient.js'; // Ensure you have the correct import for Redis client
import { sendOTPToPhone } from '../utils/OTPUtlis.js';



export const signup = async (req, res) => {

    const { name, email, password } = req.body;

    try {
        if (!name || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const userAlreadyExist = await User.findOne({ email });
        if (userAlreadyExist) {
            return res.status(400).json({ message: "user already exist" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = generateVerificationToken();

        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            verificationToken: verificationToken,
            verificationTokenExpireAt: Date.now() + 24 * 60 * 60 * 1000 // ✅ fix here
        })

        if (!user) {
            return res.status(400).json({ success: false, message: "User not created" });
        }

        await sendVerificationEmail(user.email, verificationToken)

        const accessToken = GenerateAccessToken(user._id);
        const refreshToken = await generateRefreshToken(user._id);

        setTokenCookies(res, accessToken, refreshToken);

        // Convert user document to plain object and remove sensitive data
        const userData = user.toObject();
        delete userData.password; // Remove password from the user object

        res.status(201).json({
            success: true,
            message: "User Created Successfully",
            user: userData,
        })
    } catch (error) {
        console.log("Signup Error", error)
        res.status(400).json({ success: false, message: error.message });
    }
}


export const login = async (req, res) => {
    const { email, password } = req.body;

    try {

        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ success: false, message: "Invalid Email or Password" });
        }


        if (!user.isVerified) {
            return res.status(403).json({ success: false, message: "Email is not verified" })
        }

        const accessToken = GenerateAccessToken(user._id);
        const refreshToken = await generateRefreshToken(user._id);

        setTokenCookies(res, accessToken, refreshToken);

        const userData = user.toObject();
        delete userData.password; // Remove password from the user object
        delete userData.verificationToken; // Remove verification token from the user object
        delete userData.verificationTokenExpireAt; // Remove verification token expiration from the user object
        delete userData.resetPasswordToken; // Remove reset password token from the user object
        delete userData.resetPasswordExpiresAt; // Remove reset password expiration from the user object

        res.status(200).json({
            success: true,
            message: "Login Successful",
            user: userData
        })
    }
    catch (error) {
        console.log("Error Signin in", error);
        res.status(400).json({ success: false, message: error.message })
    }
}


export const verifyEmail = async (req, res) => {
    const { code } = req.body;
    try {
        const user = await User.findOne({
            verificationToken: code,
            verificationTokenExpireAt: { $gt: Date.now() },
        })
        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid or expired verification code" })
        }
        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpireAt = undefined;

        await user.save();

        await sendWelcomeEmail(user.email, user.name);

        res.status(200).json({ success: true, message: "Email verified successfully" })
    } catch (error) {
        console.log("Error Verifying Email", error);
        res.status(400).json({ success: false, message: error.message })
    }
}


export const refreshAccessToken = async (req, res) => {
    const token = req.cookies.refreshToken;

    if (!token) {
        return res.status(401).json({ success: false, message: "No refresh token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.REFRESH_SECRET);
        const userId = decoded.userId;

        const storedToken = await redis.get(`refreshToken:${userId}`);
        if (!storedToken || storedToken !== token) {
            return res.status(403).json({ success: false, message: "Invalid refresh token" });
        }

        await redis.del(`refreshToken:${userId}`); // Delete the old refresh token

        const accessToken = GenerateAccessToken(userId);
        const newRefreshToken = await generateRefreshToken(userId);

        setTokenCookies(res, accessToken, newRefreshToken);
        res.status(200).json(
            {
                success: true,
                accessToken
            });

    } catch (error) {
        console.log("Error refreshing access token", error);
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(403).json({ success: false, message: "Invalid refresh token" });
        }
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}


export const logout = async (req, res) => {
    const token = req.cookies.refreshToken;

    if (!token) {
        return res.status(200).json({ success: true, message: "No active session" });
    }

    try {
        const decoded = jwt.verify(token, process.env.REFRESH_SECRET);

        await redis.del(`refreshToken:${decoded.userId}`);

    } catch (error) {
        console.log("Error logging out", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    return res.status(200).json({ success: true, message: "Logged out successfully" });
}


export const forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            res.status(400).json({ success: false, message: "User not found" });
        }
        const resetPasswordToken = crypto.randomBytes(32).toString("hex");
        const resetPasswordExpireAt = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

        user.resetPasswordToken = resetPasswordToken;
        user.resetPasswordExpiresAt = resetPasswordExpireAt;

        await user.save();
        await sendPasswordResetEmail(user.email, `${process.env.CLIENT_URL}/reset-password/${resetPasswordToken}`)

        res.status(200).json({ success: true, message: "Password reset email sent successfully" })
    } catch (error) {
        console.log("Error sending password reset email", error);
        res.status(400).json({ success: false, message: error.message })
    }
}


export const resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpiresAt: { $gt: Date.now() }
        })

        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid or expired token" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;

        user.resetPasswordToken = undefined;
        user.resetPasswordExpiresAt = undefined;

        await user.save();

        res.status(200).json({ success: true, message: "Password reset successfully" })

    } catch (error) {
        console.log("Reset Password Error:", error);
        res.status(500).json({ success: false, message: error.message });
    }
}


export const getUserProfile = async (req, res) => {
    try {
        const userId = req.user._id; // Assuming user ID is stored in req.user
        const user = await User.findById(userId).select("-__v -password -verificationToken -verificationTokenExpireAt -resetPasswordToken -resetPasswordExpiresAt");
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        res.status(200).json({ success: true, user });
    } catch (error) {
        console.log("Error fetching user profile", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}


export const phoneLogin = async (req, res) => {

    const { phoneNumber } = req.body;
    if (!phoneNumber) {
        return res.status(400).json({ success: false, message: "Phone number is required" });
    }

    try {
        console.log("Looking for user with phone number:", phoneNumber);
        let user = await User.findOne({ phoneNumber });

        if (!user) {
            console.log("User not found, creating new user");
            user = new User({ phoneNumber });
            await user.save();
        }

        const otp = generateVerificationToken(); // check if this function is defined correctly
        const phoneToken = crypto.randomBytes(32).toString("hex");

        console.log("Generated OTP:", otp, "Generated token:", phoneToken);

        await redis.setEx(
            `otp:${phoneToken}`,
            300,
            JSON.stringify({
                phoneNumber,
                otp,
                lastRequestTime: Date.now(),
                count: 1 // Initialize count for rate limiting
            }));

        await redis.setEx(
            `otp:${phoneNumber}`,
            300,
            JSON.stringify({ count: 1, lastRequestTime: Date.now() })
        )

        await sendOTPToPhone(phoneNumber, otp); // make sure this doesn't throw error silently

        user.phoneToken = phoneToken;
        user.phoneTokenExpireAt = Date.now() + 5 * 60 * 1000;
        user.verificationToken = otp;
        user.isVerified = false;
        user.verificationTokenExpireAt = Date.now() + 5 * 60 * 1000;
        user.phoneNumber = phoneNumber;

        await user.save();

        res.status(200).json({ success: true, message: "OTP sent successfully", phoneToken });



    } catch (error) {
        console.error("🔴 Error in phoneLogin:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};


export const verifyPhoneOTP = async (req, res) => {
    const { phoneToken, otp } = req.body;

    if (!phoneToken || !otp) {
        return res.status(400).json({ success: false, message: "Phone token and OTP are required" });
    }

    try {
        const data = await redis.get(`otp:${phoneToken}`);

        if (!data) {
            return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
        }

        const { phoneNumber, otp: storedOtp } = JSON.parse(data);

        console.log(storedOtp, otp);


        if (storedOtp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        }

        const user = await User.findOne({ phoneNumber });
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        user.isVerified = true;
        user.phoneToken = undefined;
        user.phoneTokenExpireAt = undefined;
        user.verificationToken = undefined;

        await user.save();

        res.status(200).json({ success: true, message: "Phone number verified successfully" });

        await redis.del(`otp:${phoneToken}`); // Clean up OTP data after successful verification
    } catch (error) {
        console.error("Error verifying phone OTP", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};


export const resentOTP = async (req, res) => {
    const { phoneToken } = req.body;

    if (!phoneToken) {
        return res.status(400).json({ success: false, message: "Phone token is required" });
    }

    try {
        const data = await redis.get(`otp:${phoneToken}`);
        if (!data) {
            return res.status(400).json({ success: false, message: "Session expired. Please login again." });
        }

        const parsed = JSON.parse(data);
        const { phoneNumber, count = 1, lastRequestTime = 0 } = parsed;

        const currentTime = Date.now();
        const timeSinceLastRequest = currentTime - lastRequestTime;

        // Optional: rate limiting - minimum 30 seconds between OTPs
        if (timeSinceLastRequest < 30 * 1000) {
            return res.status(429).json({ success: false, message: "Please wait before requesting a new OTP." });
        }

        // Optional: max 5 resends
        if (count >= 5) {
            return res.status(429).json({ success: false, message: "Maximum OTP resend limit reached." });
        }

        const newOtp = generateVerificationToken();

        await redis.setEx(
            `otp:${phoneToken}`,
            300, // Reset TTL to 5 minutes
            JSON.stringify({
                phoneNumber,
                otp: newOtp,
                count: count + 1,
                lastRequestTime: currentTime
            })
        );

        // Update phoneNumber-based limiter key also:
        await redis.setEx(
            `otp:${phoneNumber}`,
            300,
            JSON.stringify({ count: count + 1, lastRequestTime: currentTime })
        );


        await sendOTPToPhone(phoneNumber, newOtp);

        res.status(200).json({ success: true, message: "OTP resent successfully" });

    } catch (error) {
        console.error("🔴 Error resending OTP:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};

