import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";
import userModel from "../models/userModel.js";

export const register = async (req,res)=>{
    const {email, name, password} = req.body;
    if( !email || !name || !password) {
        return res.json({success: false, message:"Missing Details"});
    }
    try{
        const existingUser = await userModel.findOne({email});
        if(existingUser) {
            return res.json({success: false, message:"User already exist"});
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({name,email,password:hashedPassword});
        await user.save();

        const token = jwt.sign({id:user._id}, process.env.JWT_SECRET, {expiresIn:'7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7  * 24 * 60 * 60 * 1000
        });

        // Sending welcome email
        const mailOptions = {
            from : process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to Shubham Websites",
            text: `Welcome to Shubham Auth website. Your accoumt is created with emailo id: ${email}`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true, message:"User successfully registered"});
    } catch(err){
        res.json({success: false, message:err.message});               
    }
}

export const login = async (req,res) =>{
    const {email, password} = req.body;
    if( !email|| !password) {
        return res.json({success: false, message:"Email and password are required"});
    }
    try{
        const user = await userModel.findOne({email});
        if(!user) {
            return res.json({success: false, message:"Invalid email"}); 
        }
        const isMatch = await bcrypt.compare(password,user.password);
        if(!isMatch) {
            res.json({success: false, message:"Invalid password"}); 
        }
        const token = jwt.sign({id:user._id}, process.env.JWT_SECRET, {expiresIn:'7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7  * 24 * 60 * 60 * 1000
        });
        return res.json({success:true});


    } catch(err){
        res.json({success: false, message:err.message});               
    }
}
export const logout = async (req,res)=> {
    try{
        res.clearCookie('token',{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });
        return res.json({success:true, message:"User logout Successfully"});
    } catch(err){
        res.json({success: false, message:err.message});               
    }
}
// Send verification otp to the user's Email
export const sendVerifyOtp = async(req, res)=>{
 try{
    const {userId} = req.body;
    const user = await userModel.findById(userId);

    if(user.isAccountVerified) {
        return res.json({success: false, message: "Account is already verified"});
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.verifyOtp = otp;
    user.verifyOtpExpiresAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    const mailOption = {
        from : process.env.SENDER_EMAIL,
        to: user.email,
        subject: "Account Verification Otp",
        text: `Your otp is ${otp}. Verify your account using this Otp.`
    }
    await transporter.sendMail(mailOption);

    res.json({ success: true, message: "Verification OTP Sent on Email "});

 }catch(err){
        res.json({success: false, message:err.message});               
    }
} 
//Email verification 
export const VerifyEmail = async(req, res) =>{
    const {userId, otp} = req.body;
    if( !userId || !otp){
        return res.json({success: false, message: "Missing Details"});
    }

 try{
    const user = await userModel.findById(userId);

    if(!user) {
        return res.json({success: false, message: "User not Found"});
    };

    if(user.verifyOtp === '' || user.verifyOtp !== otp) {
        return res.json({success: false, message: "Invalid otp"});
    }
    if(user.verifyOtpExpiresAt < Date.now()) {
        return res.json({success: false, message: "OTP Expires"});
    }
    user.isAccountVerified = true;
    user.verifyOtp = '';
    user.verifyOtpExpiresAt = 0;

    await user.save();

    res.json({ success: true, message: "Email verified successfully "});        

 }catch(err){
        res.json({success: false, message:err.message});               
    }
};
// This route only verify user is authorised user or not
export const isAuthenticated = async (req, res) => {
    try{
        res.json({success: true});     
    } catch(err){
        res.json({success: false, message:err.message});               
    }
};
export const sendResetOtp = async (req, res) =>{
    const {email} = req.body;
    if(!email) {
        return res.json({success: false, message: 'Email is required'});
    };
    try{
        const user = await userModel.findOne({email});
        if(!user) {
        return res.json({success: false, message: 'Email is required'});
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpiresAt = Date.now() + 15 * 60 * 1000;

        await user.save();

    const mailOption = {
        from : process.env.SENDER_EMAIL,
        to: user.email,
        subject: "Password Reset Otp",
        text: `Your otp for reseting your password is ${otp}. Use this OTP to proceed with resetting your password.`
    }
    await transporter.sendMail(mailOption);

    res.json({ success: true, message: "Otp sent to your email"});
        
    } catch(error) {
        return res.json({success: false, message:error.message});
    }
};
// Reset User password

export const resetPassword = async (req, res)=>{
    const {email,otp,newPassword} = req.body;
    if(!email || !otp || !newPassword) {
       return res.json({ success: false, message: "Email, OTP and NewPassword is required"});
    };
    try{
        const user = await userModel.findOne({email});
        if(!user) {
           return res.json({ success: false, message: "User not found"});
        }
        if(user.resetOtp === '' || user.resetOtp !== otp) {
           return res.json({ success: false, message: "Invalid OTP"});
        }
        if(user.resetOtpExpiresAt < Date.now()) {
           return res.json({ success: false, message: "OTP Expired"});
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '' ;
        user.resetOtpExpiresAt = 0 ;

        await user.save();

            return res.json({ success: true, message: "Password has been reset successfully "});
    } catch(error) {
            return res.json({success: false, message:error.message});
    };
};