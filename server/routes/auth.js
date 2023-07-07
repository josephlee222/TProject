const express = require("express")
const yup = require("yup")
const { User, Sequelize } = require("../models")
const router = express.Router()
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const ejs = require("ejs")
const { emailSender } = require("../middleware/emailSender")
const { validateToken } = require('../middleware/validateToken');
require('dotenv').config();

router.post("/", async (req, res) => {
    // Authenticate a user
    const schema = yup.object().shape({
        email: yup.string().email().required(),
        password: yup.string().required().min(12).max(64),
    })

    try {
        await schema.validate(req.body, { abortEarly: false })
        const { email, password } = req.body
        const user = await User.findOne({ where: { email: email } })

        // Check if user exists
        if (!user) {
            res.status(401).json({ message: "Invalid email or password." })
            return
        }

        // Check if account is activated
        if (!user.is_active) {
            res.status(401).json({ message: "Account is not activated." })
            return
        }

        // Check if user email is verified
        if (!user.is_email_verified) {
            res.status(401).json({ message: "Email is not verified." })
            return
        }

        // Check if user has set password
        if (user.password === null) {
            res.status(401).json({ message: "Account password is not set." })
            return
        }

        // Check if password is valid by comparing hash
        const isPasswordValid = await bcrypt.compare(password, user.password)
        if (!isPasswordValid) {
            res.status(401).json({ message: "Invalid email or password." })
            return
        }

        let userInfo = {
            id: user.id,
            email: user.email,
            name: user.name,
            account_type: user.account_type,
            profile_picture: user.profile_picture,
            profile_picture_type: user.profile_picture_type,
            driver_application_sent: user.driver_application_sent
        }

        const token = jwt.sign({type: "session",user:userInfo}, process.env.APP_SECRET, { expiresIn: "7d" })
        res.json({ token, user: userInfo })
    } catch (error) {
        res.status(400).json({ message: error.message })
    }
})

router.post("/register", async (req, res) => {
    // Create a new user
    const schema = yup.object().shape({
        email: yup.string().email().required(),
        name: yup.string().required(),
        password: yup.string().required().min(12).max(64),
        phone_number: yup.string().required().min(8).max(8),
    })

    try {
        const { email, name, password, phone_number } = await schema.validate(req.body, { abortEarly: false })
        const newUser = await User.create({ email, name, password, phone_number })
        const token = jwt.sign({ type: "activate", id: newUser.id  }, process.env.APP_SECRET, { expiresIn: "30m" })
        const link = process.env.CLIENT_URL +`/verify?token=${token}`
        const html = await ejs.renderFile("templates/emailVerification.ejs", { url:link })
        await emailSender.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "EnviroGo - Email Verification",
            html: html,
        })
        res.json(newUser)
    } catch (error) {
        // check if error is because of duplicate email
        if (error instanceof Sequelize.UniqueConstraintError) {
            res.status(400).json({ message: "Email already exists." })
            return
        }
        
        res.status(400).json({ message: error.message })
    }
})

router.post("/verify", async (req, res) => {
    // Verify a user's email
    const schema = yup.object().shape({
        token: yup.string().required(),
    })

    try {
        const { token } = await schema.validate(req.body, { abortEarly: false })
        const { id } = jwt.verify(token, process.env.APP_SECRET)
        const user = await User.findByPk(id)
        if (!user) {
            res.status(404).json({ message: "User not found." })
            return
        }

        user.is_email_verified = true
        await user.save()
        res.json({ message: "Email verified." })
    } catch (error) {
        res.status(400).json({ message: error.message })
    }
})

router.post("/resend", async (req, res) => {
    // Resend email verification
    const schema = yup.object().shape({
        email: yup.string().email().required(),
    })

    try {
        const { email } = await schema.validate(req.body, { abortEarly: false })
        const user = await User.findOne({ where: { email:email } })
        if (!user) {
            res.status(404).json({ message: "User not found." })
            return
        }

        if (user.is_email_verified) {
            res.status(400).json({ message: "Email is already verified." })
            return
        }

        const token = jwt.sign({ type: "activate", id: user.id }, process.env.APP_SECRET, { expiresIn: "30m" })
        const link = process.env.CLIENT_URL +`/verify?token=${token}`
        const html = await ejs.renderFile("templates/emailVerification.ejs", { url:link })
        await emailSender.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "EnviroGo - Email Verification",
            html: html,
        })
        res.json({ message: "Email sent." })
    } catch (error) {
        res.status(400).json({ message: error.message })
    }
})

router.post("/forgot", async (req, res) => {
    // Send an email to reset password
    const schema = yup.object().shape({
        email: yup.string().email().required(),
    })

    try {
        const { email } = await schema.validate(req.body, { abortEarly: false })
        const user = await User.findOne({ where: { email:email } })
        if (!user) {
            res.status(404).json({ message: "User not found." })
            return
        }

        const token = jwt.sign({ type: "reset", id: user.id }, process.env.APP_SECRET, { expiresIn: "15m" })
        const link = process.env.CLIENT_URL +`/reset?token=${token}`
        const html = await ejs.renderFile("templates/resetPassword.ejs", { user: user, url:link })
        await emailSender.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "EnviroGo - Reset Password",
            html: html,
        })
        res.json({ message: "Email sent." })
    } catch (error) {
        res.status(400).json({ message: error.message })
    }
})

router.post("/reset", async (req, res) => {
    // Reset a user's password
    const schema = yup.object().shape({
        token: yup.string().required(),
        password: yup.string().required().min(12).max(64),
    })

    try {
        const { token, password } = await schema.validate(req.body, { abortEarly: false })
        const { id } = jwt.verify(token, process.env.APP_SECRET)
        const user = await User.findByPk(id)
        if (!user) {
            res.status(404).json({ message: "User not found." })
            return
        }

        user.password = password
        await user.save()
        res.json({ message: "Password reset." })
    } catch (error) {
        res.status(400).json({ message: error.message })
    }
})

router.get("/validate", validateToken, async (req, res) => {
    let userInfo = {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        account_type: req.user.account_type,
        profile_picture: req.user.profile_picture,
        profile_picture_type: req.user.profile_picture_type,
    };
    res.json({
        user: userInfo
    });
});
module.exports = router