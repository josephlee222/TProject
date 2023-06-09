const { User, Transaction } = require("../models")
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY)
const express = require("express");
const router = express.Router()
const yup = require("yup");
const { validateToken } = require("../middleware/validateToken");

router.post("/webhook", async (req, res) => {
    // Handle webhook
    console.log(req.body)
    // PayementIntent object
    const data = req.body.data.object

    // Check if the paymentIntent is succeeded
    if (data.status === "succeeded") {
        // Update the transaction
        // Check whether the request is genuine
        const transaction = await Transaction.findOne({
            where: {
                paymentIntent_id: data.id
            }
        })
        if (transaction) {
            if (transaction.status === "Succeeded") {
                return res.status(200).json({ message: "Webhook received." })
            }

            transaction.status = "Succeeded"
            if (transaction.type === "topup") {
                const user = await User.findByPk(transaction.user_id)
                user.cash = parseFloat(user.cash) + parseFloat(transaction.amount)
                await user.save()
            }
            await transaction.save()
        }
    }
    res.status(200).json({ message: "Webhook received." })
})

router.post("/topup", validateToken, async (req, res) => {
    // Top up
    // Create a PaymentIntent
    const schema = yup.object().shape({
        amount: yup.number().required().min(1),
    })

    try {
        await schema.validate(req.body, { abortEarly: false })
        const { amount } = req.body
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount * 100,
            currency: "sgd",
            automatic_payment_methods: {enabled: true},
        })

        const transaction = await Transaction.create({
            amount: amount,
            type: "topup",
            status: "Pending",
            paymentIntent_id: paymentIntent.id,
            paymentIntent_client_secret: paymentIntent.client_secret,
            user_id: req.user.id,
            operator: "+"
        })

        res.status(200).json({ clientSecret: paymentIntent.client_secret })
    } catch (err) {
        res.status(400).json({ message: err.errors[0] })
    }
})

router.get("/history", validateToken, async (req, res) => {
    // Get history
    try {
        const { type } = req.query
        const condition = type ? {
            user_id: req.user.id,
            type
        } : {
            user_id: req.user.id
        }

        const transactions = await Transaction.findAll({
            where: {
                ...condition
            },
            order: [["createdAt", "DESC"]]
        })

        res.status(200).json(transactions)
    } catch (err) {
        res.status(400).json({ message: err.message })
    }
})

router.get("/history/:id", validateToken, async (req, res) => {
    // Get history
    try {
        const { id } = req.params
        const transaction = await Transaction.findOne({
            where: {
                id: id,
                user_id: req.user.id
            }
        })

        if (!transaction) {
            res.status(404).json({ message: "Transaction not found." })
        }

        res.status(200).json(transaction)
    } catch (err) {
        res.status(400).json({ message: err.message })
    }
})

module.exports = router;