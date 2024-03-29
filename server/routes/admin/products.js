const express = require('express');
const router = express.Router();
const { User, Sequelize, Product } = require('../../models');
const yup = require("yup");
const path = require('path');
const jwt = require("jsonwebtoken")
const ejs = require("ejs")
const { emailSender } = require("../../middleware/emailSender")
const { validateAdmin } = require("../../middleware/validateAdmin");
const { upload_picture } = require('../../middleware/upload');
const fs = require('fs');

router.get("/", validateAdmin, async (req, res) => {
    try {
        const products = await Product.findAll({
            attributes: {
                exclude: ["createdAt"]
            }
        });
        res.json(products);
    } catch (error) {
        console.error("Error retrieving products:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

router.post('/upload', validateAdmin, upload_picture, (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: "No files uploaded" });
    }
    const filenames = req.files.map(file => file.filename);
    res.json({ filenames: filenames });
});



router.post("/create", validateAdmin,upload_picture,  async (req, res) => {
    let data = req.body;
    let validationSchema = yup.object().shape({
        product_name: yup.string().trim().min(3).required(),
        product_category: yup.string().trim().required(),
        product_sub_category: yup.string().trim().required(),
        pass_category_status: yup.bool(),
        product_stock: yup.number().integer().required(),
        product_description: yup.string().trim().min(3).required(),
        product_picture: yup.string().required(),
        product_price: yup.number().min(0).integer().required(),
        product_sale: yup.bool(),
        product_discounted_percent: yup.number().min(0).integer().required(),
        duration_of_pass: yup.number().integer(),
        product_status: yup.bool()
    });
    try {
        await validationSchema.validate(data,
            { abortEarly: false, strict: true });
    }
    catch (err) {
        console.error(err);
        res.status(400).json({ errors: err.errors });
        return;
    }

    data.product_name = data.product_name.trim();
    data.product_category = data.product_category.trim();
    data.product_sub_category = data.product_sub_category.trim()
    data.product_stock = data.product_stock;
    data.product_description = data.product_description.trim();
    data.product_picture = data.product_picture;
    data.product_price = data.product_price;
    data.product_sale = data.product_sale;
    data.product_discounted_percent = data.product_discounted_percent;
    data.duration_of_pass = data.duration_of_pass;
    data.product_status = data.product_status;
    let result = await Product.create(data);
    res.json(result);
});



router.get("/:id", validateAdmin, async (req, res) => {
    let id = req.params.id;
    let product = await Product.findByPk(id, {});
    if (!product) {
        res.sendStatus(404);
        return;
    }

    if (typeof product.product_picture === "string") {
        product.product_picture = JSON.parse(product.product_picture);
    }

    res.json(product);
});

router.get("/productImage/:filename", (req, res) => {
    const fileName = req.params.filename;
    const directoryPath = path.join(__dirname, "../../public/uploads/products/");
    
    res.sendFile(directoryPath + fileName, fileName);
})

router.put("/status/:id", validateAdmin, async (req, res) => {
    try {
        const schema = yup.object().shape({
            product_status: yup.bool()
        });

        const body = await schema.validate(req.body, { abortEarly: false })
        const product = await Product.findByPk(req.params.id)

        if (!product) {
            return res.status(404).json({message:"Product not found"})
        }

        await product.update({
            ...body
        })

        res.json(product)
    } catch (error) {
        res.status(400).json({ message: error.errors })
    }
});


router.put("/:id", validateAdmin, async (req, res) => {
    const schema = yup.object().shape({
        product_name: yup.string().trim().min(3).required(),
        product_category: yup.string().trim().required(),
        product_sub_category: yup.string().trim().required(),
        pass_category_status: yup.bool(),
        product_stock: yup.number().integer().required(),
        product_description: yup.string().trim().min(3).required(),
        product_picture: yup.string(),
        product_price: yup.number().min(0).integer().required(),
        product_sale: yup.bool(),
        product_discounted_percent: yup.number().min(0).integer().required(),
        duration_of_pass: yup.number().integer(),
        product_status: yup.bool()
    });
    try {
        const body = await schema.validate(req.body, { abortEarly: false })
        const product = await Product.findByPk(req.params.id)
        if (!product) {
            return res.status(404).json({message:"Product not found"})
        }

        await product.update({
            ...body
        })

        res.json(product)
    } catch (error) {
        res.status(400).json({ message: error.errors })
    }

});

router.delete("/productImage/:filename", validateAdmin, (req, res) => {
    const fileName = req.params.filename;
    const directoryPath = path.join(__dirname, "../../public/uploads/products/");

    if (!fs.existsSync(directoryPath + fileName)) {
        return res.status(404).json({ message: "File not found" });
    }

    fs.unlink(directoryPath + fileName, (err) => {
        if (err) {
            console.error("Error deleting the file:", err);
            return res.status(500).json({ message: "Internal server error" });
        }
        res.json({ message: "File successfully deleted" });
    });
});


module.exports = router;