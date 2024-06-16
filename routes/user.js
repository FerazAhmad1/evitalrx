const express = require("express");
const { signup, verifyOtp, login } = require("../controllers/auth.js");
const router = express.Router();

router.post("/signup", signup);
router.post("/verifyotp", verifyOtp);
router.post("/login", login);
module.exports = router;
