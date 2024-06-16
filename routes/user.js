const express = require("express");
const {
  signup,
  verifyOtp,
  login,
  forgotPassword,
  resetPassword,
} = require("../controllers/auth.js");
const router = express.Router();

router.post("/signup", signup);
router.post("/verifyotp", verifyOtp);
router.post("/login", login);
router.post("/forgotpassword", forgotPassword);
router.post("/resetpassword/:token", resetPassword);
module.exports = router;
