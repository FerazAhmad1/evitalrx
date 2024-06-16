const User = require("../models/user.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const loginValidationSchema = require("../utils/loginschema.js");
const htmlTemplate = require("../utils/html.js");
const sendMail = require("../utils/email.js");
const crypto = require("crypto");
const { error } = require("console");
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const signToken = (email) => {
  return jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};
const createRandomToken = () => {
  const randomToken = crypto.randomBytes(32).toString("hex");
  const passwordResetToken = crypto
    .createHash("sha256")
    .update(randomToken)
    .digest("hex");
  return [randomToken, passwordResetToken];
};
exports.signup = async (req, res) => {
  try {
    const {
      name = null,
      mobile = null,
      email = null,
      dob = null,
      gender = null,
      address = null,
      password = null,
    } = req.body;
    if (
      !name ||
      !mobile ||
      !email ||
      !dob ||
      !gender ||
      !address ||
      !password
    ) {
      throw {
        message: "validation error",
      };
    }
    const userData = await User.findByPk(email);
    if (userData) {
      const { otpExpiry: expired, verify = null } = userData.dataValues;
      if (expired === null) {
        throw {
          message: "this email is already registers",
        };
      } else if (expired > new Date()) {
        console.log(expired, "gdfgdgdfgdgfdfgdghdghdghghghhgdghhgdghdhd");

        throw {
          message: "verify your email",
        };
      } else {
        await userData.destroy();
      }
    }

    const otp = generateOTP();
    const hashedOtp = await bcrypt.hash(otp, 12);
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    const user = await User.create({
      name,
      email,
      mobile,
      dob,
      gender,
      address,
      otp: hashedOtp,
      otpExpiry,
    });
    const link = `${req.protocol}://${req.get("host")}/api/v1/user/verifyotp`;
    res.status(200).json({
      success: true,
      otp,
      link,
      messge: "check your email ",
    });
  } catch (error) {
    console.log(error.message);
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};

exports.verifyOtp = async (req, res) => {
  try {
    const { otp, email } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user) {
      throw {
        success: false,
        message: "you are not authorize to perfom this action",
      };
    }
    const { otpExpiry, otp: dataBaseOtp } = user.dataValues;

    if (otpExpiry < new Date()) {
      throw {
        message: "Invalid otp or user not found",
      };
    }
    console.log(otp, dataBaseOtp);
    const verifyOtp = await bcrypt.compare(otp, dataBaseOtp);
    console.log("GGHHJHJHJFHJFJHFJFJJH", verifyOtp);
    if (!verifyOtp) {
      throw {
        message: "Invalid otp or user not found",
      };
    }

    user.otp = null;
    user.otpExpiry = null;

    const token = signToken(email);
    await user.save();
    res.status(200).json({
      success: true,
      token,
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      message: error.message,
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { email = null, password = null } = req.body;
    try {
      const validate = await applyValidation(
        { email, password },
        loginValidationSchema
      );
    } catch (error) {
      res.status(error.errorCode).json({
        success: false,
        message: error.message,
      });

      return;
    }
    const user = await User.findByPk(email);
    if (!user) {
      throw {
        message: "user not found",
      };
    }
    const { otpExpiry, password: databasePassword } = user.dataValues;
    if (otpExpiry > new Date()) {
      throw {
        success: false,
        message: "verify your email",
      };
    } else if (otpExpiry !== null) {
      throw { message: "signup again" };
    }
    const verify = await bcrypt.compare(password, databasePassword);
    if (!verify) {
      throw {
        message: "Invalid User or password",
      };
    }

    const token = signToken(email);

    const cookieOption = {
      expires: new Date(
        Date.now() + process.env.JWT_COOKIE_EXPIRE_IN * 24 * 60 * 60 * 1000
      ),
      // this makes cookie only be send to encripted connection,basically using https
      httpOnly: true,
    };

    if (process.env.NODE_ENV === "production") {
      cookieOption.secure = true;
    }
    res.cookie("jwt", token, cookieOption);
    res.status(200).json({
      success: false,
      token,
    });
  } catch (error) {
    res.status(error.errorCode || 401).json({
      success: error.success || false,
      message: error.message,
    });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email = null } = req.body;
    if (!email) {
      throw {
        success: false,
        errorCode: 400,
        message: "Please send email",
      };
    }

    const user = await User.findByPk(email);
    if (!user) {
      throw {
        success: false,
        errorCode: 401,
        message: "Invalid User",
      };
    }
    const { otpExpiry = 5 } = user.dataValues;
    if (otpExpiry > new Date()) {
      throw {
        success: false,
        message: "please verify your email",
        errorCode: 400,
      };
    }
    if (otpExpiry !== null) {
      throw {
        success: true,
        message: "please signup again",
        errorCode: 400,
      };
    }
    const [randomToken, hashedToken] = createRandomToken();
    const resetLink = `${req.protocol}://${req.get(
      "host"
    )}/api/v1/user/resetpassword/${randomToken}`;
    let html = htmlTemplate.replace(
      "REPLACE_WITH_HTML_CONTENT",
      "<p>To reset password please click on below tab</p>"
    );
    html = html.replace("REPLACE_WITH_LINK", resetLink);
    html = html.replace("REPLACE_WITH_TAB", "reset password");
    const subject = "reset your password";
    const sender = "feraz@gmail.com";

    const response = await sendMail({ html, subject, sender, email });
    if (response.accepted.length === 0) {
      throw {
        success: false,
        errorCode: 500,
        message: "your send Email function has been failed",
      };
    }
    user.resetToken = hashedToken;
    user.tokenExpiry = new Date(Date.now() + 10 * 60 * 1000);
    res.status(200).json({
      success: true,
      message: "reset link has been sent to your registred email",
    });
  } catch (error) {
    res.status(error.errorCode || 401).json({
      success: false,
      message: error.message,
    });
  }
};

exports.resetPassword = async (req, res) => {
  try {
  } catch (error) {}
};
