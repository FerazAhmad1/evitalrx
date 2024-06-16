const User = require("../models/user.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const loginValidationSchema = require("../utils/loginschema.js");
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const signToken = (email) => {
  return jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
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
