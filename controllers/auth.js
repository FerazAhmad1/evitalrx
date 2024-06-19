const User = require("../models/user.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const loginValidationSchema = require("../utils/loginschema.js");
const htmlTemplate = require("../utils/html.js");
const sendMail = require("../utils/email.js");
const {
  MESSAGES,
  STATUS_CODES,
  EMAIL,
  OTP_EXPIRY_DURATION,
} = require("../CONSTANTS.js");
const {
  VALIDATION_ERROR,
  NAME,
  EMAIL: EMAILCONSTANT,
  UPDATE_SUCCESS,
  DOB,
  GENDER,
  PASSWORD,
  ADDRESS,
  OLD_TOKEN,
  NOT_LOGGED_IN,
  RESET_PASSWORD_SUCCESS,
  FORGOT_PASSWORD_GET_RESET_LINK,
  TOKEN_EXPIRED,
  SEND_PASSWORD,
  RESET_LINK_SENT,
  INVALID_USER,
  FAILED_EMAIL_SEND,
  EMAIL_NOT_FOUND,
  INVALID_USER_OR_PASSWORD,
  SIGN_UP_AGAIN,
  EMAIL_ALREADY_REGISTERED,
  USER_NOT_EXIST,
  VERIFY_EMAIL,
  CHECK_EMAIL,
  UNAUTHORIZED_USER,
  INVALID_OTP_OR_USER,
} = MESSAGES;
const {
  applyValidation,
  generateOTP,
  signToken,
  createRandomToken,
} = require("../utils/helper.js");
const crypto = require("crypto");
const { error } = require("console");
const { promisify } = require("util");

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
        message: VALIDATION_ERROR,
      };
    }
    const userData = await User.findByPk(email);
    if (userData) {
      const { otpExpiry: expired, verify = null } = userData.dataValues;
      if (expired === null) {
        throw {
          message: EMAIL_ALREADY_REGISTERED,
        };
      } else if (expired > new Date()) {
        throw {
          message: VERIFY_EMAIL,
        };
      } else {
        await userData.destroy(); // destroy user if user signup but did not verify the with in expiry time
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
      password,
      otp: hashedOtp,
      otpExpiry,
    });
    console.log(user);
    const link = `${req.protocol}://${req.get("host")}/api/v1/user/verifyotp`;
    res.status(200).json({
      success: true,
      otp,
      link,
      messge: CHECK_EMAIL,
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
        message: UNAUTHORIZED_USER,
      };
    }
    const { otpExpiry, otp: dataBaseOtp } = user.dataValues;

    if (otpExpiry < new Date()) {
      throw {
        message: INVALID_OTP_OR_USER,
      };
    }
    console.log(otp, dataBaseOtp);
    const verifyOtp = await bcrypt.compare(otp, dataBaseOtp);
    console.log("GGHHJHJHJFHJFJHFJFJJH", verifyOtp);
    if (!verifyOtp) {
      throw {
        message: INVALID_OTP_OR_USER,
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

    // 1.)Request body validation using Joi validation

    try {
      const validate = await applyValidation(
        { email, password },
        loginValidationSchema
      );
    } catch (error) {
      res.status(error.errorCode || 400).json({
        success: false,
        message: error.message,
      });

      return;
    }

    // 2.) finding if user exist
    const user = await User.findByPk(email);
    if (!user) {
      throw {
        message: USER_NOT_EXIST,
      };
    }

    const { otpExpiry = 5, password: databasePassword } = user.dataValues;

    // 3.) check user trying to login without verifying otp after signup
    if (otpExpiry > new Date()) {
      throw {
        success: false,
        message: VERIFY_EMAIL,
      };
    } else if (otpExpiry !== null) {
      throw { message: SIGN_UP_AGAIN };
    }
    const verify = await bcrypt.compare(password, databasePassword);
    console.log("dferederederder", verify);
    if (!verify) {
      throw {
        message: INVALID_USER_OR_PASSWORD,
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
      success: true,
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
    // 1.) Check if email is present or not
    const { email = null } = req.body;
    if (!email) {
      throw {
        success: false,
        errorCode: 400,
        message: EMAIL_NOT_FOUND,
      };
    }
    // 2 .) check if user exist or not

    const user = await User.findByPk(email);
    if (!user) {
      throw {
        success: false,
        errorCode: 401,
        message: INVALID_USER,
      };
    }
    const { otpExpiry = 5 } = user.dataValues;

    // 3.) check if user calling just after signup without verifying otp

    if (otpExpiry > new Date()) {
      throw {
        success: false,
        message: VERIFY_EMAIL,
        errorCode: 400,
      };
    }
    // 4. ) Check user calling forgot password without verifying otp after token expire
    if (otpExpiry !== null) {
      throw {
        success: true,
        message: SIGN_UP_AGAIN,
        errorCode: 400,
      };
    }

    // 5.)creating random token and hashed the same
    const [randomToken, hashedToken] = createRandomToken();

    // 6.) RESET LINK

    const resetLink = `${req.protocol}://${req.get(
      "host"
    )}/api/v1/user/resetpassword/${randomToken}`;

    // 7.) HTML for reset email
    let html = htmlTemplate.replace(
      "REPLACE_WITH_HTML_CONTENT",
      "<p>To reset password please click on below tab</p>"
    );
    html = html.replace("REPLACE_WITH_LINK", resetLink);
    html = html.replace("REPLACE_WITH_TAB", "reset password");
    const subject = "reset your password";
    const sender = "feraz@gmail.com";

    // 8.) SENDING email
    const response = await sendMail({ html, subject, sender, email });
    if (response.accepted.length === 0) {
      throw {
        success: false,
        errorCode: 500,
        message: FAILED_EMAIL_SEND,
      };
    }

    // 9.)  RESETTING THE TOKEN AND EXPIRY of it for resetPassword aspi
    user.resetToken = hashedToken;

    user.tokenExpiry = new Date(Date.now() + OTP_EXPIRY_DURATION);
    await user.save();
    res.status(200).json({
      success: true,
      message: RESET_LINK_SENT,
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
    const { token = null } = req.params;
    const { email = null, password = null } = req.body;
    // 1.) check token is prsent
    if (!token) {
      throw {
        message: INVALID_USER,
      };
    }

    // 2.) check if email is present or nor
    if (!email) {
      throw {
        success: false,
        errorCode: 401,
        message: INVALID_USER,
      };
    }
    // 3.) check if password is present or not

    if (!password) {
      throw {
        errorCode: 400,
        message: SEND_PASSWORD,
      };
    }
    // 4.)Hashed the token with same that use to create
    const resetToken = crypto.createHash("sha256").update(token).digest("hex");

    // 5.Find user on the basis of hashed user
    const user = await User.findOne({ where: { resetToken } });

    if (!user) {
      throw {
        errorCode: 401,
        success: false,
        message: UNAUTHORIZED_USER,
      };
    }

    const { tokenExpiry = null, email: databseEmail = null } = user.dataValues;

    // 6.) validate user on the basis of email from request body and present in database
    if (email !== databseEmail) {
      throw {
        errorCode: 401,
        success: false,
        message: UNAUTHORIZED_USER,
      };
    }

    // 7.) check if token is expired
    if (tokenExpiry !== null && tokenExpiry < new Date()) {
      user.tokenExpiry = undefined;
      user.resetToken = undefined;
      await user.save();
      throw {
        status: false,
        errorCode: 400,
        message: TOKEN_EXPIRED,
      };
    } else if (tokenExpiry === null) {
      throw {
        success: false,
        errorCode: 400,
        message: FORGOT_PASSWORD_GET_RESET_LINK,
      };
    }

    // 8.) RESETING the password
    user.password = password;
    user.tokenExpiry = undefined;
    user.resetToken = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: RESET_PASSWORD_SUCCESS,
    });
  } catch (error) {
    res.status(error.errorCode || 401).json({
      success: error.success || false,
      message: error.message,
    });
  }
};
exports.protect = async (req, res, next) => {
  try {
    // 1.) check if token is present
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
      console.log(req.headers.authorization.split(" ")[1]);
    }
    if (!token) {
      throw Error({
        message: NOT_LOGGED_IN,
        status: 401,
      });
    }

    // 2.) verify and decode token

    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
    const { email, iat } = decoded;
    const user = await User.findByPk(email);
    if (!user) {
      throw {
        success: false,
        message: UNAUTHORIZED_USER,
      };
    }
    const { changePasswordAt = null } = user.dataValues;
    if (changePasswordAt) {
      const tokenIssueDAte = new Date(iat * 1000);
      if (changePasswordAt > tokenIssueDAte) {
        throw {
          errorCode: 400,
          success: false,
          message: OLD_TOKEN,
        };
      }
    }
    req.user = user;
    next();
  } catch (error) {
    res.status(error.errorCode || 401).json({
      success: false,
      message: error.message,
    });
  }
};
exports.updateProfile = async (req, res) => {
  try {
    let message = "";
    const {
      password = null,
      dob = null,
      name = null,
      email = null,
      gender = null,
      address = null,
    } = req.body;
    if (password) {
      req.user.password = password;
      message += PASSWORD;
    }
    if (dob) {
      req.user.dob = dob;
      message += DOB;
    }
    if (name) {
      req.user.name = name;
      message += NAME;
    }
    if (email) {
      req.user.email = email;
      message += EMAILCONSTANT;
    }

    if (gender) {
      req.user.gender = gender;
      message += GENDER;
    }
    if (address) {
      req.user.address = address;
      message += ADDRESS;
    }
    await req.user.validate();
    await req.user.save();
    res.status(200).json({
      success: true,
      message: `${message} ${UPDATE_SUCCESS}`,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
