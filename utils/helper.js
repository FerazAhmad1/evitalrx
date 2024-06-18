/**
 *
 * @param {*} object collection of data that needs to verify
 * @param {*} schema joi schema
 * @returns Boolean or error object
 */
exports.applyValidation = async (object, schema) => {
  try {
    const validate = await schema.validateAsync(object);
    return validate;
  } catch (error) {
    error.errorCode = 400;
    error.message = error.message.replace(/"/g, "");
    throw error;
  }
};

/**
 *
 * @returns six digit numeric string
 */
exports.generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 *
 * @param {*} email payload of jwt sign function
 * @returns jason web token
 */
exports.signToken = (email) => {
  return jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

/**
 *
 * @returns random Token and hashedToken
 */
exports.createRandomToken = () => {
  const randomToken = crypto.randomBytes(32).toString("hex");
  const passwordResetToken = crypto
    .createHash("sha256")
    .update(randomToken)
    .digest("hex");
  return [randomToken, passwordResetToken];
};
