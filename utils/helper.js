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
exports.generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};
exports.signToken = (email) => {
  return jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};
exports.createRandomToken = () => {
  const randomToken = crypto.randomBytes(32).toString("hex");
  const passwordResetToken = crypto
    .createHash("sha256")
    .update(randomToken)
    .digest("hex");
  return [randomToken, passwordResetToken];
};
