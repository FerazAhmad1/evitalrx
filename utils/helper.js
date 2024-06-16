const applyValidation = async (object, schema) => {
  try {
    const validate = await schema.validateAsync(object);
    return validate;
  } catch (error) {
    error.errorCode = 400;
    error.message = error.message.replace(/"/g, "");
    throw error;
  }
};

module.exports = { applyValidation };
