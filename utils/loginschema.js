const joi = require("joi");

const schema = joi.object({
  email: joi.string().required().email(),
  password: joi.string().required().min(8),
});

module.exports = schema;
