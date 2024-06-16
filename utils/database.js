const { Sequelize } = require("sequelize");
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.USER,
  process.env.PASSWORD,
  {
    dialect: process.env.DIALECT,
    host: process.env.DB_HOST,
  }
);
module.exports = sequelize;
