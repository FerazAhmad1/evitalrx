const { DataTypes, Sequelize } = require("sequelize");
const sequelize = require("../utils/database.js");
const bcrypt = require("bcrypt");

const User = sequelize.define("User", {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  mobile: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
    primaryKey: true,
  },
  dob: {
    type: DataTypes.DATEONLY,
    allowNull: false,
  },
  gender: {
    type: DataTypes.ENUM("male", "female", "other"),
    allowNull: false,
  },
  address: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  otp: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  otpExpiry: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  resetToken: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  tokenExpiry: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  changePasswordAt: {
    type: DataTypes.DATEONLY,
    allowNull: true,
  },
});

User.addHook("beforeSave", "hashedpassword", async function (user, option) {
  if (user.changed("password")) {
    const hashedPassword = await bcrypt.hash(user.password, 12);
    user.password = hashedPassword;
  }
});
User.addHook(
  "beforeSave",
  "updatingpasswordchangeTime",
  async function (user, option) {
    if (!user.isNewRecord && user.changed("password")) {
      user.changePasswordAt = new Date(Date.now() - 1000);
    }
  }
);
module.exports = User;
