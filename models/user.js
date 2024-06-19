const { DataTypes, Sequelize } = require("sequelize");
const sequelize = require("../utils/database.js");
const bcrypt = require("bcrypt");

const User = sequelize.define("User", {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      is: {
        args: /^[A-Za-z]+ [A-Za-z]+$/,
        msg: "Name must contain only alphabetic characters and be in the format 'FirstName LastName' with exactly one space",
      },
      len: {
        args: [3, 255], // Minimum length of 3 to account for "A B" as the shortest valid name
        msg: "Name must be at least 3 characters long",
      },
    },
  },
  mobile: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isNumeric: {
        msg: "Mobile number must contain only numeric characters",
      },
      len: {
        args: [10, 10],
        msg: "Mobile number must be exactly 10 digits long",
      },
    },
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: {
        msg: "Must be a valid email address",
      },
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
    validate: {
      len: {
        args: [8, 255], // Minimum length of 8, maximum length can be specified as needed
        msg: "Password must be at least 8 characters long",
      },
    },
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
