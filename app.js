console.log(process.env.DIALECT);

const express = require("express");
const User = require("./models/user.js");
const userRouter = require("./routes/user.js");
const sequelize = require("./utils/database.js");
const app = express();

app.use(express.json());
app.use("/api/v1/user", userRouter);

//
(async () => {
  const data = await sequelize.sync();
})();

module.exports = app;
