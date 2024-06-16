const { configDotenv } = require("dotenv");

configDotenv({
  path: "./config.env",
});

const app = require("./app.js");

app.listen(3000, () => {
  console.log("How to use it");
});
