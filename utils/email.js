const nodemailer = require("nodemailer");
const sendMail = async (options) => {
  // 1.) Create transporter
  var transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT * 1,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  // 2.) Define the mail option
  let html = options.resetPasswordHtml.replace(
    "REPLACE_WITH_HTML_CONTENT",
    options.htmlcontent
  );
  html = html.replace("REPLACE_WITH_LINK", options.resetLink);
  const mailOption = {
    from: `feraz khan <${options.sender}>`,
    to: options.email,
    subject: options.subject,
    html,
  };

  try {
    const mail = await transporter.sendMail(mailOption);
    console.log(mail);
    return mail;
  } catch (error) {
    console.log("eeeeeeeeeeeeeeeeeeeeeeeeeeee", error.message);
  }
};
module.exports = sendMail;
