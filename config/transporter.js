const nodemailer = require("nodemailer");

const host = process.env.HOST;
const email = process.env.EMAIL;
const pass = process.env.PASS;

console.log(host, email, pass)

const transporterData = {
  host: host,
  port: 465, // SSL mode
  secure: true, // true for 465, false for 587
  auth: {
    user: email,
    pass: pass, // App Password
  },
  tls: {
    rejectUnauthorized: false, // Bypass certificate validation
  },
};

const transporter = nodemailer.createTransport(transporterData);

module.exports=transporter