import Express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bodyParser from 'body-parser';
import jsonWebToken from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { rateLimit } from 'express-rate-limit';
import crypto from 'crypto';

const saltRounds = 10;
const prisma = new PrismaClient();
const app = new Express();
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 5000, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
  standardHeaders: 'draft-7', // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
  // store: ... , // Use an external store for consistency across multiple server instances.
});
const ENCRYPTION_KEY = "Odf6qfnrDH8IQuZDhB0ZjDMuBkNx7XeA";
const IV_LENGTH = 16;
function encrypt(text) {
 const iv = crypto.randomBytes(IV_LENGTH);
 const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
 
 let encrypted = cipher.update(text, 'utf-8', 'hex');
 encrypted += cipher.final('hex');

 return `${iv.toString('hex')}:${encrypted}`;
}
function decrypt(text) {
 const [ivHex, encryptedText] = text.split(':');
 const iv = Buffer.from(ivHex, 'hex');
 const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);

 let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
 decrypted += decipher.final('utf-8');

 return decrypted;
}
app.use(limiter);
app.use(cors({
 origin: true, //included origin as true
 credentials: true, //included credentials as true
}));
//app.use(express.json());
app.use(bodyParser.json())
app.use(cookieParser(process.env.SECRET));
app.use(bodyParser.urlencoded({ extended: false }));

function logs(req, res, next) {
 const data = req.body;
 if (req.url === "/login") {
  console.log(data);
 } else if (req.url === "/register") {
  console.log(data);
 } else if (req.url === "/generate") {
  console.log(data);
 }
 next();
}
async function auth(req,res,next) {
 if (req.signedCookies.token) {
  const token = jsonWebToken.verify(req.signedCookies.token, process.env.SECRET)
  const user = await prisma.user.findUniqueOrThrow({where:{username:token.username}})
  if (user) {
   return next();
  }
 } else {
  return res.status(401).json("Not signed in");
 }
}

app.post("/login", logs, async (req, res) => {
 try {
  const data = await req.body;
  const pass = data.password;
  try {
   const user = await prisma.user.findUniqueOrThrow({where:{username:data.username}});
   const passDecrypted = decrypt(user.password);
   console.log(passDecrypted)
   if (passDecrypted === pass) {
    const token = jsonWebToken.sign(user, process.env.SECRET);
    if (req.signedCookies.token) {
     if (jsonWebToken.verify(req.signedCookies.token, process.env.SECRET)) {
      return res.status(403).json("Already authenticated");
     }
    }
    await prisma.user.update({where:{username:user.username},data:{token:token}});
    res.cookie('token', token, {signed:true, maxAge: 1000*60*60*24*7, httpOnly: true});
    return res.status(200).json(token);
   } else {
    return res.status(400).json("Invalid password");
   }
   } catch (err) {
    console.log(err);
    return res.status(400).json({error: err});
   }
 } catch (err) {
  console.log(err)
  return res.status(403).json(err);
 }
});
app.post("/register", logs,  async (req, res) => {
 try {
  const data = await req.body;
  const user = await prisma.user.findUnique({where:{username:data.username}});
  if (user) {
   return res.status(403).json("Already registered");
  }
  const create = await prisma.user.create({data:{username:data.username,password:encrypt(data.password)}});
  return res.status(200).json("Successfully registered");
 } catch (err) {
  res.status(403).json(err);
 }
});
app.post("/logout", [logs, auth], (req, res) => {
 res.clearCookie('token').json("Logged out");
});
app.post("/generate", [logs, auth], async (req, res) => {
 const data2 = await req.body;
 if (req.signedCookies.token) {
  const data = jsonWebToken.verify(req.signedCookies.token, process.env.SECRET)
  await prisma.rating.create({data:{authorId:data2.authorId, rating:data2.rating}});
  res.json("Submitted");
 }
});
app.get("/get", auth, async (req, res) => {
 if (req.signedCookies.token) {
  const user = await prisma.user.findMany();
  let list = [];
  for (let i = 0; i < user.length;i++) {
   list.push(user[i]);
  }
  return res.json(list).status(200);
 }
 res.json();
});
app.post("/get/:id", auth, (req, res) => {
 
});
app.get("/profile", [logs, auth], async(req, res) => {
  if (req.signedCookies.token) {
   const token = jsonWebToken.verify(req.signedCookies.token, process.env.SECRET)
   try {
    const user = await prisma.user.findUniqueOrThrow({where:{username:token.username}})
    if (user) {
     return res.status(200).json(token)
    }
   } catch (err){
    return res.status(401).json(err)
   }
  }
  return res.status(401)
});
app.get("/getrating", [logs, auth], async(req, res) => {
 if (req.signedCookies.token) {
  const token = jsonWebToken.verify(req.signedCookies.token, process.env.SECRET)
  try {
   const user = await prisma.rating.findMany({where:{authorId:token.id}})
   if (user) {
    let total = 0;
    for (let i = 0;i < user.length;i++) {
     total += user[i].rating
    }
    return res.status(200).json(total / user.length)
   }
  } catch (err){
   return res.status(401).json(err)
  }
 }
 return res.status(401)
});
app.listen(5000, (req, res) => {
 console.log(`Server has started on port 5000`);
});