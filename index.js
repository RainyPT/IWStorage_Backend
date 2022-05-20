const express = require("express");
const mysql = require("mysql");
const dotenv = require("dotenv");
var aws = require("aws-sdk");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const multer = require("multer");
aws.config.loadFromPath("./config.json");
var s3 = new aws.S3({
  /* ... */
});
const DIR = "./uploads";

var multerS3 = require("multer-s3");

const bcrypt = require("bcrypt");
const saltRouts = 10;

const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();

app.use(express.json());
app.use(express.static("public"));
app.use(
  cors({
    origin: ["http://ec2-13-38-130-5.eu-west-3.compute.amazonaws.com:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    key: "uid",
    secret: "ondabanksbaby",
    resave: true,
    saveUninitialized: true,
    cookie: {
      expires: 60 * 60 * 24 * 1000,
    },
  })
);
const db = mysql.createConnection({
  host: "dabanks.cjx6xiorqyuq.eu-west-3.rds.amazonaws.com",
  user: "root",
  password: "ondabanks",
  database: "iwstorage",
});

const jwtSecret = "20nestetrabalho";

db.connect((error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Mysql connected");
  }
});

var upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: "sicfinalstorage",

    key: function (req, file, cb) {
      let dotArray = file.originalname.split(".");
      const uniqueSuffix = Date.now() + Math.round(Math.random() * 1e9);
      const newFileName = dotArray[0] + "-" + uniqueSuffix;
      let extension = "." + dotArray.pop();
      cb(null, Buffer.from(newFileName).toString("base64") + extension);
    },
  }),
});

app.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  bcrypt.hash(password, saltRouts, (err, hash) => {
    if (err) {
      throw err;
    }
    db.query(
      "INSERT INTO users (username, password) VALUES (?,?)",
      [username, hash],
      (err, result) => {
        if (err) throw err;
        res.send({ ack: 1 });
      }
    );
  });
});

const verifyJWT = (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) {
    res.status(403).json({ auth: false });
  } else {
    try {
      jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
          res.status(403).json({ auth: false });
        } else {
          req.uid = decoded.uid;
          next();
        }
      });
    } catch (err) {
      throw err;
    }
  }
};
app.get("/download", verifyJWT, (req, res) => {
  res.download(DIR + "/" + req.query.filename);
});
app.get("/imgPreview", verifyJWT, (req, res) => {
  res.sendFile(__dirname + "/uploads/" + req.query.filename);
});
app.get("/getUserFiles", verifyJWT, (req, res) => {
  if (req.session.user) {
    const uid = req.session.user.uid;
    db.query(
      "SELECT filename,type,description,DateAdded FROM files WHERE uid=?",
      [uid],
      (err, result) => {
        if (err) throw err;
        res.send(result);
      }
    );
  }
});
app.get("/isUserAuth", verifyJWT, (req, res) => {
  res.json({ auth: true });
});

app.get("/login", verifyJWT, (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.status(401).json({ loggedIn: false });
  }
});
app.get("/logout", (req, res) => {
  res.status(202).clearCookie("access_token").send("token-cookie cleared");
});
app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, result) => {
      if (err) {
        throw err;
      }
      if (result.length > 0) {
        bcrypt.compare(password, result[0].password, (error, response) => {
          if (response) {
            const id = result[0].uid;
            let payload = { uid: id };
            const token = jwt.sign(payload, jwtSecret, {
              noTimestamp: true,
              expiresIn: "24h",
            });
            req.session.user = {
              uid: result[0].uid,
              username: result[0].username,
            };

            res
              .status(200)
              .cookie("access_token", token, {
                httpOnly: true,
                expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
              })
              .json({ ack: true });
          } else {
            res.json({ ack: false, message: "Wrong Credentials!" });
          }
        });
      } else {
        res.json({ ack: false, message: "Wrong Credentials!" });
      }
    }
  );
});
app.post(
  "/file/upload",
  verifyJWT,
  upload.single("uploaded_file"),
  function (req, res) {
    if (req.session.user) {
      if (req.file.key) {
        let uid = req.session.user.uid;
        let fileArray = req.file.key.split(".");
        let fileName = fileArray[0];
        let type = "." + fileArray[1];
        let description = req.body.description;
        db.query(
          "INSERT INTO files (uid,filename,type,description,DateAdded) VALUES (?,?,?,?,NOW())",
          [uid, fileName, type, description],
          (err, result) => {
            if (err) throw err;
            res.json({ ack: true });
          }
        );
      } else {
        res.json({ ack: false, message: "Repeated file name!" });
      }
    }
  }
);

app.listen(3001, () => {
  console.log("Server started on port 3001");
});
