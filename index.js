const express = require("express");
const mysql = require("mysql");
const dotenv = require("dotenv");
const cors = require("cors");

const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const multer = require("multer");
const DIR = "./uploads";

const bcrypt = require("bcrypt");
const saltRouts = 10;

const jwt = require("jsonwebtoken");

dotenv.config({ path: "./.env" });

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    key: "userId",
    secret: "secretSssion",
    resave: false,
    saveUninittialized: false,
    cookie: {
      expires: 60 * 60 * 24,
    },
  })
);

const db = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  database: process.env.DATABASE,
});

const jwtSecret = process.env.JWTSECRET;

db.connect((error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Mysql connected");
  }
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, DIR);
  },
  filename: (req, file, cb) => {
    const fileName = file.originalname.split(" ").join("_");
    let dotArray = fileName.split(".");
    let extension = "." + dotArray.pop();
    const newFileName =
      Buffer.from(req.session.user[0].uid + "-" + dotArray.join("")).toString(
        "base64"
      ) + extension;
    dotArray[dotArray.length - 1];

    cb(null, newFileName);
  },
});

var upload = multer({
  storage: storage,
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
          req.userId = decoded.userID;
          next();
        }
      });
    } catch (err) {
      throw err;
    }
  }
};
app.get("/download", verifyJWT, (req, res) => {
  res.download("./uploads/" + req.query.filename);
});
app.get("/getUserFiles", verifyJWT, (req, res) => {
  if (req.session.user) {
    const uid = req.session.user[0].uid;
    db.query(
      "SELECT title,filename,description FROM files WHERE uid=?",
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
            let payload = { userID: id };
            const token = jwt.sign(payload, jwtSecret, {
              noTimestamp: true,
              expiresIn: "24h",
            });
            req.session.user = result;

            res
              .status(200)
              .cookie("access_token", token, {
                httpOnly: true,
                expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
                secure: false,
              })
              .json({ ack: true });
          } else {
            res.status(401).json({ ack: false, mesage: "wrong credentials" });
          }
        });
      } else {
        res.status(401).json({ ack: false, mesage: "wrong credentials" });
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
      let uid = req.session.user[0].uid;
      let fileTitle = req.body.title;
      let fileName = req.file.filename;
      let description = req.body.description;
      db.query(
        "INSERT INTO files (uid, title,filename,description) VALUES (?,?,?,?)",
        [uid, fileTitle, fileName, description],
        (err, result) => {
          if (err) throw err;
          res.json({ ack: 1 });
        }
      );
    }
  }
);
app.get("/profile", (req, res) => {
  const id = req.respose.data.rrslt.id;
  res.json(id);
});

app.listen(3001, () => {
  console.log("Server started on port 3001");
});
