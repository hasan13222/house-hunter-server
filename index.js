const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieparser = require("cookie-parser");
require("dotenv").config();

const { MongoClient, ServerApiVersion } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieparser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.uowwywl.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// our middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res
      .status(401)
      .send({ success: false, message: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_KEY, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ success: false, message: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    const database = client.db("house-hunter");
    const userCollection = database.collection("users");

    // signup the user
    app.post("/signup", async (req, res) => {
      const userEmail = req.body.email;
      const isEmailInUse = await userCollection.findOne({ email: userEmail });

      if (isEmailInUse) {
        res.send({ success: false, message: "User Email already in use" });
      } else {
        const hashPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = { ...req.body, password: hashPassword };
        const result = await userCollection.insertOne(newUser);
        res.send(result);
      }
    });

    // login usr and set cookie for jwt token and user information
    app.post("/login", async (req, res) => {
      const isEmailRegistered = await userCollection.findOne({
        email: req.body.email,
      });
      if (!isEmailRegistered) {
        res.send({ success: false, message: "Your Email is not registered" });
      } else {
        const isUserValid = await bcrypt.compare(
          req.body.password,
          isEmailRegistered.password
        );

        if (isUserValid) {
          const result = {
            success: true,
            ...isEmailRegistered,
            password: "sorry, password should be memorized by you",
          };

          // cookie set
          const user = { email: req.body.email };
          const token = jwt.sign({ user }, process.env.ACCESS_TOKEN_KEY, {
            expiresIn: "1h",
          });

          res
            .cookie("token", token, {
              httpOnly: true,
              secure: true,
              sameSite: "none",
            })
            .send(result);
        } else {
          res.send({ success: false, message: "Your Entered Wrong Password" });
        }
      }
    });

    // logout the user
    app.post("/logout", (req, res) => {
        res.clearCookie('token')
        .send({message: 'Logged out successfully'});
    });

    app.get("/isLogin", verifyToken, async (req, res) => {
      const userEmail = req.user.user.email;
      const userResult = await userCollection.findOne({ email: userEmail });

      if (userResult) {
        res.send({ success: true, ...userResult });
      } else {
        res.send({ success: false, message: "User does not exist" });
      }
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("house hunter is running");
});

app.listen(port, () => {
  console.log(`listening on ${port}`);
});
