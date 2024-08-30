const express = require("express");
var bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");
const cors = require("cors");
var MyInfoConnector = require("myinfo-connector-v4-nodejs");
const fs = require("fs");
const app = module.exports.app = express();
const server = require("http").createServer(app);
const jwt = require("jsonwebtoken")
const io = require("socket.io")(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
  },
});

const db = require("./models/index.js")
require("dotenv").config()
let MYINFO_CONNECTOR_CONFIG = {
  CLIENT_ID: process.env.APP_CLIENT_ID,
  SUBENTITY_ID: process.env.APP_SUBENTITY_ID,
  REDIRECT_URL: process.env.APP_CALLBACK_URL,
  SCOPE: process.env.APP_SCOPES,
  AUTHORIZE_JWKS_URL: `https://test.authorise.singpass.gov.sg/.well-known/keys.json`,
  MYINFO_JWKS_URL: `https://test.authorise.singpass.gov.sg/.well-known/keys.json`,
  TOKEN_URL: `https://test.api.myinfo.gov.sg/com/v4/token`,
  PERSON_URL: `https://test.api.myinfo.gov.sg/com/v4/person`,
  CLIENT_ASSERTION_SIGNING_KID: '', // optional parameter to specify specific kid for signing. Default will be thumbprint of JWK
  USE_PROXY: "N",
  PROXY_TOKEN_URL: "",
  PROXY_PERSON_URL: "",
  DEBUG_LEVEL: "info"
};
const connector = new MyInfoConnector(MYINFO_CONNECTOR_CONFIG);


var sessionIdCache = {};

const corsOptions = {
  origin: "*",
  credentials: true,            //access-control-allow-credentials:true
  optionSuccessStatus: 200
}
app.use(cors(corsOptions));


app.use(express.json({ limit: '100mb' }));

app.use(express.static("public"));

app.use(bodyParser.json({ limit: "100mb" }));
app.use(bodyParser.urlencoded({ limit: "100mb", extended: false, parameterLimit: 5000000 }));
app.use(cookieParser());

// parse requests of content-type - application/x-www-form-urlencoded
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(function (err, req, res, next) {
  console.error(err.stack);
  res.status(500).send({ "message": "Something broke! Check console for details" });
})

// Main Route (Status check)
app.get("/", (request, response) => {
  response.setHeader("Access-Control-Allow-Origin", "*")
  response.setHeader("Access-Control-Allow-Credentials", "true");
  response.setHeader("Access-Control-Max-Age", "1800");
  response.setHeader("Access-Control-Allow-Headers", "content-type");
  response.setHeader("Access-Control-Allow-Methods", "PUT, POST, GET, DELETE, PATCH, OPTIONS");
  response.json({ message: "Welcome to EnviroGo API. API Server is operational. Now with automatic deployments" })
})


// get the environment variables (app info) from the config
app.get("/getEnv", function (req, res) {
  try {
    if (
      process.env.APP_CLIENT_ID == undefined ||
      process.env.APP_CLIENT_ID == null
    ) {
      res.status(500).send({
        error: "Missing Client ID",
      });
    } else {
      res.status(200).send({
        clientId: process.env.APP_CLIENT_ID,
        redirectUrl: process.env.APP_CALLBACK_URL,
        scope: process.env.APP_SCOPES,
        purpose_id: process.env.APP_PURPOSE_ID,
        authApiUrl: process.env.MYINFO_API_AUTHORIZE,
        subentity: process.env.APP_SUBENTITY_ID,
      });
    }
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      error: error,
    });
  }
});

// callback function - directs back to home page
app.get("/callback", function (req, res) {
  console.log('callback route', req);
  res.redirect(process.env.CLIENT_URL + "/driver/register?code=" + req.query.code);
});

//function to read multiple files from a directory
function readFiles(dirname, onFileContent, onError) {
  fs.readdir(dirname, function (err, filenames) {
    if (err) {
      onError(err);
      return;
    }
    filenames.forEach(function (filename) {
      fs.readFile(dirname + filename, "utf8", function (err, content) {
        if (err) {
          onError(err);
          return;
        }
        onFileContent(filename, content);
      });
    });
  });
}

// getPersonData function - call MyInfo Token + Person API
app.post("/getPersonData", async function (req, res, next) {
  if (req.body.codeVerifier == null) {
    req.body.codeVerifier = ' '
  }
  console.log('data: ', req.body)
  try {
    // get variables from frontend
    var authCode = req.body.authCode;
    //retrieve code verifier from session cache
    var codeVerifier = sessionIdCache['verifier'];
    console.log("Calling MyInfo NodeJs Library...".green);

    // retrieve private siging key and decode to utf8 from FS
    let privateSigningKey = fs.readFileSync(
      process.env.APP_CLIENT_PRIVATE_SIGNING_KEY,
      "utf8"
    );
    console.log('auth code:', authCode);
    console.log('code verifier', codeVerifier);
    console.log('signing key:', privateSigningKey)
    let privateEncryptionKeys = [];
    // retrieve private encryption keys and decode to utf8 from FS, insert all keys to array
    readFiles(
      process.env.APP_CLIENT_PRIVATE_ENCRYPTION_KEYS,
      (filename, content) => {
        privateEncryptionKeys.push(content);
      },
      (err) => {
        throw err;
      }
    );
    console.log('list:', privateEncryptionKeys)
    //call myinfo connector to retrieve data
    let personData = await connector.getMyInfoPersonData(
      authCode,
      codeVerifier,
      privateSigningKey,
      privateEncryptionKeys
    );
    console.log('person data: ', personData)

    /* 
      P/s: Your logic to handle the person data ...
    */
    console.log(
      "--- Sending Person Data From Your-Server (Backend) to Your-Client (Frontend)---:"
        .green
    );
    console.log(JSON.stringify(personData)); // log the data for demonstration purpose only
    res.status(200).send(personData); //return personData
  } catch (error) {
    console.log("---MyInfo NodeJs Library Error---".red);
    console.log(error);
    res.status(500).send({
      error: error,
    });
  }
});

// Generate the code verifier and code challenge for PKCE flow
app.post("/generateCodeChallenge", async function (req, res, next) {
  try {
    // call connector to generate code_challenge and code_verifier
    let pkceCodePair = connector.generatePKCECodePair();
    // create a session and store code_challenge and code_verifier pair
    sessionIdCache['verifier'] = pkceCodePair.codeVerifier;
    console.log('session cache', sessionIdCache)

    //send code code_challenge to frontend to make /authorize call
    res.status(200).send(pkceCodePair.codeChallenge);
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      error: error,
    });
  }
});

io.on("connection", (socket) => {
  const token = socket.handshake.query.token
  const room = socket.handshake.query.room

  try {
    const decoded = jwt.verify(token, process.env.APP_SECRET)
    socket.join(room)
    console.log("a user connected");
    console.log(socket.rooms)
  } catch (error) {
    socket.emit('error', 'Invalid token')
    socket.disconnect()
  }

  io.on("disconnect", () => {
    console.log("user disconnected");
  });
});



// Routes
const userRoutes = require("./routes/user.js")
const adminUsersRoutes = require("./routes/admin/users.js")
const authRoutes = require("./routes/auth.js")
const uploadRoutes = require("./routes/upload.js")
const paymentRoutes = require("./routes/payment.js")
const driverRoutes = require('./routes/driver.js')
const adminProductsRoutes = require("./routes/admin/products.js")
const bicycleRoutes = require('./routes/bicycle.js')
const adminDriverRoutes = require('./routes/admin/driver.js')
const productsRoutes = require('./routes/products.js')
const adminLocationRoutes = require('./routes/admin/locations.js')
const fileRoute = require('./routes/file.js');
const cartRoutes = require('./routes/cart.js');
const adminOrdersRoutes = require('./routes/admin/orders.js');
const orderRoutes = require('./routes/orders.js');
const wishlistRoutes = require('./routes/wishlist.js');
const adminRefundRoutes = require('./routes/admin/refunds.js');
const refundRoutes = require('./routes/refunds.js');
const adminSupportRoutes = require("./routes/admin/support");
const supportRoutes = require("./routes/support");
const rideRequestRoutes = require("./routes/rideRequests");
const rideRatingRoutes = require("./routes/rideRatings.js");
app.use("/file", fileRoute);

app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use('/images', express.static('images'));

app.use("/user", userRoutes)
app.use("/admin/users", adminUsersRoutes)
app.use("/auth", authRoutes)
app.use("/uploads", uploadRoutes)
app.use("/payment", paymentRoutes)
app.use('/driver', driverRoutes)
app.use('/admin/driver', adminDriverRoutes)
app.use('/admin/products', adminProductsRoutes)
app.use('/bicycle', bicycleRoutes)
app.use("/admin/driver", adminDriverRoutes)
app.use("/products", productsRoutes)
app.use("/admin/locations", adminLocationRoutes)
app.use("/cart", cartRoutes)
app.use("/admin/orders", adminOrdersRoutes)
app.use("/orders", orderRoutes)
app.use("/wishlist", wishlistRoutes)
app.use("/admin/refunds", adminRefundRoutes)
app.use("/refunds", refundRoutes)
app.use("/admin/support", adminSupportRoutes);
app.use("/support", supportRoutes);
app.use("/riderequests", rideRequestRoutes);
app.use("/riderating", rideRatingRoutes);

app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.get('*', function (req, res) {
  res.status(404).send({ message: 'Endpoint not implemented' });
});

app.io = io

let port = process.env.APP_PORT
server.listen(port, () => {
  console.clear()
  console.log(`The server has been started on port ${port}\nIf you made changes to the database, please continue waiting till 'Database synced' appears.`)
})

db.sequelize.sync({ alter: true }).then(() => {
  console.log('Database synced')
})

module.exports = app;
